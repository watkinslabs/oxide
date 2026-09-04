// Scheduler-owned CPU evacuation and final quiescence proof.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{SchedClass, Task};
use super::migration::{MoveResult, queued_candidate};
use super::runqueue::{global_for, RqIrq, Runqueue};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Evacuation { pub moved: u32, pub current_target: Option<u32> }

/// Linux smpboot-thread shape: a kernel thread with immutable singleton
/// affinity belongs to that CPU and must park before placement is closed.
/// # C: O(words)
fn is_per_cpu_kthread(task: &Task, cpu: u32) -> bool {
    task.kernel_thread.load(Ordering::Acquire)
        && task.no_setaffinity.load(Ordering::Acquire)
        && task.cpus_allowed.load(Ordering::Acquire) == cpu::CpuMask::of(cpu as usize)
}

/// Synchronously park every bound kthread before this CPU leaves ACTIVE.
/// The acknowledgement means evacuation never breaks a structural kthread
/// binding merely to keep a runnable task owned. # Sleeps: y # C: O(tasks)
pub fn park_per_cpu_kthreads(cpu: u32) {
    park_per_cpu_kthreads_with(cpu, crate::registry::snapshot,
        |task| super::kthread::park(task));
}

fn park_per_cpu_kthreads_with<S, P>(cpu: u32, mut snapshot: S, mut park: P)
where S: FnMut() -> alloc::vec::Vec<Arc<Task>>, P: FnMut(&Arc<Task>) {
    // A per-CPU kworker manager may already be between its own park point and
    // `spawn_worker()` when the first snapshot is taken. Parking that manager
    // closes future creation, but a worker it published meanwhile was absent
    // from the snapshot. Rescan to a fixed point after every synchronous pass;
    // once every creator is parked, the next empty pass is stable.
    loop {
        let mut pending = 0usize;
        for task in snapshot() {
            if is_per_cpu_kthread(&task, cpu)
                && !super::kthread::is_parked(&task)
                && !super::kthread::has_exited(&task)
            {
                pending += 1;
                park(&task);
            }
        }
        if pending == 0 { return; }
    }
}

/// Resume the exact bound population after cancellation or CPU-up.
/// # C: O(tasks)
pub fn unpark_per_cpu_kthreads(cpu: u32) {
    for task in crate::registry::snapshot() {
        if is_per_cpu_kthread(&task, cpu) { super::kthread::unpark(&task); }
    }
}

/// Process-context CPU-down stage: persistently evacuate until the target rq
/// has an owning-lock empty proof, then close generic call publication and
/// wait its RCU grace. The architecture may send the terminal offline call
/// only after this returns. # Sleeps: y # C: O(spins * runnable)
pub fn prepare_stop(cpu: u32, spin_limit: u32) -> bool {
    prepare_stop_with(spin_limit, &mut || {
        let _ = evacuate(cpu);
        let _ = super::workqueue::evacuate_offline(cpu as usize);
    }, &mut || final_empty(cpu), &mut || cpu::smp::begin_callfn_shutdown(cpu))
}

fn prepare_stop_with<E, Q, C>(spin_limit: u32, evacuate: &mut E,
    quiescent: &mut Q, close_callfn: &mut C) -> bool
where E: FnMut(), Q: FnMut() -> bool, C: FnMut() -> bool {
    let mut spins = 0;
    while spins < spin_limit {
        evacuate();
        if quiescent() { return close_callfn(); }
        spins += 1;
        sync::spin_relax::relax();
    }
    false
}

/// Push every queued task from an inactive rq and request switch-time
/// placement for its current non-idle task. Repeated calls are idempotent.
/// # C: O(runnable * (CPUs + log N))
pub fn evacuate(cpu: u32) -> Evacuation {
    // SAFETY: deactivation retains all installed runqueues until final
    // transport-online publication.
    evacuate_with(&|candidate| unsafe { global_for(candidate) }, cpu,
                  &cpu::smp::is_active)
}

fn evacuate_with<'a, F, A>(get_rq: &F, cpu: u32, active: &A) -> Evacuation
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool {
    let Some(src) = get_rq(cpu) else { return Evacuation { moved: 0, current_target: None }; };
    let mut moved = 0u32;
    loop {
        let Some(task) = queued_candidate(src) else { break; };
        let _placement = sync::rcu_read_lock();
        match super::migration::move_queued_with(
            get_rq, &task, None, active, &mut |_, _, _| {}) {
            MoveResult::Moved { from, to } => {
                if from == cpu && to != cpu {
                    moved = moved.saturating_add(1);
                    super::ttwu::resched_locked_on(get_rq, to);
                } else { break; }
            }
            MoveResult::Unplaced { from, task } => {
                let result = super::migration::finish_unplaced_with(
                    get_rq, task, from, None, active, &mut |_, _, _| {});
                if let MoveResult::Moved { from: f, to } = result {
                    if f != cpu || to == cpu { break; }
                    moved = moved.saturating_add(1);
                    super::ttwu::resched_locked_on(get_rq, to);
                } else { break; }
            }
            MoveResult::Running { .. } | MoveResult::NotQueued => break,
        }
    }
    let current_target = current_target_with(get_rq, cpu, active);
    Evacuation { moved, current_target }
}

fn current_target_with<'a, F, A>(get_rq: &F, cpu: u32, active: &A) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool {
    let rq = get_rq(cpu)?;
    let inner = rq.inner.lock_irqsave::<RqIrq>();
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: the held rq lock pins its current-task strong reference.
    let task = unsafe { &*raw };
    if matches!(task.sched_class(), SchedClass::Idle) { return None; }
    let target = super::schedule::migrate::evict_target_for_active_with(
        get_rq, cpu, task, None, active);
    if target.is_some() { super::ttwu::resched_locked(rq); }
    drop(inner);
    target
}

/// Final target-side proof. The class-tree count, current pointer, parked
/// switch handoff, and deferred-wake state are sampled while owning the rq.
/// New publishers are already excluded by active clear plus placement grace.
/// # C: O(deferred wake debug bound)
pub fn final_empty(cpu: u32) -> bool {
    if !super::workqueue::offline_quiescent(cpu as usize) { return false; }
    // SAFETY: CPU-down retains this installed runqueue until this proof and
    // final transport-online publication complete.
    let Some(rq) = (unsafe { global_for(cpu) }) else { return false; };
    final_empty_with(rq, cpu, &mut || {})
}

fn final_empty_with<P>(rq: &Runqueue, cpu: u32, probe: &mut P) -> bool
where P: FnMut() {
    let inner = rq.inner.lock_irqsave::<RqIrq>();
    probe();
    let wake = super::wake_list_debug(cpu);
    let empty = rq.curr_is_idle() && inner.nr_running() == 0
        && !super::schedule::migrate::has_parked(cpu) && !wake.0 && wake.1 == 0;
    rq.publish_nr_running(inner.nr_running());
    empty
}

#[cfg(test)]
#[path = "cpu_hotplug/tests.rs"]
mod tests;
