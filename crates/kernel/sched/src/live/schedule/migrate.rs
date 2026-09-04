// Affinity eviction of the OUTGOING task at switch time.
//
// `schedule()` re-queues a preempted-but-still-Runnable task with
// `put_prev_task`, which stores `task.cpu = rq.cpu` and drops it into the LOCAL
// class tree without ever reading `cpus_allowed`. When the mask lost this CPU
// while the task was running (a `sched_setaffinity(2)` call, a `CPUAffinity=`
// unit, a cgroup `cpuset.cpus` write), that re-queue puts the task straight
// back on a CPU it may not use and the next pick runs it there again — so a
// CPU-bound thread never leaves the forbidden CPU until it blocks. The
// need_resched + IPI nudge the mask writer sends is undone by exactly this
// re-queue.
//
// The task cannot simply be enqueued on the destination from `schedule()`:
//   * the local rq lock is held there, and taking a second rq lock under it is
//     an AB-BA hazard against any CPU doing the reverse;
//   * the task is still `on_cpu` at that point, and a task enqueued elsewhere
//     while still executing here can be picked by the destination CPU and run
//     from a register context this CPU has not saved yet.
// So the placement is PARKED here and performed by the INCOMING task's
// `finish_task_switch`, which runs after the outgoing task's `on_cpu` is
// cleared and after the local rq lock is released — one rq lock at a time,
// nothing held, no cross-CPU aliasing. This mirrors Linux, where the running
// case is handled by a stopper that migrates the task only once it is off-CPU.
//
// Terminal fallback: when the mask names no CPU with an installed runqueue the
// task stays where it is and keeps running, rather than being stranded — the
// kernel breaks affinity before it strands a runnable task.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::{SchedClass, Task};
use crate::live::runqueue::{global_for, RqIrq, Runqueue};

/// `target` value meaning "slot empty".
const NO_TARGET: u32 = u32::MAX;

/// Does `allowed` permit `cpu`? # C: O(1)
pub fn cpu_permitted(allowed: cpu::CpuMask, cpu: u32) -> bool { allowed.contains(cpu as usize) }

/// Destination for a still-Runnable outgoing task that may no longer use `cpu`,
/// or `None` when it may stay. `None` also covers the terminal fallback: a mask
/// naming no CPU with an installed runqueue leaves the task running where it
/// is (affinity broken, never stranded).
/// # C: O(N_cpus)
pub fn evict_target_with<'a, F>(get_rq: &F, cpu: u32, task: &Task) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue> {
    evict_target_for_with(get_rq, cpu, task, None)
}

/// Placement decision with an optional internal system-transition pin.
/// The pin wins over affinity without modifying any of its three masks.
/// # C: O(N_cpus) without a pin; O(1) with a pin
pub fn evict_target_for_with<'a, F>(
    get_rq: &F,
    cpu: u32,
    task: &Task,
    transition: Option<u32>,
) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue> {
    evict_target_for_active_with(get_rq, cpu, task, transition, &|cpu| get_rq(cpu).is_some())
}

pub(crate) fn evict_target_for_active_with<'a, F, A>(
    get_rq: &F,
    cpu: u32,
    task: &Task,
    transition: Option<u32>,
    active: &A,
) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool {
    if matches!(task.sched_class(), SchedClass::Idle) { return None; }
    if let Some(target) = transition {
        if target == cpu { return None; }
        return (active(target) && get_rq(target).is_some()).then_some(target);
    }
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    if cpu_permitted(allowed, cpu) && active(cpu) { return None; }
    let target = crate::live::ttwu::select_task_rq_with(&|candidate| {
        if active(candidate) { get_rq(candidate) } else { None }
    }, cpu, task);
    // The enclosing placement reader keeps an old ACTIVE sample valid through
    // publication into PARKED. Destination attachment revalidates under its
    // rq lock and can choose another active CPU.
    if target == cpu { return None; }
    if get_rq(target).is_none() { return None; }
    Some(target)
}

/// [`evict_target_with`] over the live per-CPU runqueues. # C: O(N_cpus)
pub fn evict_target(cpu: u32, task: &Task) -> Option<u32> {
    let _placement = sync::rcu_read_lock();
    // SAFETY: `global_for` is sound for any index and yields `None` for a CPU
    // that has not completed `install_global`, which the scan skips.
    evict_target_for_active_with(
        // SAFETY: each queried index is range-checked by `global_for`, and a
        // missing runqueue is represented as `None` rather than dereferenced.
        &|c| unsafe { global_for(c) }, cpu, task, transition_target(task),
        &cpu::smp::is_active,
    )
}

/// Whether a transition coordinator can be retained on `target`. Per-CPU idle
/// tasks cannot migrate, but the target CPU's own idle task is a valid owner
/// for an early-boot transition already executing there.
/// # C: O(1)
pub(crate) fn coordinator_can_pin(class: SchedClass, here: u32, target: u32) -> bool {
    !matches!(class, SchedClass::Idle) || here == target
}

/// Pin the current system-transition coordinator to `target` and synchronously
/// migrate it there. The pin remains until [`unpin_current_cpu`], so ordinary
/// affinity eviction cannot move the coordinator back while secondaries are
/// being removed. User, cpuset, and effective affinity masks are untouched.
/// # C: O(log N) + one context switch
/// # Ctx: sleepable process context, no locks held, IRQs enabled
pub fn pin_current_to_cpu(target: u32) -> bool {
    if target as usize >= cpu::MAX_CPUS { return false; }
    // SAFETY: `global_for` returns only installed runqueues. CPU hotplug is
    // serialized by the caller across the subsequent down pass.
    if unsafe { global_for(target) }.is_none() { return false; }
    let Some(task) = super::current() else { return false };
    let here = super::sched_current_cpu() as u32;
    if !coordinator_can_pin(task.sched_class(), here, target) { return false; }

    if TRANSITION_PIN.task.compare_exchange(
        core::ptr::null_mut(), PUBLISHING, Ordering::AcqRel, Ordering::Acquire,
    ).is_err() { return false; }
    let raw = task as *const Task as *mut Task;
    // SAFETY: current's runqueue owns a strong reference throughout this
    // preemptible call. The matching `Arc::from_raw` is in unpin/failure.
    unsafe { Arc::increment_strong_count(raw); }
    TRANSITION_PIN.target.store(target, Ordering::Relaxed);
    TRANSITION_PIN.task.store(raw, Ordering::Release);

    if here != target {
        // SAFETY: this API's context contract is exactly sched_yield's.
        unsafe { super::switch::sched_yield(); }
    }
    if super::sched_current_cpu() as u32 == target { return true; }
    let _ = unpin_current_cpu();
    false
}

/// Release the current coordinator's transition pin. If its preserved
/// affinity excludes this CPU, request a schedule so normal affinity eviction
/// restores that policy after all secondaries are online again.
/// # C: O(1)
pub fn unpin_current_cpu() -> bool {
    let Some(task) = super::current() else { return false };
    let raw = task as *const Task as *mut Task;
    if TRANSITION_PIN.task.compare_exchange(
        raw, core::ptr::null_mut(), Ordering::AcqRel, Ordering::Acquire,
    ).is_err() { return false; }
    TRANSITION_PIN.target.store(NO_TARGET, Ordering::Release);
    // SAFETY: pin_current_to_cpu retained exactly this Arc and the successful
    // compare-exchange transfers its sole retained reference back here.
    drop(unsafe { Arc::from_raw(raw) });
    let here = super::sched_current_cpu() as u32;
    if !cpu_permitted(task.cpus_allowed.load(Ordering::Acquire), here) {
        crate::preempt::resched::set_tsk_need_resched(task);
    }
    true
}

/// One parked placement per CPU. The switcher and the drainer run on the same
/// CPU and every switch drains before the next can park, so one slot suffices —
/// the same shape as the runqueue's deferred-reap slot.
struct Parked {
    /// `Arc::into_raw` of the task awaiting placement, or null.
    task: AtomicPtr<Task>,
    /// CPU to place it on; meaningful only while `task` is non-null.
    target: AtomicU32,
}

const EMPTY: Parked = Parked {
    task: AtomicPtr::new(core::ptr::null_mut()),
    target: AtomicU32::new(NO_TARGET),
};
static PARKED: [Parked; cpu::MAX_CPUS] = [EMPTY; cpu::MAX_CPUS];

/// One system-transition pin. Suspend/hibernate is globally serialized, so
/// there can be only one coordinator. This is deliberately separate from the
/// task's user/cpuset affinity: Linux's CPU-down stopper may temporarily run a
/// pinned task on the surviving CPU without rewriting its saved affinity.
struct TransitionPin {
    /// Retained `Arc<Task>` raw pointer, or null. `PUBLISHING` is an internal
    /// claim state which schedule-side readers ignore.
    task: AtomicPtr<Task>,
    target: AtomicU32,
}

const PUBLISHING: *mut Task = 1usize as *mut Task;
static TRANSITION_PIN: TransitionPin = TransitionPin {
    task: AtomicPtr::new(core::ptr::null_mut()),
    target: AtomicU32::new(NO_TARGET),
};

fn transition_target(task: &Task) -> Option<u32> {
    let raw = TRANSITION_PIN.task.load(Ordering::Acquire);
    if raw.is_null() || raw == PUBLISHING || !core::ptr::eq(raw, task) { return None; }
    let target = TRANSITION_PIN.target.load(Ordering::Acquire);
    (target != NO_TARGET).then_some(target)
}

/// Park `task` for placement on `target` once the switch off `cpu` completes.
/// Returns false when the slot is already occupied, so the caller re-queues
/// locally instead — a task is never dropped on the floor for a full slot.
/// # C: O(1)
pub fn park(cpu: u32, task: &Arc<Task>, target: u32) -> bool {
    let slot = match PARKED.get(cpu as usize) { Some(s) => s, None => return false };
    if !slot.task.load(Ordering::Acquire).is_null() { return false; }
    slot.target.store(target, Ordering::Release);
    slot.task.store(Arc::into_raw(Arc::clone(task)) as *mut Task, Ordering::Release);
    true
}

/// Reclaim a parked task WITHOUT placing it — the switch it was parked for did
/// not happen, so the caller owns re-queueing it. # C: O(1)
pub fn unpark(cpu: u32) -> Option<Arc<Task>> {
    let (task, _) = take(cpu)?;
    Some(task)
}

/// Whether switch-time placement still owns a detached task for `cpu`.
/// # C: O(1)
pub fn has_parked(cpu: u32) -> bool {
    PARKED.get(cpu as usize).is_some_and(|slot| !slot.task.load(Ordering::Acquire).is_null())
}

/// True when switch-tail owns this exact, now-off-CPU task.  Keeping the slot
/// published until TaskPi is acquired lets PI updates recognize that there is
/// no runqueue tree to re-key; the tail will consume their update before it
/// attaches the task to a destination.  `on_cpu == false` excludes the
/// no-switch rollback, which still has to requeue under the source rq lock.
/// # C: O(1)
pub(crate) fn owns_switched_parked(cpu: u32, task: &Task) -> bool {
    if task.on_cpu.load(Ordering::Acquire) { return false; }
    PARKED.get(cpu as usize).is_some_and(|slot| {
        let raw = slot.task.load(Ordering::Acquire);
        !raw.is_null() && core::ptr::eq(raw.cast_const(), core::ptr::from_ref(task))
    })
}

/// Reclaim the parked task and its destination. # C: O(1)
fn take(cpu: u32) -> Option<(Arc<Task>, u32)> {
    let slot = PARKED.get(cpu as usize)?;
    let raw = slot.task.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if raw.is_null() { return None; }
    let target = slot.target.swap(NO_TARGET, Ordering::AcqRel);
    // SAFETY: `raw` came from `Arc::into_raw` in `park` and is taken exactly
    // once — the swap that reads it also clears the slot.
    Some((unsafe { Arc::from_raw(raw) }, target))
}

/// Place the task the last switch off `cpu` parked, if any. Returns the CPU to
/// kick so it re-picks. Caller must hold NO runqueue lock: this takes the
/// destination runqueue's lock.
/// # C: O(log N)
#[cfg(test)]
pub fn place_parked_with<'a, F>(get_rq: &F, cpu: u32) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue> {
    place_parked_with_lock_probe(get_rq, cpu, &|cpu| get_rq(cpu).is_some(),
        &mut || {}, &mut |_, _, _| {})
}

#[cfg(test)]
fn place_parked_with_probe<'a, F, A, P>(get_rq: &F, cpu: u32, active: &A,
    probe: &mut P) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool,
      P: FnMut(crate::live::migration::MovePoint, u32, &Task) {
    place_parked_with_lock_probe(get_rq, cpu, active, &mut || {}, probe)
}

#[cfg(test)]
fn place_parked_with_lock_probe<'a, F, A, L, P>(get_rq: &F, cpu: u32, active: &A,
    lock_blocked: &mut L, probe: &mut P) -> Option<u32>
where F: Fn(u32) -> Option<&'a Runqueue>, A: Fn(u32) -> bool, L: FnMut(),
      P: FnMut(crate::live::migration::MovePoint, u32, &Task) {
    let slot = PARKED.get(cpu as usize)?;
    let raw = slot.task.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // Retain the published task before waiting for TaskPi.  Most importantly,
    // do not clear PARKED first: an already-running PI transaction must be
    // able to classify this off-rq bridge and finish, otherwise both sides
    // wait forever (PI waits for MIGRATING; switch-tail waits for TaskPi).
    // SAFETY: this CPU is the sole slot consumer and the slot owns one Arc
    // until `take`; this increment creates the independent `pi_owner` Arc.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: balances the increment immediately above.
    let pi_owner = unsafe { Arc::from_raw(raw) };
    if pi_owner.pi_lock.try_lock().is_none() { lock_blocked(); }
    let _pi = pi_owner.pi_lock.lock_irqsave::<RqIrq>();
    let (task, target) = take(cpu)?;
    let _placement = sync::rcu_read_lock();
    match crate::live::migration::place_detached_with(
        get_rq, task, Some(target), active, probe) {
        Ok(dest) => Some(dest),
        Err(task) => {
            let slot = &PARKED[cpu as usize];
            slot.target.store(target, Ordering::Release);
            slot.task.store(Arc::into_raw(task) as *mut Task, Ordering::Release);
            None
        }
    }
}

/// Place the switch-tail task on a live runqueue and kick a remote destination.
/// # C: O(log N)
pub fn place_parked(cpu: u32) {
    let Some(slot) = PARKED.get(cpu as usize) else { return; };
    let raw = slot.task.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: the per-CPU switch tail is the sole consumer; PARKED retains
    // the original strong reference until `take` below.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: balances the increment immediately above.
    let pi_owner = unsafe { Arc::from_raw(raw) };
    let pi = pi_owner.pi_lock.lock_irqsave::<RqIrq>();
    let Some((task, target)) = take(cpu) else { return; };
    let result = {
        let _placement = sync::rcu_read_lock();
        crate::live::migration::finish_unplaced_pi_locked_with(
            &|candidate| unsafe { global_for(candidate) }, task, cpu, Some(target),
            &cpu::smp::is_active, &mut |_, _, _| {})
    };
    drop(pi);
    drop(pi_owner);
    if let crate::live::migration::MoveResult::Moved { to, .. } = result {
        if to != cpu { crate::live::ttwu::resched_curr(to); }
    }
}

#[cfg(test)]
#[path = "migrate/tests.rs"]
mod tests;
