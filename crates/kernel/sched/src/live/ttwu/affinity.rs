use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::live::runqueue::{RqIrq, Runqueue};
use crate::Task;
use super::cpu_target::this_cpu;
use crate::live::runqueue::global_for;
use crate::live::rq_locate;

use super::resched_curr;

/// Choose the CPU to wake `task` on (Linux `select_task_rq`): the idlest
/// online runqueue (fewest `nr_running`) among the task's allowed CPUs,
/// biased to the caller's local CPU on ties (wake-affine: a not-busier
/// local stays cache-warm). Honors `cpus_allowed` (sched_setaffinity /
/// cpuset). UP / single online CPU → that CPU.
/// # C: O(N_cpus)
pub fn select_task_rq(task: &Task) -> u32 {
    let online = cpu::smp::online_cpumask();
    // SAFETY: `global_for` is sound for any index; it yields `None` for a CPU
    // that has not completed `install_global`, which the walk skips.
    select_task_rq_with(&|c| {
        if !online.contains(c as usize) || !cpu::smp::accepts_work(c) { None } else {
            // SAFETY: online publication follows runqueue installation.
            unsafe { global_for(c) }
        }
    }, this_cpu(), task)
}

/// [`select_task_rq`] over an injected CPU->runqueue accessor, so the placement
/// decision is exercised by hosted tests against real `Runqueue` instances on
/// more than one CPU (`GLOBALS` only accepts writes for `this_cpu()`, which is
/// unconditionally 0 off-target). Same split `rq_locate` uses.
/// # C: O(N_cpus)
pub fn select_task_rq_with<'a, F>(get_rq: &F, local: u32, task: &Task) -> u32
where F: Fn(u32) -> Option<&'a Runqueue> {
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    let prev = task.cpu.load(Ordering::Acquire);
    if prev != u16::MAX {
        let cpu = prev as u32;
        if allowed.contains(cpu as usize) {
            if let Some(rq) = get_rq(cpu) {
                // Keep prev ONLY if it is idle (cache-warm + runs the wakee
                // immediately). If prev is busy, fall through to the idlest-CPU
                // scan so the wakee lands on an idle CPU and runs now instead of
                // queueing behind prev's current task — Linux
                // `select_idle_sibling`. An unconditional prev-return made a
                // woken sync-I/O waiter wait multi-ms with idle CPUs free.
                if rq.nr_running.load(Ordering::Acquire) == 0 { return cpu; }
            }
        }
    }
    let mut best: Option<u32> = None;
    let mut best_load = u32::MAX;
    // Visit local first so equal-load ties resolve to it (wake-affine).
    let order = core::iter::once(local)
        .chain((0..cpu::MAX_CPUS as u32).filter(move |&c| c != local));
    for cpu in order {
        if !allowed.contains(cpu as usize) { continue; }
        if let Some(rq) = get_rq(cpu) {
            let load = rq.nr_running.load(Ordering::Acquire);
            if load < best_load { best_load = load; best = Some(cpu); }
        }
    }
    best.unwrap_or(local)
}

/// Honor a changed `cpus_allowed` (sched_setaffinity / cpuset): move `task`
/// off any disallowed CPU.
///
/// A task QUEUED (on_rq, not currently running) on a now-disallowed CPU is
/// dequeued here and re-placed by `select_task_rq` — it is not executing, so
/// there is no cross-CPU race. A task RUNNING on a disallowed CPU is only
/// nudged with need_resched plus a reschedule IPI: it cannot be moved while it
/// still owns a CPU's register context. The eviction itself happens when that
/// nudge lands in `schedule()`, which parks the task and lets the incoming
/// task's `finish_task_switch` place it once `on_cpu` has cleared
/// (`live::schedule::migrate`). UP / single CPU: no-op (allowed == local).
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity(task: &Arc<Task>, allowed: cpu::CpuMask) {
    // Affinity and ttwu share the task wake lock. Hold it through removing
    // queued work and selecting its replacement CPU, so a concurrent wake
    // sees either the old placement or this completed new one, never a mix.
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    relocate_for_affinity_live(task, allowed)
}

/// Publish one source of a task affinity mask and complete its relocation
/// while holding the same task-side lock ttwu uses for CPU selection.
/// # C: O(N_cpus · log N)
pub fn update_affinity(task: &Arc<Task>, user: Option<cpu::CpuMask>, cpuset: Option<cpu::CpuMask>) {
    let _wake = task.pi_lock.lock_irqsave::<RqIrq>();
    if let Some(mask) = user { task.user_cpus_allowed.store(mask, Ordering::Release); }
    if let Some(mask) = cpuset { task.cpuset_cpus_allowed.store(mask, Ordering::Release); }
    let source = if user.is_some() {
        crate::affinity::MaskChange::UserRequest
    } else {
        crate::affinity::MaskChange::CpusetUpdate
    };
    let allowed = crate::affinity::compose(
        task.cpuset_cpus_allowed.load(Ordering::Acquire),
        task.user_cpus_allowed.load(Ordering::Acquire), source,
    );
    task.cpus_allowed.store(allowed, Ordering::Release);
    relocate_for_affinity_live(task, allowed);
}

fn relocate_for_affinity_live(task: &Arc<Task>, allowed: cpu::CpuMask) {
    let online = cpu::smp::online_cpumask();
    // SAFETY: `global_for` is sound for any index and yields `None` for a CPU
    // that has not completed `install_global`, which the walk skips.
    relocate_for_affinity_with(&|c| {
        if !online.contains(c as usize) || !cpu::smp::accepts_work(c) { None } else {
            // SAFETY: online publication follows runqueue installation.
            unsafe { global_for(c) }
        }
    }, task, allowed)
}

/// Place `task` on `target`, falling back to `fallback` when `target` has no
/// installed runqueue. Returns whether `target` took it.
/// # C: O(log N)
fn enqueue_on_with_fallback<'a, F>(get_rq: &F, target: u32, fallback: u32, task: Arc<Task>) -> bool
where F: Fn(u32) -> Option<&'a Runqueue> {
    if get_rq(target).is_some() {
        return rq_locate::enqueue_on_with(get_rq, target, task);
    }
    let _ = rq_locate::enqueue_on_with(get_rq, fallback, task);
    false
}

/// [`relocate_for_affinity`] over an injected CPU->runqueue accessor, so the
/// relocation is exercised by hosted tests against real `Runqueue` instances
/// on more than one CPU. Same split [`select_task_rq_with`] uses, and for the
/// same reason: the un-split version reaches only the live per-CPU globals,
/// which off-target exist for CPU 0 alone — that is how the running-task half
/// of this function shipped untested.
/// # C: O(N_cpus · log N)
pub fn relocate_for_affinity_with<'a, F>(get_rq: &F, task: &Arc<Task>, allowed: cpu::CpuMask)
where F: Fn(u32) -> Option<&'a Runqueue> {

    let tid = task.tid;
    for cpu in 0..cpu::MAX_CPUS as u32 {
        // Skip CPUs the task is allowed on.
        if allowed.contains(cpu as usize) { continue; }
        let rq = match get_rq(cpu) { Some(r) => r, None => continue };
        // Try to dequeue it from this disallowed CPU's runqueue (queued, not
        // running). One rq lock at a time — no nesting, no ordering hazard.
        let removed = {
            let mut inner = rq.inner.lock_irqsave::<RqIrq>();
            let r = inner.remove(tid);
            if r.is_some() { rq.publish_nr_running(inner.nr_running()); }
            r
        };
        if let Some(moved) = removed {
            moved.on_rq.store(false, Ordering::Release);
            // Re-place on an allowed CPU (select_task_rq filters by the mask).
            // When the mask names no CPU with an installed runqueue the
            // placement fails, and the task must go back where it came from:
            // affinity is broken before a runnable task is stranded, which is
            // what dropping it here would do — silently and permanently.
            let target = select_task_rq_with(get_rq, this_cpu(), &moved);
            let dest = if enqueue_on_with_fallback(get_rq, target, cpu, moved) { target } else { cpu };
            resched_curr(dest);
        } else {
            // Not queued here — is it the RUNNING task on this disallowed CPU?
            // It cannot be moved while it owns this CPU's register context, so
            // it is nudged instead; `schedule()` parks it and the incoming
            // task's `finish_task_switch` places it on an allowed CPU.
            let cur = rq.current.load(Ordering::Acquire);
            // SAFETY: rq.current is non-null after install; the pointee is kept
            // alive by the rq's strong ref; reading the tid field is sound.
            if !cur.is_null() && unsafe { (&(*cur)).tid } == tid {
                resched_curr(cpu);
            }
        }
    }
}
