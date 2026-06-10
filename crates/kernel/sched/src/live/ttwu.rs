// try_to_wake_up + wake-time CPU placement per `13§11` (Linux ttwu /
// select_task_rq). A blocking wait wakes a task by transitioning it
// Sleeping→Runnable and enqueuing it on a chosen CPU's runqueue; this module
// is the "which CPU" + "make that CPU reschedule" half. The periodic load
// balancer (`balance.rs`) redistributes afterwards; ttwu places work near
// idle CPUs at wake time so the idle AP picks it up without waiting a tick.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{Task, TaskState};
use super::runqueue::global_for;

/// This CPU's index (gs:0 / TPIDR). Host build → 0.
#[inline]
fn this_cpu() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Choose the CPU to wake `task` on (Linux `select_task_rq`): the idlest
/// online runqueue (fewest `nr_running`) among the task's allowed CPUs,
/// biased to the caller's local CPU on ties (wake-affine: a not-busier
/// local stays cache-warm). Honors `cpus_allowed` (sched_setaffinity /
/// cpuset). UP / single online CPU → that CPU.
/// # C: O(N_cpus)
pub fn select_task_rq(task: &Task) -> u32 {
    let allowed = task.cpus_allowed.load(Ordering::Acquire);
    let local = this_cpu();
    let mut best: Option<u32> = None;
    let mut best_load = u32::MAX;
    // Visit local first so equal-load ties resolve to it (wake-affine).
    let order = core::iter::once(local)
        .chain((0..cpu::MAX_CPUS as u32).filter(move |&c| c != local));
    for cpu in order {
        // Affinity: only CPUs in the task's mask (bit per CPU, <64).
        if cpu < 64 && (allowed & (1u64 << cpu)) == 0 { continue; }
        // SAFETY: global_for is sound for any index; returns None unless that
        // CPU has installed its runqueue (online + scheduling).
        if let Some(rq) = unsafe { global_for(cpu) } {
            let load = rq.nr_running.load(Ordering::Acquire);
            if load < best_load { best_load = load; best = Some(cpu); }
        }
    }
    best.unwrap_or(local)
}

/// Make `cpu` reschedule (Linux `resched_curr`): set its per-CPU
/// `need_resched`; if it's a REMOTE CPU, send a reschedule IPI so it
/// re-enters `schedule()` promptly — waking its idle `hlt`/`wfi`, or
/// preempting its current user task at the next IRQ-exit. Local: the next
/// return-to-user / idle-loop schedule consumes the flag.
/// # C: O(1)
pub fn resched_curr(cpu: u32) {
    crate::preempt::set_need_resched_on(cpu as usize);
    if cpu != this_cpu() {
        // x86: CPU index == LAPIC apic_id (gs:0 stamped from the MADT id);
        // arm: GIC SGI target. Hook installed at boot (set_send_resched_ipi_hook).
        // SAFETY: non-blocking IPI/SGI to an online CPU; no-op if the hook is unset.
        unsafe { let _ = super::send_resched_ipi(cpu); }
    }
}

/// Linux `try_to_wake_up`: place a Sleeping `task` Runnable on its selected
/// CPU's runqueue and make that CPU reschedule. Returns true on a genuine
/// Sleeping→Runnable transition; false if the task was already runnable /
/// exiting (a racing waker won, or it's a stale wait-list entry). The target
/// rq's lock is taken cross-CPU (B1 made the switch hold rq->lock so a remote
/// pick never observes a half-updated rq).
/// # SAFETY: caller is a wake site (process/IRQ ctx); the Arc keeps `task`
/// alive; preempt discipline per the wake path.
/// # C: O(N_cpus + log N)
pub unsafe fn try_to_wake_up(task: Arc<Task>) -> bool {
    if task.state() != TaskState::Sleeping { return false; }
    let target = select_task_rq(&task);
    // SAFETY: global_for(target) reads the per-CPU runqueue slot; sound for any
    // index, returns None unless that CPU installed its rq (online + scheduling).
    let rq = match unsafe { global_for(target) } { Some(r) => r, None => return false };
    {
        let mut inner = rq.inner.lock();
        // Re-check under the rq lock — another CPU's waker may have raced us
        // (Linux's ttwu re-reads p->state under the lock).
        if task.state() != TaskState::Sleeping { return false; }
        task.set_state(TaskState::Runnable);
        // Explicit wake clears any SO_*TIMEO deadline so the scanner doesn't
        // also re-rouse it.
        task.wakeup_deadline_ns.store(0, Ordering::Release);
        // Sleeper credit on wake (F211).
        task.set_vruntime_to_floor(inner.cfs.min_vruntime());
        inner.enqueue(task);
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    resched_curr(target);
    true
}
