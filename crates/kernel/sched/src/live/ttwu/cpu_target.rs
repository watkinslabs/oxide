//! Current-CPU identity and reschedule targeting for wake placement.

/// This CPU's index (gs:0 / TPIDR). Host build → 0.
#[inline]
pub(super) fn this_cpu() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) as u32 }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) as u32 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[cfg(feature = "debug-watchdog")]
#[inline]
pub(super) fn wake_diag_now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Activate the wake list claimed for `rq` on its owning CPU. IRQ dispatchers
/// call this on their IRQ stack; idle polling supplies the no-IPI path.
/// # C: O(deferred * log N)
pub(crate) fn service_pending_on(rq: &crate::live::runqueue::Runqueue) -> bool {
    use core::sync::atomic::Ordering;
    let current = rq.current.load(Ordering::Acquire);
    super::sched_ttwu_pending(rq.cpu as u32, current, rq)
}

/// Activate wakeups queued to this CPU, if its runqueue is installed.
/// # C: O(1) when no wake list is pending; O(deferred * log N) otherwise
pub fn service_current_cpu() -> bool {
    let Some(rq) = super::super::runqueue::global() else { return false; };
    service_pending_on(rq)
}

/// Make `cpu` reschedule (Linux `resched_curr`): set its per-CPU
/// `need_resched`; if it is remote, send a reschedule IPI so it re-enters
/// `schedule()` promptly. The local CPU consumes the flag on its next
/// return-to-user or idle-loop schedule. # C: O(1)
pub fn resched_curr(cpu: u32) {
    crate::preempt::set_need_resched_on(cpu as usize);
    if cpu != this_cpu() {
        // SAFETY: non-blocking IPI/SGI to an online CPU; the boot-installed
        // hook is a no-op until architecture routing is available.
        unsafe { let _ = super::super::send_resched_ipi(cpu); }
    }
}
