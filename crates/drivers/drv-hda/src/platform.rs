//! Architecture-selected clock and physical-to-virtual mapping helpers.

#![cfg(target_os = "oxide-kernel")]

/// HHDM base for the running architecture. # C: O(1)
#[inline]
pub(crate) fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
}

/// Monotonic wall clock in nanoseconds. # C: O(1)
#[inline]
pub(crate) fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Spin until `deadline_ns`, yielding the pipeline. # C: O(1)
#[inline]
pub(crate) fn spin_until(deadline_ns: u64) {
    while now_ns() < deadline_ns { core::hint::spin_loop(); }
}

/// Busy-wait `us` microseconds. # C: O(us)
#[inline]
pub(crate) fn udelay(us: u64) { spin_until(now_ns() + us * 1_000); }
