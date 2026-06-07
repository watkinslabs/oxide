// Shared poll/ppoll helper (docs/53 §0). `monotonic_ns` is used by both
// the slot-7 poll handler and the slot-271 ppoll handler.
#![cfg(target_os = "oxide-kernel")]

/// # C: O(1) monotonic clock read
#[inline]
pub(crate) fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
