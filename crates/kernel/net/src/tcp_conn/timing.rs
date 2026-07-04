//! Clock helpers used by TCP timestamps / keepalive.

/// F182: monotonic millisecond clock for TSval per RFC 7323 §5.4.
/// # C: O(1)
pub fn ka_now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

/// F182: monotonic ms clock for TSval.
/// # C: O(1)
pub fn tcp_now_ms() -> u32 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return (hal_x86_64::X86TimerOps::monotonic_ns().0 / 1_000_000) as u32; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return (hal_aarch64::ArmTimerOps::monotonic_ns().0 / 1_000_000) as u32; }
    #[allow(unreachable_code)]
    0
}
