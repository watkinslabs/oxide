//! Opt-in ext4 `fsync(2)` durability-boundary latency probes.

#[cfg(target_os = "oxide-kernel")]
use hal::TimerOps;

const LATENCY_REPORT_NS: u64 = 1_000_000;

#[inline]
pub(crate) fn now_ns() -> u64 {
    #[cfg(target_os = "oxide-kernel")]
    {
        #[cfg(target_arch = "x86_64")]
        { return hal_x86_64::X86TimerOps::monotonic_ns().0; }
        #[cfg(target_arch = "aarch64")]
        { return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[inline]
pub(crate) fn report(stage: &'static [u8], start_ns: u64, blocks: u64) {
    let elapsed_ns = now_ns().saturating_sub(start_ns);
    if elapsed_ns < LATENCY_REPORT_NS { return; }
    klog::write_raw(b"[EXT4-FSYNC stage=");
    klog::write_raw(stage);
    klog::write_raw(b" ns=");
    klog::write_dec_u64(elapsed_ns);
    klog::write_raw(b" blocks=");
    klog::write_dec_u64(blocks);
    klog::write_raw(b"]\n");
}
