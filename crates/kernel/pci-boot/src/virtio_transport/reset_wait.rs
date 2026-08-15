//! Bootstrap delay for modern virtio status polling.

use hal::TimerOps;

const RESET_POLL_INTERVAL_NS: u64 = 1_000_000;

#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { hal_aarch64::ArmTimerOps::monotonic_ns().0 }

/// Delay one modern-virtio reset poll before a running task exists.
///
/// The architecture timer is calibrated before `kernel_main`, so this is a
/// time interval rather than an iteration budget. Runtime teardown uses the
/// scheduler sleep variant instead.
/// # Ctx: boot, IRQ-off, single CPU
/// # C: O(1 ms)
pub(crate) fn wait_one_ms() {
    let deadline = now_ns().saturating_add(RESET_POLL_INTERVAL_NS);
    while now_ns() < deadline { sync::spin_relax::relax(); }
}
