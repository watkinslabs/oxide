// Monotonic source the deadline class measures instances against, selected at
// the module boundary (`07§5`) rather than by scattering `#[cfg]` through the
// CBS wiring.
//
// The hosted build gets a settable clock, which is what makes the throttle and
// replenish EDGES testable without a boot: a test advances time by exactly one
// budget and asserts the task was thrown off the ready tree.

/// Monotonic nanoseconds.
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }

/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

#[cfg(not(target_os = "oxide-kernel"))]
mod hosted {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NOW: AtomicU64 = AtomicU64::new(0);

    /// # C: O(1)
    pub fn now_ns() -> u64 { NOW.load(Ordering::Acquire) }
    /// Set the hosted clock. Test-only driver for the CBS edges.
    /// # C: O(1)
    pub fn set_now_ns(v: u64) { NOW.store(v, Ordering::Release); }
    /// Advance the hosted clock. # C: O(1)
    pub fn advance_ns(d: u64) { NOW.fetch_add(d, Ordering::AcqRel); }
}

#[cfg(not(target_os = "oxide-kernel"))]
pub use hosted::{advance_ns, now_ns, set_now_ns};
