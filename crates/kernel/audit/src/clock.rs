// Time source for record stamps and the rate-limit window.
//
// Compiler-gated at the module boundary: the kernel reads the real clock, a
// hosted build reads a settable one so record text and window rollover are
// deterministic under `cargo test`.

#[cfg(target_os = "oxide-kernel")]
mod imp {
    /// # C: O(1)
    pub fn realtime_ns() -> u64 { timekeeper::realtime_ns() }
}

#[cfg(not(target_os = "oxide-kernel"))]
mod imp {
    use core::sync::atomic::{AtomicU64, Ordering};

    static NOW_NS: AtomicU64 = AtomicU64::new(0);

    /// # C: O(1)
    pub fn realtime_ns() -> u64 { NOW_NS.load(Ordering::Relaxed) }

    /// # C: O(1)
    pub fn set_realtime_ns(v: u64) { NOW_NS.store(v, Ordering::Relaxed); }
}

pub use imp::realtime_ns;
#[cfg(not(target_os = "oxide-kernel"))]
pub use imp::set_realtime_ns;

/// Milliseconds since boot-clock zero, the unit the rate limiter counts in.
/// # C: O(1)
pub fn now_ms() -> u64 {
    const NS_PER_MS: u64 = 1_000_000;
    realtime_ns() / NS_PER_MS
}
