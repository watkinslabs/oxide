// Native NT syscall transition accounting. The timer is sampled at the real
// NT entry boundary; the accumulator is separate from Linux syscall buckets.
#![allow(dead_code)]

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
use core::sync::atomic::{AtomicU64, Ordering};

const NO_SAMPLE: u64 = u64::MAX;

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
static COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
static TOTAL_NS: AtomicU64 = AtomicU64::new(0);
#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
static MIN_NS: AtomicU64 = AtomicU64::new(NO_SAMPLE);
#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
static MAX_NS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stats { pub count: u64, pub total_ns: u64, pub min_ns: Option<u64>, pub max_ns: u64 }

/// Saturating addition used by both the checked model and production atomics.
/// # C: O(1)
const fn saturating_add(value: u64, delta: u64) -> u64 { value.saturating_add(delta) }

impl Stats {
    /// Empty aggregate before the first observed transition. # C: O(1)
    pub const fn empty() -> Self { Self { count: 0, total_ns: 0, min_ns: None, max_ns: 0 } }

    /// Add one timer-derived transition interval to the aggregate. # C: O(1)
    pub fn observe(&mut self, elapsed_ns: u64) {
        self.count = self.count.saturating_add(1);
        self.total_ns = self.total_ns.saturating_add(elapsed_ns);
        self.min_ns = Some(match self.min_ns { Some(value) => value.min(elapsed_ns), None => elapsed_ns });
        self.max_ns = self.max_ns.max(elapsed_ns);
    }
}

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")] { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")] { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
pub fn start() -> u64 { now_ns() }

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
pub fn record(start_ns: u64) {
    let elapsed_ns = now_ns().saturating_sub(start_ns);
    atomic_saturating_add(&COUNT, 1);
    atomic_saturating_add(&TOTAL_NS, elapsed_ns);
    let mut old = MIN_NS.load(Ordering::Relaxed);
    while elapsed_ns < old {
        match MIN_NS.compare_exchange_weak(old, elapsed_ns, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(value) => old = value,
        }
    }
    let mut old = MAX_NS.load(Ordering::Relaxed);
    while elapsed_ns > old {
        match MAX_NS.compare_exchange_weak(old, elapsed_ns, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(value) => old = value,
        }
    }
}

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
fn atomic_saturating_add(atom: &AtomicU64, delta: u64) {
    let mut old = atom.load(Ordering::Relaxed);
    loop {
        let next = saturating_add(old, delta);
        match atom.compare_exchange_weak(old, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(value) => old = value,
        }
    }
}

#[cfg(all(target_os = "oxide-kernel", feature = "debug-syscost"))]
pub fn dump() {
    let count = COUNT.load(Ordering::Relaxed);
    if count == 0 { return; }
    let total = TOTAL_NS.load(Ordering::Relaxed);
    klog::write_raw(b"[NT-SYSCOST] transitions="); klog::write_dec_u64(count);
    klog::write_raw(b" total_ns="); klog::write_dec_u64(total);
    klog::write_raw(b" avg_ns="); klog::write_dec_u64(total / count);
    klog::write_raw(b" min_ns="); klog::write_dec_u64(MIN_NS.load(Ordering::Relaxed));
    klog::write_raw(b" max_ns="); klog::write_dec_u64(MAX_NS.load(Ordering::Relaxed));
    klog::write_raw(b"\n");
}

#[cfg(test)]
mod tests {
    use super::{saturating_add, Stats};

    #[test]
    fn empty_stats_have_no_minimum() { assert_eq!(Stats::empty(), Stats::empty()); }

    #[test]
    fn stats_keep_real_sample_extrema_and_saturate() {
        let mut stats = Stats::empty();
        stats.observe(41); stats.observe(9); stats.observe(77);
        assert_eq!(stats, Stats { count: 3, total_ns: 127, min_ns: Some(9), max_ns: 77 });
        stats.observe(u64::MAX);
        assert_eq!(stats.total_ns, u64::MAX);
        assert_eq!(stats.min_ns, Some(9));
        assert_eq!(stats.max_ns, u64::MAX);
    }

    #[test]
    fn production_addition_contract_saturates_without_wrapping() {
        assert_eq!(saturating_add(u64::MAX - 2, 1), u64::MAX - 1);
        assert_eq!(saturating_add(u64::MAX - 2, 3), u64::MAX);
        assert_eq!(saturating_add(u64::MAX, 1), u64::MAX);
    }
}
