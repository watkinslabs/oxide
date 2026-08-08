// Record rate limiting for the `/dev/kmsg` write side.
//
// A token-bucket over a fixed interval: up to `BURST` records per `INTERVAL`,
// after which writes are dropped until the interval rolls over. Lock-free —
// the limiter runs on the emit path, which any context may reach.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Records admitted per interval before the limiter starts dropping.
pub const BURST: u32 = 10;
/// Limiter interval in nanoseconds.
pub const INTERVAL_NS: u64 = 5_000_000_000;

static WINDOW_START_NS: AtomicU64 = AtomicU64::new(0);
static ADMITTED: AtomicU32 = AtomicU32::new(0);

/// Decide whether a `/dev/kmsg` record is admitted at monotonic time `now`.
/// `None` (no clock installed yet) admits: the pre-timer window is early boot,
/// where dropping records loses exactly the evidence the limiter is not there
/// to protect against.
/// # C: O(1)
pub fn devkmsg_allow(now: Option<u64>) -> bool {
    let Some(now) = now else { return true };
    admit(now, &WINDOW_START_NS, &ADMITTED)
}

/// Token-bucket decision over an explicit window pair. Split out with no
/// globals so the policy is testable without touching the live limiter.
/// # C: O(1)
pub fn admit(now: u64, window_start: &AtomicU64, admitted: &AtomicU32) -> bool {
    let start = window_start.load(Ordering::Acquire);
    if start == 0 || now.wrapping_sub(start) >= INTERVAL_NS {
        window_start.store(now, Ordering::Release);
        admitted.store(1, Ordering::Release);
        return true;
    }
    admitted.fetch_add(1, Ordering::AcqRel) < BURST
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (AtomicU64, AtomicU32) { (AtomicU64::new(0), AtomicU32::new(0)) }

    #[test]
    fn burst_is_admitted_then_the_window_closes() {
        let (w, a) = fresh();
        for i in 0..BURST { assert!(admit(1_000 + i as u64, &w, &a), "record {i} within burst"); }
        assert!(!admit(1_000 + BURST as u64, &w, &a), "the record past the burst is dropped");
    }

    #[test]
    fn a_new_interval_refills_the_bucket() {
        let (w, a) = fresh();
        for i in 0..BURST + 5 { let _ = admit(1_000 + i as u64, &w, &a); }
        assert!(!admit(1_100, &w, &a), "still inside the first interval");
        assert!(admit(1_000 + INTERVAL_NS, &w, &a), "interval rolled over");
    }

    #[test]
    fn no_clock_admits_everything() {
        for _ in 0..BURST * 3 { assert!(devkmsg_allow(None), "early boot must not drop records"); }
    }
}
