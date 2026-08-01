// Presentation-path diagnostics: count how a compositor actually presents
// frames so a flicker report is attributed to a mechanism rather than a guess.
//
// The three presentation entry points differ in what they imply:
//   - PAGE_FLIP alternating between >=2 distinct fb ids  => real double buffering
//   - PAGE_FLIP always naming the SAME fb id             => single buffer, live scanout
//   - DIRTYFB                                            => in-place render into the live scanout
//
// Counting is ungated so the policy below is host-testable; emission is
// rate-limited because a compositor presents at frame rate.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Emit one line per this many presentation events. # C: O(1)
pub const REPORT_INTERVAL: u64 = 120;

/// Presentation mechanism a single event used.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Present {
    Flip,
    Dirty,
    SetCrtc,
}

/// Emit iff `n` is the first event or lands on a `REPORT_INTERVAL` boundary,
/// so the first frame is always visible in a log and later ones sample.
/// `n` is the 1-based event ordinal. # C: O(1)
pub fn should_report(n: u64) -> bool {
    n == 1 || n % REPORT_INTERVAL == 0
}

/// Classify what the observed fb-id history implies about buffering.
/// `distinct` is how many different fb ids have been presented. # C: O(1)
pub fn is_single_buffered(distinct: u32) -> bool {
    distinct <= 1
}

static FLIPS:    AtomicU64 = AtomicU64::new(0);
static DIRTIES:  AtomicU64 = AtomicU64::new(0);
static SETCRTCS: AtomicU64 = AtomicU64::new(0);
static LAST_FB:  AtomicU32 = AtomicU32::new(0);
static PREV_FB:  AtomicU32 = AtomicU32::new(0);
static DISTINCT: AtomicU32 = AtomicU32::new(0);

/// Record one presentation of `fb_id` on `res_id` and emit a sampled line.
/// # C: O(1)
pub fn record(kind: Present, fb_id: u32, res_id: u32) {
    let counter = match kind {
        Present::Flip => &FLIPS,
        Present::Dirty => &DIRTIES,
        Present::SetCrtc => &SETCRTCS,
    };
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    let last = LAST_FB.swap(fb_id, Ordering::Relaxed);
    if last != fb_id {
        PREV_FB.store(last, Ordering::Relaxed);
        if last == 0 || PREV_FB.load(Ordering::Relaxed) != fb_id {
            DISTINCT.fetch_add(1, Ordering::Relaxed);
        }
    }
    if !should_report(n) { return; }
    klog::write_raw(match kind {
        Present::Flip => b"[DRM-PRESENT] flip n=",
        Present::Dirty => b"[DRM-PRESENT] dirty n=",
        Present::SetCrtc => b"[DRM-PRESENT] setcrtc n=",
    });
    klog::write_hex_u64(n);
    klog::write_raw(b" fb="); klog::write_hex_u64(fb_id as u64);
    klog::write_raw(b" prev="); klog::write_hex_u64(PREV_FB.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" res="); klog::write_hex_u64(res_id as u64);
    klog::write_raw(b" distinct="); klog::write_hex_u64(DISTINCT.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" flips="); klog::write_hex_u64(FLIPS.load(Ordering::Relaxed));
    klog::write_raw(b" dirty="); klog::write_hex_u64(DIRTIES.load(Ordering::Relaxed));
    klog::write_raw(b"\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_first_event_then_every_interval() {
        assert!(should_report(1));
        assert!(!should_report(2));
        assert!(!should_report(REPORT_INTERVAL - 1));
        assert!(should_report(REPORT_INTERVAL));
        assert!(should_report(REPORT_INTERVAL * 2));
        assert!(!should_report(REPORT_INTERVAL * 2 + 1));
    }

    #[test]
    fn single_buffer_classification() {
        assert!(is_single_buffered(0));
        assert!(is_single_buffered(1));
        assert!(!is_single_buffered(2));
    }
}
