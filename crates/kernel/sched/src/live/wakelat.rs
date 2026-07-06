// debug-wakelat: runtime wake→run latency + tick-period instrumentation.
//
// Permanently in-tree, gated behind the `debug-wakelat` cargo feature
// (default-off, HARD house rule: gated debug probes stay). When the
// feature is off every entry point compiles to an empty inline no-op, so
// there is zero steady-state cost.
//
// It answers the three gnome-hang wakeup hypotheses in a single boot:
//   H1 (missed arrival-edge wake → task only roused by the 100 ms
//       deadline scanner): `note_runnable` records the wake SOURCE
//       (edge `try_to_wake_up` vs deferred `ttwu_deferred`/scanner), so
//       a wait that consistently wakes via the scanner shows src=defer.
//   H2 (woken Runnable but not SWITCHED-IN promptly on UP): the wake→run
//       delta (`note_runnable` timestamp vs `note_switch_in`) surfaces as
//       `[WLLAT]` when it exceeds `LAT_LOG_THRESH_NS`.
//   H3 (slow / stalled periodic tick): `note_tick` reports the measured
//       LAPIC period every `TICK_SAMPLE` ticks and flags any inter-tick
//       gap over `TICK_GAP_THRESH_NS` as `[WLTICKGAP]`; `note_scan`
//       flags stretched `tick_wake_expired` scan gaps.
//
// Correlation is a lock-free direct-mapped table keyed by `tid % SLOTS`
// with a tid tag, so it is safe from IRQ / preempt-off scheduler context
// and never allocates. A colliding tid simply overwrites the slot — a
// dropped sample, never corruption. Logging is threshold-gated so only
// pathological stalls reach the serial console (no per-wake flood that
// would itself distort the timing it measures).

#![cfg(feature = "debug-wakelat")]

use core::sync::atomic::{AtomicU64, Ordering};

/// Wake→run delay at or above which a `[WLLAT]` line is emitted. Below
/// this is ordinary CFS jitter (sub-tick) and stays silent. 50 ms is
/// well under gdm's 30 s TimeoutStartSec yet an order of magnitude over a
/// healthy ~1 ms tick, so only genuine stalls trip it.
const LAT_LOG_THRESH_NS: u64 = 50_000_000;
/// Inter-tick gap flagged as a stalled periodic tick.
const TICK_GAP_THRESH_NS: u64 = 50_000_000;
/// `tick_wake_expired` scan-gap flagged as a stretched safety-net scan
/// (the scanner self-throttles to 100 ms; > 250 ms means ticks stalled).
const SCAN_GAP_THRESH_NS: u64 = 250_000_000;
/// Emit one `[WLTICK]` period sample every this many ticks.
const TICK_SAMPLE: u64 = 4096;

/// Wait-primitive tags stored by the park sites (`note_wait`).
pub const KIND_OTHER: u64 = 0;
pub const KIND_EPOLL: u64 = 1;
pub const KIND_FUTEX: u64 = 2;
pub const KIND_RECVMSG: u64 = 3;
pub const KIND_POLL: u64 = 4;

/// Wake-source tags (`note_runnable`).
pub const SRC_EDGE: u64 = 0; // try_to_wake_up (targeted arrival-edge wake)
pub const SRC_DEFER: u64 = 1; // ttwu_deferred (timer-ISR / scanner / remote)

const SLOTS: usize = 2048;

struct Slot {
    /// tid occupying this slot (0 = empty). Tag to detect `tid % SLOTS`
    /// collisions so a stale sample for a different tid is discarded.
    tid: AtomicU64,
    /// Monotonic ns the task was made Runnable by the last wake; 0 once
    /// consumed by `note_switch_in` (so a plain re-schedule of an
    /// already-Runnable task posts no false latency).
    runnable_ns: AtomicU64,
    /// Low 8 bits = wait-primitive KIND_*; bit 8 = wake SRC_* flag.
    meta: AtomicU64,
}

const EMPTY: Slot = Slot {
    tid: AtomicU64::new(0),
    runnable_ns: AtomicU64::new(0),
    meta: AtomicU64::new(0),
};
static TABLE: [Slot; SLOTS] = [EMPTY; SLOTS];

#[inline]
fn slot(tid: u32) -> &'static Slot {
    &TABLE[(tid as usize) % SLOTS]
}

/// Record the wait primitive a task is about to block in. Called from the
/// park / busy-yield sites just before yielding. Claims the slot for this
/// tid and stores the KIND_* tag.
/// # C: O(1)
#[inline]
pub fn note_wait(tid: u32, kind: u64) {
    if tid == 0 { return; }
    let s = slot(tid);
    s.tid.store(tid as u64, Ordering::Relaxed);
    s.meta.store(kind & 0xff, Ordering::Relaxed);
    s.runnable_ns.store(0, Ordering::Relaxed);
}

/// Record that `tid` was made Runnable at `now` by a wake of source `src`
/// (SRC_EDGE / SRC_DEFER). Only stamps if the slot still belongs to this
/// tid (i.e. it went through `note_wait`); a wake of a task we never saw
/// park is not interesting for the IPC-latency question.
/// # C: O(1)
#[inline]
pub fn note_runnable(tid: u32, now: u64, src: u64) {
    if tid == 0 { return; }
    let s = slot(tid);
    if s.tid.load(Ordering::Relaxed) != tid as u64 { return; }
    let kind = s.meta.load(Ordering::Relaxed) & 0xff;
    s.meta.store(kind | ((src & 1) << 8), Ordering::Relaxed);
    s.runnable_ns.store(now.max(1), Ordering::Relaxed);
}

/// Record that `tid` was switched IN at `now`. If it carries an
/// unconsumed wake stamp, compute the wake→run delta and emit `[WLLAT]`
/// when it crosses the threshold. Clears the stamp so the next genuine
/// wake measures fresh.
/// # C: O(1)
#[inline]
pub fn note_switch_in(tid: u32, now: u64) {
    if tid == 0 { return; }
    let s = slot(tid);
    if s.tid.load(Ordering::Relaxed) != tid as u64 { return; }
    let r = s.runnable_ns.swap(0, Ordering::Relaxed);
    if r == 0 { return; }
    let lat = now.saturating_sub(r);
    if lat < LAT_LOG_THRESH_NS { return; }
    let meta = s.meta.load(Ordering::Relaxed);
    klog::write_raw(b"[WLLAT tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" kind=");
    klog::write_dec_u64(meta & 0xff);
    klog::write_raw(b" src=");
    klog::write_dec_u64((meta >> 8) & 1);
    klog::write_raw(b" lat_us=");
    klog::write_dec_u64(lat / 1000);
    klog::write_raw(b"]\n");
}

/// Directly report a busy-yield blocking loop (recvmsg / epoll) that
/// finally made progress after `waited` ns. Emits `[WLBLK]` past the
/// latency threshold — this catches Runnable-but-starved stalls that
/// never transit Sleeping and so post no `note_runnable`.
/// # C: O(1)
#[inline]
pub fn note_blocked(tid: u32, kind: u64, waited: u64, ready: u64) {
    if waited < LAT_LOG_THRESH_NS { return; }
    klog::write_raw(b"[WLBLK tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" kind=");
    klog::write_dec_u64(kind);
    klog::write_raw(b" waited_us=");
    klog::write_dec_u64(waited / 1000);
    klog::write_raw(b" ready=");
    klog::write_dec_u64(ready);
    klog::write_raw(b"]\n");
}

static LAST_TICK_NS: AtomicU64 = AtomicU64::new(0);
static TICK_N: AtomicU64 = AtomicU64::new(0);
static SAMPLE_ANCHOR_NS: AtomicU64 = AtomicU64::new(0);

/// Called from the LAPIC timer dispatcher on every VEC_TIMER tick.
/// Reports the measured mean period every `TICK_SAMPLE` ticks and flags
/// any single inter-tick gap over `TICK_GAP_THRESH_NS`.
/// # C: O(1)
#[inline]
pub fn note_tick(now: u64) {
    if now == 0 { return; }
    let prev = LAST_TICK_NS.swap(now, Ordering::Relaxed);
    let n = TICK_N.fetch_add(1, Ordering::Relaxed) + 1;
    if prev != 0 {
        let gap = now.saturating_sub(prev);
        if gap >= TICK_GAP_THRESH_NS {
            klog::write_raw(b"[WLTICKGAP us=");
            klog::write_dec_u64(gap / 1000);
            klog::write_raw(b"]\n");
        }
    }
    if n % TICK_SAMPLE == 0 {
        let anchor = SAMPLE_ANCHOR_NS.swap(now, Ordering::Relaxed);
        if anchor != 0 {
            let per = now.saturating_sub(anchor) / TICK_SAMPLE;
            klog::write_raw(b"[WLTICK n=");
            klog::write_dec_u64(n);
            klog::write_raw(b" period_us=");
            klog::write_dec_u64(per / 1000);
            klog::write_raw(b"]\n");
        }
    }
}

static LAST_SCAN_NS: AtomicU64 = AtomicU64::new(0);

/// Called each time `tick_wake_expired` actually runs a scan (after its
/// 100 ms throttle). Flags a scan gap far over the 100 ms cadence, which
/// means the tick that drives it stalled.
/// # C: O(1)
#[inline]
pub fn note_scan(now: u64) {
    let prev = LAST_SCAN_NS.swap(now, Ordering::Relaxed);
    if prev == 0 { return; }
    let gap = now.saturating_sub(prev);
    if gap >= SCAN_GAP_THRESH_NS {
        klog::write_raw(b"[WLSCANGAP us=");
        klog::write_dec_u64(gap / 1000);
        klog::write_raw(b"]\n");
    }
}
