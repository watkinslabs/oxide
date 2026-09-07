//! Where one window flush's time goes, split three ways: serialising the
//! surface pixels into a wire payload, handing the record to the transport
//! queue, and the desktop's acknowledgement of the pixels it was handed.
//!
//! The three demand different repairs. Serialise time is data volume and is
//! repaired by sending less of the surface; enqueue time is the second copy
//! the queue makes of the payload plus the queue lock; acknowledgement time
//! is the bridge's own scheduling and its X server, which no payload size
//! changes.
//!
//! Bounded, because the instrument sits inside the path it measures: one line
//! is about eighty bytes on a serial console and a caret blink flushes twice
//! a second. An unbounded trace here spends more time reporting flushes than
//! performing them, which is the instrument changing what it measures.

#![cfg(feature = "debug-winframe")]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Flushes reported before the trace goes quiet.
const TRACE_BUDGET: u32 = 96;
/// Nanoseconds per microsecond, the unit every interval reports.
const NS_PER_US: u64 = 1_000;
/// Flushes whose timings are retained while their acknowledgement is
/// outstanding. A frame is handed over unawaited, so its acknowledgement
/// arrives on the reader thread long after the flush returned.
const SLOTS: usize = 8;

static SPENT: AtomicU32 = AtomicU32::new(0);
/// Serialise cost and payload size of the flush that has not yet been enqueued.
static PENDING_NS: AtomicU64 = AtomicU64::new(0);
static PENDING_BYTES: AtomicU64 = AtomicU64::new(0);

static SEQUENCE: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static BYTES: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static SERIALISE_NS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static ENQUEUE_NS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static HANDOVER_NS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static PICKUP_NS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static WRITE_NS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

/// Open an interval. # C: O(1)
pub(crate) fn now() -> u64 { timekeeper::monotonic_ns() }

/// Charge one surface serialisation and the payload it produced. # C: O(1)
pub(crate) fn serialised(start: u64, bytes: usize) {
    PENDING_NS.store(now().saturating_sub(start), Ordering::Relaxed);
    PENDING_BYTES.store(bytes as u64, Ordering::Relaxed);
}

/// Charge the hand-over of one serialised record to the transport queue and
/// retain it until the desktop acknowledges that sequence. # C: O(1)
pub(crate) fn enqueued(start: u64, sequence: u64) {
    if sequence == 0 { return; }
    let slot = (sequence as usize) % SLOTS;
    SEQUENCE[slot].store(sequence, Ordering::Relaxed);
    BYTES[slot].store(PENDING_BYTES.swap(0, Ordering::Relaxed), Ordering::Relaxed);
    SERIALISE_NS[slot].store(PENDING_NS.swap(0, Ordering::Relaxed), Ordering::Relaxed);
    ENQUEUE_NS[slot].store(now().saturating_sub(start), Ordering::Relaxed);
    HANDOVER_NS[slot].store(now(), Ordering::Relaxed);
}

/// Charge the interval the record waited for the transport writer to wake and
/// pick it up. # C: O(1)
pub(crate) fn taken(sequence: u64) {
    let slot = (sequence as usize) % SLOTS;
    if SEQUENCE[slot].load(Ordering::Relaxed) != sequence { return; }
    PICKUP_NS[slot].store(now().saturating_sub(HANDOVER_NS[slot].load(Ordering::Relaxed)), Ordering::Relaxed);
}

/// Charge the socket write itself, which ends when the desktop has the bytes
/// and has not yet answered for them. # C: O(1)
pub(crate) fn written(sequence: u64) {
    let slot = (sequence as usize) % SLOTS;
    if SEQUENCE[slot].load(Ordering::Relaxed) != sequence { return; }
    let waited = PICKUP_NS[slot].load(Ordering::Relaxed);
    WRITE_NS[slot].store(now().saturating_sub(HANDOVER_NS[slot].load(Ordering::Relaxed)).saturating_sub(waited), Ordering::Relaxed);
}

/// Report the flush this acknowledgement settles. # C: O(1)
pub(crate) fn acknowledged(sequence: u64) {
    let slot = (sequence as usize) % SLOTS;
    if SEQUENCE[slot].swap(0, Ordering::Relaxed) != sequence { return; }
    if SPENT.fetch_add(1, Ordering::Relaxed) >= TRACE_BUDGET { return; }
    let ack = now().saturating_sub(HANDOVER_NS[slot].load(Ordering::Relaxed));
    klog::write_raw(b"[WINDOWS-FRAME] seq="); klog::write_hex_u64(sequence);
    klog::write_raw(b" bytes="); klog::write_hex_u64(BYTES[slot].load(Ordering::Relaxed));
    klog::write_raw(b" serialise_us="); klog::write_hex_u64(SERIALISE_NS[slot].load(Ordering::Relaxed) / NS_PER_US);
    klog::write_raw(b" enqueue_us="); klog::write_hex_u64(ENQUEUE_NS[slot].load(Ordering::Relaxed) / NS_PER_US);
    klog::write_raw(b" pickup_us="); klog::write_hex_u64(PICKUP_NS[slot].swap(0, Ordering::Relaxed) / NS_PER_US);
    klog::write_raw(b" write_us="); klog::write_hex_u64(WRITE_NS[slot].swap(0, Ordering::Relaxed) / NS_PER_US);
    klog::write_raw(b" ack_us="); klog::write_hex_u64(ack / NS_PER_US);
    klog::write_raw(b"\n");
}
