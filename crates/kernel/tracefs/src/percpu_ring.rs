// Per-CPU lockless trace ring buffer — the substrate static tracepoints
// (sched_switch / sys_enter) need: recording must be wait-free and
// allocation-free because it runs in hot paths (scheduler context switch,
// syscall entry) under rq locks with IRQs off, where taking a Spinlock or
// allocating would deadlock or wreck latency.
//
// Model: one SPSC ring per CPU. The ONLY producer of CPU N's ring is CPU N
// itself (IRQs off during a record → no same-CPU re-entrancy), so the
// producer is single + wait-free: bounds-check against the consumer's tail,
// write the fixed-size slot, publish head with a Release store. Drop-on-full
// (count drops) — never overwrite unconsumed slots, so the consumer never
// races a producer over the same slot. Records are fixed-size binary (no
// formatting in the hot path); the reader renders to ftrace text.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// Max CPUs (matches the scheduler's per-CPU arrays).
pub const NCPU: usize = cpu::MAX_CPUS;
/// Slots per CPU (power of two → mask indexing). 128 × 96 B = 12 KiB/CPU
/// (≈768 KiB total at MAX_CPUS=64, zero-init BSS).
const SLOTS: usize = 128;
const SLOT_MASK: u32 = (SLOTS - 1) as u32;
/// Payload bytes per record (trace_marker text / sched_switch fields).
pub const PAYLOAD: usize = 80;

/// Record kinds.
pub const KIND_MARK: u8 = 1;
pub const KIND_SCHED_SWITCH: u8 = 2;
pub const KIND_SYS_ENTER: u8 = 3;
pub const KIND_SYS_EXIT: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Record {
    pub ts_ns: u64,
    pub pid:   u32,
    pub kind:  u8,
    pub plen:  u8,
    pub cpu:   u8,    // originating CPU (for the ftrace "[00N]" column)
    _pad:      u8,
    pub payload: [u8; PAYLOAD],
}
impl Record {
    const EMPTY: Record = Record { ts_ns: 0, pid: 0, kind: 0, plen: 0, cpu: 0, _pad: 0, payload: [0; PAYLOAD] };
    /// The valid payload bytes. # C: O(1)
    pub fn data(&self) -> &[u8] { &self.payload[..self.plen as usize] }
}

struct CpuRing {
    head:    AtomicU32, // next write index (producer-owned)
    tail:    AtomicU32, // next read index (consumer-owned)
    dropped: AtomicU32, // records dropped because the ring was full
    slots:   UnsafeCell<[Record; SLOTS]>,
}
// SAFETY: each ring is written only by its owning CPU (IRQs-off, single
// producer) and read under the consumer lock; slot access uses element raw
// pointers (never overlapping references); head/tail Release/Acquire order
// the slot writes against the reader.
unsafe impl Sync for CpuRing {}

static RINGS: [CpuRing; NCPU] = [const {
    CpuRing {
        head: AtomicU32::new(0), tail: AtomicU32::new(0), dropped: AtomicU32::new(0),
        slots: UnsafeCell::new([Record::EMPTY; SLOTS]),
    }
}; NCPU];

/// Element pointer to slot `idx` of CPU `c`'s ring (no whole-array ref, so a
/// producer writing slot A never aliases a reader reading slot B). # C: O(1)
#[inline]
fn slot_ptr(c: usize, idx: u32) -> *mut Record {
    // SAFETY: masked index is in-bounds of CPU c's preallocated SLOTS array;
    // we form a raw element pointer only (no reference), so it never aliases.
    unsafe { (RINGS[c].slots.get() as *mut Record).add((idx & SLOT_MASK) as usize) }
}

/// Append a record to CPU `c`'s ring. Wait-free; drops (and counts) when the
/// ring is full. `c` MUST be the calling CPU's id (single-producer invariant).
/// # C: O(1)
pub fn record(c: usize, ts_ns: u64, pid: u32, kind: u8, payload: &[u8]) {
    if c >= NCPU { return; }
    let r = &RINGS[c];
    let h = r.head.load(Ordering::Relaxed);
    let t = r.tail.load(Ordering::Acquire);
    if h.wrapping_sub(t) >= SLOTS as u32 {
        r.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let n = payload.len().min(PAYLOAD);
    // SAFETY: single producer for this CPU; we exclusively own slot `h` until
    // the Release publish below; the consumer only reads slots < head.
    unsafe {
        let p = slot_ptr(c, h);
        core::ptr::addr_of_mut!((*p).ts_ns).write(ts_ns);
        core::ptr::addr_of_mut!((*p).pid).write(pid);
        core::ptr::addr_of_mut!((*p).kind).write(kind);
        core::ptr::addr_of_mut!((*p).plen).write(n as u8);
        core::ptr::addr_of_mut!((*p).cpu).write(c as u8);
        let pl = core::ptr::addr_of_mut!((*p).payload) as *mut u8;
        core::ptr::copy_nonoverlapping(payload.as_ptr(), pl, n);
    }
    r.head.store(h.wrapping_add(1), Ordering::Release);
}

/// Total records dropped (ring-full) across all CPUs. # C: O(NCPU)
pub fn dropped_total() -> u32 {
    let mut s = 0u32;
    for r in RINGS.iter() { s = s.wrapping_add(r.dropped.load(Ordering::Relaxed)); }
    s
}

/// Collect every unconsumed record across all CPUs, timestamp-ordered. When
/// `consume`, advances each ring's tail to head (trace_pipe drain); else
/// leaves them (the `trace` snapshot). The consumer is serialized by the
/// caller (a non-hot-path lock). # C: O(total records · log)
pub fn collect(consume: bool) -> alloc::vec::Vec<Record> {
    let mut out: alloc::vec::Vec<Record> = alloc::vec::Vec::new();
    for c in 0..NCPU {
        let r = &RINGS[c];
        let t = r.tail.load(Ordering::Relaxed);
        let h = r.head.load(Ordering::Acquire);
        let mut i = t;
        while i != h {
            // SAFETY: slots in [tail, head) are stable — the producer drops
            // rather than overwrite them, so reading them out is race-free.
            out.push(unsafe { core::ptr::read(slot_ptr(c, i) as *const Record) });
            i = i.wrapping_add(1);
        }
        if consume { r.tail.store(h, Ordering::Release); }
    }
    // Stable sort by timestamp interleaves the per-CPU streams like ftrace.
    out.sort_by_key(|r| r.ts_ns);
    out
}

/// Drop every unconsumed record (echo > trace). # C: O(NCPU)
pub fn clear() {
    for r in RINGS.iter() {
        let h = r.head.load(Ordering::Acquire);
        r.tail.store(h, Ordering::Release);
    }
}

/// True if any CPU has unconsumed records (poll readiness). # C: O(NCPU)
pub fn any_pending() -> bool {
    RINGS.iter().any(|r| r.head.load(Ordering::Acquire) != r.tail.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests share the global RINGS static and run in parallel, so each test
    // operates on its OWN cpu index + drains only that ring (no cross-test
    // interference). `collect`/`clear` touch all CPUs, so the helpers below
    // restrict to one cpu.
    fn drain_cpu(c: usize) -> alloc::vec::Vec<Record> {
        let r = &RINGS[c];
        let t = r.tail.load(Ordering::Relaxed);
        let h = r.head.load(Ordering::Acquire);
        let mut v = alloc::vec::Vec::new();
        let mut i = t;
        // SAFETY: slots in [tail, head) are stable in this single-threaded test;
        // ptr::read copies the Copy Record out via an element pointer.
        while i != h { v.push(unsafe { core::ptr::read(slot_ptr(c, i) as *const Record) }); i = i.wrapping_add(1); }
        r.tail.store(h, Ordering::Release);
        v.sort_by_key(|x| x.ts_ns);
        v
    }
    fn snap_cpu(c: usize) -> usize {
        let r = &RINGS[c];
        r.head.load(Ordering::Acquire).wrapping_sub(r.tail.load(Ordering::Relaxed)) as usize
    }

    #[test]
    fn record_then_collect_roundtrips_in_ts_order() {
        let c = 1;
        record(c, 30, 7, KIND_MARK, b"c");
        record(c, 10, 7, KIND_MARK, b"a");
        record(c, 20, 7, KIND_MARK, b"b");
        let v = drain_cpu(c);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].ts_ns, 10); assert_eq!(v[0].data(), b"a");
        assert_eq!(v[1].ts_ns, 20); assert_eq!(v[1].data(), b"b");
        assert_eq!(v[2].ts_ns, 30); assert_eq!(v[2].data(), b"c");
        assert_eq!(drain_cpu(c).len(), 0);
    }

    #[test]
    fn snapshot_does_not_consume() {
        let c = 2;
        record(c, 1, 1, KIND_MARK, b"x");
        assert_eq!(snap_cpu(c), 1); // still pending
        assert_eq!(snap_cpu(c), 1);
        assert_eq!(drain_cpu(c).len(), 1); // now drained
        assert_eq!(drain_cpu(c).len(), 0);
    }

    #[test]
    fn full_ring_drops_excess_and_counts() {
        let c = 3;
        let d0 = RINGS[c].dropped.load(Ordering::Relaxed);
        for i in 0..(SLOTS + 5) { record(c, i as u64, 1, KIND_MARK, b"."); }
        assert_eq!(RINGS[c].dropped.load(Ordering::Relaxed).wrapping_sub(d0), 5);
        let v = drain_cpu(c);
        assert_eq!(v.len(), SLOTS);
        // drop-on-full keeps the FIRST SLOTS; the 5 newest were dropped.
        assert_eq!(v[0].ts_ns, 0);
        assert_eq!(v[SLOTS - 1].ts_ns, (SLOTS - 1) as u64);
    }

    #[test]
    fn wrap_reuses_slots_after_consume() {
        let c = 4;
        for i in 0..SLOTS { record(c, i as u64, 1, KIND_MARK, b"."); }
        assert_eq!(drain_cpu(c).len(), SLOTS);
        for i in 0..SLOTS { record(c, (1000 + i) as u64, 1, KIND_MARK, b"."); }
        let v = drain_cpu(c);
        assert_eq!(v.len(), SLOTS);
        assert_eq!(v[0].ts_ns, 1000);
    }

    #[test]
    fn payload_truncates_to_capacity() {
        let c = 5;
        let big = [0x41u8; PAYLOAD + 40];
        record(c, 1, 1, KIND_MARK, &big);
        let v = drain_cpu(c);
        assert_eq!(v[0].plen as usize, PAYLOAD);
        assert_eq!(v[0].data().len(), PAYLOAD);
    }
}
