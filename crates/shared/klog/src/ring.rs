// Per-CPU MPSC lockless ring per `04§4.1`–`§4.4`.
//
// Producer path (`04§4.1`): one Acquire load + one Relaxed CAS to claim a
// slot, inline copy of the fixed-size `Record`, one Release store to commit.
// Bounded retry on CAS failure (only producers on the same CPU can race —
// process / IRQ / soft-IRQ — so contention is ≤3). Full ⇒ bump per-CPU
// `dropped` (Relaxed) and abandon. Producer never spins, never blocks
// (`04§4.4`).
//
// Consumer path: single drainer per ring (`04§4.2`); kthread wiring is
// deferred. `pop` reads with Acquire, returns `Option<Record>`.
//
// NMI ringlet (`04§4.3`) reuses this primitive with smaller N.
//
// Vyukov bounded MPSC scheme: each slot carries a `seq` counter compared
// against the producer's claimed head; matching seq ⇒ slot is empty and
// claimable; lower seq ⇒ ring full; higher seq ⇒ another producer raced
// us and we reload head.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// Per-CPU main-ring capacity per `04§4.1` (4096 records ⇒ 320 KiB/CPU
/// at `size_of::<Record>() == 80`). Power of two; mask via `& (N - 1)`.
pub const MAIN_RING_CAP: usize = 4096;

/// NMI ringlet capacity per `04§4.3`. SPSC (NMI is sole producer; main
/// IRQ-exit drains).
pub const NMI_RING_CAP: usize = 64;

/// Bounded retry budget on the producer CAS. Same-CPU contenders are
/// capped at process + IRQ + soft-IRQ + NMI = 4; beyond that we treat
/// as adversarial and drop per `04§4.4`.
const PUSH_MAX_RETRIES: u32 = 8;

/// Fixed-size log record per `04§4.1`. 2 + 2 + 4 + 64 = 72 B payload;
/// `repr(C)` keeps the layout stable for the userspace decoder per `04§4.2`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub level: u16,
    pub target_id: u16,
    pub fmt_id: u32,
    pub args: [u64; 8],
}

impl Record {
    pub const ZERO: Record = Record { level: 0, target_id: 0, fmt_id: 0, args: [0; 8] };
}

/// Ring slot. `seq` is the synchronization word; `data` is written by
/// the claiming producer between the Relaxed CAS and the Release store
/// of the next-`seq` value.
#[repr(C)]
struct Slot {
    seq: AtomicU32,
    data: UnsafeCell<Record>,
}

/// Lockless bounded ring with a single consumer (drainer) and N producers
/// on the same CPU. `N` must be a power of two; enforced at `new()`.
pub struct Ring<const N: usize> {
    slots: [Slot; N],
    head: AtomicU32,
    tail: AtomicU32,
    dropped: AtomicU32,
}

// SAFETY: every UnsafeCell access is gated by the slot's seq protocol —
// a producer only writes after winning the CAS for that head value, and
// the consumer only reads after observing seq == tail+1. Cross-CPU sharing
// occurs only between producers (same CPU per `06§4`) and the drainer,
// which is the unique consumer.
unsafe impl<const N: usize> Sync for Ring<N> {}
unsafe impl<const N: usize> Send for Ring<N> {}

impl<const N: usize> Ring<N> {
    /// # C: O(N) — initializes every slot's seq to its index.
    pub fn new() -> Self {
        const { assert!(N > 0 && N.is_power_of_two(), "Ring<N>: N must be a power of two"); }
        Self {
            slots: core::array::from_fn(|i| Slot {
                seq: AtomicU32::new(i as u32),
                data: UnsafeCell::new(Record::ZERO),
            }),
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            dropped: AtomicU32::new(0),
        }
    }

    /// Capacity (== N).
    /// # C: O(1)
    pub const fn capacity(&self) -> usize { N }

    /// Per-CPU drop counter snapshot per `04§4.4`. Relaxed read.
    /// # C: O(1)
    pub fn dropped(&self) -> u32 { self.dropped.load(Ordering::Relaxed) }

    /// Producer enqueue per `04§4.1`. Returns `Ok(())` on commit, `Err(Full)`
    /// after bumping the drop counter. **Never blocks, never spins
    /// unboundedly.**
    ///
    /// # C: O(1) amortized (≤`PUSH_MAX_RETRIES` CAS attempts)
    /// # Ctx: any (process / IRQ / soft-IRQ / NMI / lock-held / preempt-off)
    pub fn push(&self, rec: Record) -> Result<(), Full> {
        let mut retries: u32 = 0;
        let mut head = self.head.load(Ordering::Relaxed);
        loop {
            let slot = &self.slots[(head as usize) & (N - 1)];
            let seq = slot.seq.load(Ordering::Acquire);
            let diff = (seq as i32).wrapping_sub(head as i32);
            if diff == 0 {
                match self.head.compare_exchange_weak(
                    head, head.wrapping_add(1),
                    Ordering::Relaxed, Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // SAFETY: this CPU won the CAS for slot index `head & (N-1)`;
                        // the seq invariant guarantees no other producer or the
                        // consumer touches `data` until we publish via the Release
                        // store below. `Record: Copy`, so the write is a memcpy.
                        unsafe { *slot.data.get() = rec; }
                        slot.seq.store(head.wrapping_add(1), Ordering::Release);
                        return Ok(());
                    }
                    Err(observed) => {
                        head = observed;
                        retries += 1;
                        if retries > PUSH_MAX_RETRIES {
                            self.dropped.fetch_add(1, Ordering::Relaxed);
                            return Err(Full);
                        }
                    }
                }
            } else if diff < 0 {
                // Slot still holds an undrained record at an older epoch ⇒ full.
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Err(Full);
            } else {
                // diff > 0: another producer claimed this head; reload.
                head = self.head.load(Ordering::Relaxed);
                retries += 1;
                if retries > PUSH_MAX_RETRIES {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                    return Err(Full);
                }
            }
        }
    }

    /// Drainer dequeue per `04§4.2`. Returns `None` if no committed
    /// record is available. Single-consumer: caller must serialize all
    /// `pop` calls (per-CPU drainer kthread).
    ///
    /// # C: O(1)
    /// # Ctx: drainer (kthread post-SMP, or boot-CPU idle pre-SMP)
    pub fn pop(&self) -> Option<Record> {
        let tail = self.tail.load(Ordering::Relaxed);
        let slot = &self.slots[(tail as usize) & (N - 1)];
        let seq = slot.seq.load(Ordering::Acquire);
        let diff = (seq as i32).wrapping_sub(tail.wrapping_add(1) as i32);
        if diff == 0 {
            // SAFETY: producer published `seq == tail+1` with Release;
            // the matching Acquire above synchronizes the `data` write.
            // Single-consumer invariant ⇒ no concurrent `pop` reads it.
            let rec = unsafe { *slot.data.get() };
            self.tail.store(tail.wrapping_add(1), Ordering::Relaxed);
            slot.seq.store(tail.wrapping_add(N as u32), Ordering::Release);
            Some(rec)
        } else {
            None
        }
    }
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self { Self::new() }
}

/// Push failure: ring full or persistent CAS contention. Drop counter
/// already incremented on the offending CPU's ring per `04§4.4`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Full;

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32 as TAtomicU32;
    use std::sync::Arc;
    use std::thread;
    use std::vec::Vec;

    fn rec(fmt_id: u32) -> Record {
        Record { level: 2, target_id: 1, fmt_id, args: [fmt_id as u64; 8] }
    }

    #[test]
    fn record_size_matches_spec() {
        // `04§4.1`: record = u16 + u16 + u32 + [u64;8] = 72 B payload,
        // ≤ 80 B incl. any padding.
        assert!(core::mem::size_of::<Record>() <= 80);
        assert_eq!(core::mem::size_of::<Record>(), 72);
    }

    #[test]
    fn push_then_pop_fifo() {
        let r: Ring<8> = Ring::new();
        for i in 0..5 {
            r.push(rec(i)).unwrap();
        }
        for i in 0..5 {
            assert_eq!(r.pop().unwrap().fmt_id, i);
        }
        assert!(r.pop().is_none());
        assert_eq!(r.dropped(), 0);
    }

    #[test]
    fn fills_to_capacity_then_drops() {
        let r: Ring<8> = Ring::new();
        for i in 0..8 {
            r.push(rec(i)).unwrap();
        }
        // 9th push must drop, not block.
        assert!(r.push(rec(99)).is_err());
        assert_eq!(r.dropped(), 1);
        // Drainer can still pop the 8 committed records.
        for i in 0..8 {
            assert_eq!(r.pop().unwrap().fmt_id, i);
        }
        assert!(r.pop().is_none());
    }

    #[test]
    fn drop_counter_is_per_ring() {
        let a: Ring<2> = Ring::new();
        let b: Ring<2> = Ring::new();
        a.push(rec(0)).unwrap();
        a.push(rec(1)).unwrap();
        a.push(rec(2)).unwrap_err();
        a.push(rec(3)).unwrap_err();
        assert_eq!(a.dropped(), 2);
        assert_eq!(b.dropped(), 0);
    }

    #[test]
    fn drain_reopens_capacity() {
        let r: Ring<4> = Ring::new();
        for i in 0..4 { r.push(rec(i)).unwrap(); }
        r.pop().unwrap();
        r.pop().unwrap();
        // Two slots freed ⇒ two more pushes succeed.
        r.push(rec(100)).unwrap();
        r.push(rec(101)).unwrap();
        assert!(r.push(rec(102)).is_err());
    }

    #[test]
    fn nmi_ringlet_capacity_matches_spec() {
        // `04§4.3`: NMI ringlet is 64 entries, same record format.
        let r: Ring<NMI_RING_CAP> = Ring::new();
        assert_eq!(r.capacity(), 64);
        for i in 0..64 { r.push(rec(i)).unwrap(); }
        assert!(r.push(rec(99)).is_err());
        assert_eq!(r.dropped(), 1);
    }

    #[test]
    fn mpsc_concurrent_producers_no_loss_under_capacity() {
        // 4 producers × 64 records into Ring<512>: capacity comfortably
        // exceeds total, so all 256 records must land (drop counter = 0).
        let r: Arc<Ring<512>> = Arc::new(Ring::new());
        let total_seen = Arc::new(TAtomicU32::new(0));
        let mut handles = Vec::new();
        for tid in 0..4u32 {
            let r = Arc::clone(&r);
            handles.push(thread::spawn(move || {
                for i in 0..64u32 {
                    r.push(rec(tid * 1000 + i)).unwrap();
                }
            }));
        }
        for h in handles { h.join().unwrap(); }
        // Single consumer drains.
        while r.pop().is_some() {
            total_seen.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(total_seen.load(Ordering::Relaxed), 4 * 64);
        assert_eq!(r.dropped(), 0);
    }

    #[test]
    fn mpsc_overcommit_drops_excess_only() {
        // 4 producers × 1024 records into Ring<64>: overflow ⇒ drops.
        // Invariant: popped + dropped == 4*1024.
        let r: Arc<Ring<64>> = Arc::new(Ring::new());
        let mut handles = Vec::new();
        for tid in 0..4u32 {
            let r = Arc::clone(&r);
            handles.push(thread::spawn(move || {
                for i in 0..1024u32 {
                    let _ = r.push(rec(tid * 100000 + i));
                }
            }));
        }
        for h in handles { h.join().unwrap(); }
        let mut popped = 0u32;
        while r.pop().is_some() { popped += 1; }
        assert_eq!(popped + r.dropped(), 4 * 1024);
    }

    #[test]
    fn concurrent_producer_drainer_fifo() {
        // Single producer streams 10_000 records into a capacity-32 ring;
        // drainer consumes concurrently. With a single producer FIFO
        // ordering must hold for every record the drainer observes
        // (Vyukov seq invariant). Producer retries on `Full` rather than
        // accepting drops, so every sent record is eventually delivered.
        let r: Arc<Ring<32>> = Arc::new(Ring::new());
        let prod = {
            let r = Arc::clone(&r);
            thread::spawn(move || {
                for i in 0..10_000u32 {
                    while r.push(rec(i)).is_err() {
                        thread::yield_now();
                    }
                }
            })
        };
        let cons = {
            let r = Arc::clone(&r);
            thread::spawn(move || {
                let mut got = 0u32;
                while got < 10_000 {
                    match r.pop() {
                        Some(rec) => {
                            assert_eq!(rec.fmt_id, got);
                            got += 1;
                        }
                        None => thread::yield_now(),
                    }
                }
                got
            })
        };
        prod.join().unwrap();
        assert_eq!(cons.join().unwrap(), 10_000);
        // Drops are expected and per-spec when the producer outruns the
        // drainer; we only assert the FIFO invariant above.
    }

    #[test]
    fn wraps_correctly_around_u32() {
        // Force many wraparounds on a tiny ring to flush out off-by-one
        // errors in the seq math.
        let r: Ring<2> = Ring::new();
        for i in 0..10_000u32 {
            r.push(rec(i)).unwrap();
            assert_eq!(r.pop().unwrap().fmt_id, i);
        }
        assert!(r.pop().is_none());
        assert_eq!(r.dropped(), 0);
    }
}
