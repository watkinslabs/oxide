// Parked context-switch identities — the two sides of one switch, plus the
// instant it happened, held until the bottom half can act on them.
//
// The switch site is the only place that knows both sides, and it runs with
// the runqueue lock held, where none of perf's own locks may be taken. So the
// pair is parked here and drained after the lock is gone.
//
// A RING, not a single slot. A note now decides accounting state and not only
// whether a side-band record is emitted: the outgoing thread's counting window
// closes on it and the incoming thread's opens. A note dropped because a newer
// one overwrote it therefore leaves the outgoing thread's window OPEN across an
// interval it was not running, which a wall-clock-sourced counter charges to it
// in full. Two switches between drains is ordinary — a task that blocks again
// before the bottom half runs produces exactly that — so the queue has to hold
// them.
//
// Lock-free by construction: the park side runs with a raw spinlock held and
// must not take another.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use cpu::MAX_CPUS;

/// The identities of one context switch's two sides and the instant it
/// happened.
///
/// `ts` is read inside the locked region, at the switch itself, and is what
/// both the closing and the opening window are stamped with. Taking the time
/// at drain instead would charge the outgoing thread for the bottom half's
/// delay and credit the incoming one with an interval it had not yet run —
/// equal and opposite errors that do not cancel, because the two threads are
/// generally not the same event's target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SwitchNote {
    pub prev_pid: u32,
    pub prev_tid: u32,
    pub next_pid: u32,
    pub next_tid: u32,
    /// The outgoing task was still runnable — a preemption rather than a block.
    pub preempt:  bool,
    /// Monotonic ns at the switch.
    pub ts:       u64,
}

/// Notes held per CPU between drains. Deep enough that reaching the cap means
/// a CPU took this many switches without once running its bottom half.
pub const NOTES_MAX: usize = 32;

struct Slot {
    prev:  AtomicU64,
    next:  AtomicU64,
    ts:    AtomicU64,
    flags: AtomicU32,
}

struct Ring {
    slots: [Slot; NOTES_MAX],
    /// Next index to write; advanced only by this CPU's own switch site.
    head:  AtomicU32,
    /// Next index to read; advanced only by this CPU's own drain.
    tail:  AtomicU32,
}

static NOTES: [Ring; MAX_CPUS] = [const {
    Ring {
        slots: [const {
            Slot { prev: AtomicU64::new(0), next: AtomicU64::new(0),
                   ts: AtomicU64::new(0), flags: AtomicU32::new(0) }
        }; NOTES_MAX],
        head: AtomicU32::new(0),
        tail: AtomicU32::new(0),
    }
}; MAX_CPUS];

const PREEMPT: u32 = 1;
const RING: u32 = NOTES_MAX as u32;

fn pack(pid: u32, tid: u32) -> u64 { (pid as u64) << 32 | tid as u64 }
fn unpack(v: u64) -> (u32, u32) { ((v >> 32) as u32, v as u32) }

/// Park one switch on `cpu`.
///
/// A full ring drops the NEWEST note rather than overwriting an undrained one:
/// the parked notes are a chain, each one's incoming thread being the next
/// one's outgoing thread, and overwriting a slot in the middle would leave a
/// window open that no later note closes. Dropping from the end loses the tail
/// of the chain, which the next switch to be parked repairs.
/// # C: O(1)
pub fn park(cpu: usize, n: SwitchNote) {
    if cpu >= MAX_CPUS { return; }
    let r = &NOTES[cpu];
    let head = r.head.load(Ordering::Relaxed);
    let next = (head + 1) % RING;
    if next == r.tail.load(Ordering::Acquire) { return; }
    let s = &r.slots[head as usize];
    s.prev.store(pack(n.prev_pid, n.prev_tid), Ordering::Relaxed);
    s.next.store(pack(n.next_pid, n.next_tid), Ordering::Relaxed);
    s.ts.store(n.ts, Ordering::Relaxed);
    s.flags.store(if n.preempt { PREEMPT } else { 0 }, Ordering::Relaxed);
    r.head.store(next, Ordering::Release);
}

/// Take `cpu`'s oldest parked switch, if any. # C: O(1)
pub fn take(cpu: usize) -> Option<SwitchNote> {
    if cpu >= MAX_CPUS { return None; }
    let r = &NOTES[cpu];
    let tail = r.tail.load(Ordering::Relaxed);
    if tail == r.head.load(Ordering::Acquire) { return None; }
    let s = &r.slots[tail as usize];
    let (prev_pid, prev_tid) = unpack(s.prev.load(Ordering::Relaxed));
    let (next_pid, next_tid) = unpack(s.next.load(Ordering::Relaxed));
    let ts = s.ts.load(Ordering::Relaxed);
    let preempt = s.flags.load(Ordering::Relaxed) & PREEMPT != 0;
    r.tail.store((tail + 1) % RING, Ordering::Release);
    Some(SwitchNote { prev_pid, prev_tid, next_pid, next_tid, preempt, ts })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn drain(cpu: usize) -> Vec<SwitchNote> {
        let mut out = Vec::new();
        while let Some(n) = take(cpu) { out.push(n); }
        out
    }

    fn note(prev_tid: u32, next_tid: u32, ts: u64) -> SwitchNote {
        SwitchNote { prev_pid: 1, prev_tid, next_pid: 2, next_tid, preempt: false, ts }
    }

    /// The round trip keeps both identities, the preempt bit and the switch's
    /// own timestamp — the last of which is what both scheduling windows are
    /// stamped with, so losing it would put the accounting back on the drain's
    /// clock.
    #[test]
    fn a_parked_note_survives_the_round_trip_intact() {
        let cpu = 0;
        let _ = drain(cpu);
        let n = SwitchNote { prev_pid: 10, prev_tid: 11, next_pid: 20, next_tid: 21,
                             preempt: true, ts: 123_456_789 };
        park(cpu, n);
        assert_eq!(take(cpu), Some(n));
        assert_eq!(take(cpu), None, "the drain consumed it");
    }

    /// THE reason this is a ring. Two switches between drains — a task that
    /// blocks, is replaced, and the replacement blocks too — must both be
    /// delivered, oldest first. A single slot delivered only the second, and
    /// the first switch's outgoing thread was left counting.
    #[test]
    fn several_switches_between_drains_are_all_delivered_in_order() {
        let cpu = 1;
        let _ = drain(cpu);
        park(cpu, note(1, 2, 100));
        park(cpu, note(2, 3, 200));
        park(cpu, note(3, 4, 300));
        let got = drain(cpu);
        assert_eq!(got.len(), 3);
        assert_eq!(got.iter().map(|n| (n.prev_tid, n.next_tid, n.ts)).collect::<Vec<_>>(),
                   alloc::vec![(1, 2, 100), (2, 3, 200), (3, 4, 300)]);
    }

    /// The chain the notes form is what makes them droppable only from the
    /// END: every undrained note is left intact and the overflow is refused.
    #[test]
    fn a_full_ring_refuses_the_newest_and_keeps_every_undrained_note() {
        let cpu = 2;
        let _ = drain(cpu);
        for i in 0..(NOTES_MAX as u32 + 10) { park(cpu, note(i, i + 1, i as u64)); }
        let got = drain(cpu);
        assert_eq!(got.len(), NOTES_MAX - 1, "the ring holds NOTES_MAX-1 undrained notes");
        // Oldest first, and unbroken: each note's incoming thread is the next
        // note's outgoing thread.
        for (i, n) in got.iter().enumerate() {
            assert_eq!(n.prev_tid, i as u32, "the OLDEST notes are the ones kept");
        }
    }

    #[test]
    fn notes_are_per_cpu_and_an_out_of_range_cpu_parks_nothing() {
        let _ = drain(3); let _ = drain(4);
        park(3, note(1, 2, 7));
        assert_eq!(take(4), None);
        assert_eq!(take(3).map(|n| n.prev_tid), Some(1));
        park(MAX_CPUS, note(1, 2, 7));
        assert_eq!(take(MAX_CPUS), None);
    }
}
