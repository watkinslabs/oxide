// Deferred sampling opportunities — the oxide stand-in for the `irq_work` the
// reference queues out of contexts its sampler cannot run in.
//
// A counter site inside the runqueue-locked region cannot call the sampler
// (the perf registry and the ring both rank below the runqueue lock), so it
// parks the opportunity here and the scheduler's post-unlock tail runs it. The
// parked value is a COUNT of opportunities, never a copy of the accumulator:
// `charge` already advanced the one counter, so nothing here can disagree with
// it.
//
// A parked opportunity also carries the identity of the task it was CHARGED
// to. The reference never needs this — `__perf_sw_event_sched` samples inline,
// so `current` is by construction the charged task — but a deferred drain runs
// after the switch, when `current` is somebody else. Without the identity the
// record names whichever task happened to be running at drain time, which is a
// profile that misattributes exactly the switches it is meant to explain.
//
// Lock-free by construction — the queue side runs with a raw spinlock held and
// must not take another.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use cpu::MAX_CPUS;

use super::{CpuSw, NR_KINDS};

/// Ring depth per CPU. The drain runs from the softirq raised by the same
/// charge, so the steady-state depth is 1-2; the cap only bounds the
/// pathological case where a CPU charges without ever reaching a drain, and its
/// effect is to drop sampling opportunities (the counters are unaffected)
/// rather than to let the queue grow without bound.
pub const PENDING_MAX: u32 = 64;

/// One parked opportunity: which software event, how many units, and the task
/// the units were charged to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Charge {
    pub kind: CpuSw,
    pub nr:   u64,
    /// The charged task's thread id and thread-group id. `0` where the site
    /// had no task (a charge from an idle/bootstrap context).
    pub tid:  u32,
    pub pid:  u32,
}

/// A ring slot. `meta` is `kind << 32 | nr`, `who` is `pid << 32 | tid`; both
/// are written before `seq` publishes the slot, and `seq` is what the drain
/// reads first.
struct Slot { meta: AtomicU64, who: AtomicU64 }

const RING: usize = PENDING_MAX as usize;

struct Ring {
    slots: [Slot; RING],
    /// Next index to write; only ever advanced by this CPU's own charge sites.
    head: AtomicU32,
    /// Next index to read; only ever advanced by this CPU's own drain.
    tail: AtomicU32,
}

static PENDING: [Ring; MAX_CPUS] = [const {
    Ring {
        slots: [const { Slot { meta: AtomicU64::new(0), who: AtomicU64::new(0) } }; RING],
        head: AtomicU32::new(0),
        tail: AtomicU32::new(0),
    }
}; MAX_CPUS];

fn pack2(hi: u32, lo: u32) -> u64 { (hi as u64) << 32 | lo as u64 }
fn unpack2(v: u64) -> (u32, u32) { ((v >> 32) as u32, v as u32) }

/// Park `n` opportunities for `kind` on `cpu`, charged to `(pid, tid)`.
///
/// A charge that lands on the newest undrained slot with the SAME kind and
/// task merges into it — the steady-state coalescing the per-kind counter used
/// to give, without merging across tasks, which is the misattribution this ring
/// exists to prevent. # C: O(1)
pub fn queue(kind: CpuSw, cpu: usize, n: u64, pid: u32, tid: u32) {
    if cpu >= MAX_CPUS || n == 0 { return; }
    let r = &PENDING[cpu];
    let head = r.head.load(Ordering::Relaxed);
    let tail = r.tail.load(Ordering::Acquire);
    let who = pack2(pid, tid);

    // Merge into the newest undrained slot when it names the same event AND
    // the same task.
    if head != tail {
        let last = &r.slots[((head + RING as u32 - 1) % RING as u32) as usize];
        let (k, nr) = unpack2(last.meta.load(Ordering::Relaxed));
        if k == kind as u32 && last.who.load(Ordering::Relaxed) == who {
            last.meta.store(pack2(k, nr.saturating_add(n.min(u32::MAX as u64) as u32)),
                            Ordering::Relaxed);
            return;
        }
    }

    // Full: drop the opportunity rather than overwrite an undrained one.
    let next = (head + 1) % RING as u32;
    if next == tail { return; }
    let s = &r.slots[head as usize];
    s.who.store(who, Ordering::Relaxed);
    s.meta.store(pack2(kind as u32, n.min(u32::MAX as u64) as u32), Ordering::Relaxed);
    r.head.store(next, Ordering::Release);
}

/// Take every parked opportunity on `cpu`, oldest first, and hand each to `f`.
/// The tail advances per slot, so a concurrent `queue` on the same CPU parks
/// against the ring rather than being lost. # C: O(parked)
pub fn drain(cpu: usize, mut f: impl FnMut(Charge)) {
    if cpu >= MAX_CPUS { return; }
    let r = &PENDING[cpu];
    loop {
        let tail = r.tail.load(Ordering::Relaxed);
        if tail == r.head.load(Ordering::Acquire) { return; }
        let s = &r.slots[tail as usize];
        let (k, nr) = unpack2(s.meta.load(Ordering::Relaxed));
        let (pid, tid) = unpack2(s.who.load(Ordering::Relaxed));
        r.tail.store((tail + 1) % RING as u32, Ordering::Release);
        if let Some(kind) = kind_of(k) { f(Charge { kind, nr: nr as u64, tid, pid }); }
    }
}

/// `CpuSw` from its discriminant. # C: O(1)
fn kind_of(v: u32) -> Option<CpuSw> { KINDS.get(v as usize).copied() }

/// Parked opportunities for `cpu` without consuming them, for the tests that
/// pin the ring's depth and merge behaviour. # C: O(parked)
#[cfg(test)]
pub fn peek(cpu: usize) -> alloc::vec::Vec<Charge> {
    let mut out = alloc::vec::Vec::new();
    if cpu >= MAX_CPUS { return out; }
    let r = &PENDING[cpu];
    let (mut i, head) = (r.tail.load(Ordering::Acquire), r.head.load(Ordering::Acquire));
    while i != head {
        let s = &r.slots[i as usize];
        let (k, nr) = unpack2(s.meta.load(Ordering::Relaxed));
        let (pid, tid) = unpack2(s.who.load(Ordering::Relaxed));
        if let Some(kind) = kind_of(k) { out.push(Charge { kind, nr: nr as u64, tid, pid }); }
        i = (i + 1) % RING as u32;
    }
    out
}

/// The identities of one context switch's two sides, parked by the switch site
/// (which is the only place that knows both) for the tail to emit.
/// `PERF_RECORD_SWITCH` needs them; the counter does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SwitchNote {
    pub prev_pid: u32,
    pub prev_tid: u32,
    pub next_pid: u32,
    pub next_tid: u32,
    /// The outgoing task was still runnable — `PERF_RECORD_MISC_SWITCH_OUT_PREEMPT`.
    pub preempt:  bool,
}

/// One parked switch per CPU. Written only by that CPU's own switch, read only
/// by that CPU's own tail, so a plain per-field atomic needs no lock; a switch
/// that overtakes an undrained one replaces it, exactly as a coalescing
/// `irq_work` would.
struct NoteSlot {
    prev: AtomicU64,
    next: AtomicU64,
    /// `1` = a note is parked, `2` = parked and the outgoing task was preempted.
    flags: AtomicU32,
}

static NOTES: [NoteSlot; MAX_CPUS] = [const {
    NoteSlot { prev: AtomicU64::new(0), next: AtomicU64::new(0), flags: AtomicU32::new(0) }
}; MAX_CPUS];

const NOTE_PRESENT: u32 = 1;
const NOTE_PREEMPT: u32 = 2;

fn pack(pid: u32, tid: u32) -> u64 { (pid as u64) << 32 | tid as u64 }
fn unpack(v: u64) -> (u32, u32) { ((v >> 32) as u32, v as u32) }

/// Park this switch's identities on `cpu`. # C: O(1)
pub fn note_switch(cpu: usize, n: SwitchNote) {
    if cpu >= MAX_CPUS { return; }
    let s = &NOTES[cpu];
    s.prev.store(pack(n.prev_pid, n.prev_tid), Ordering::Relaxed);
    s.next.store(pack(n.next_pid, n.next_tid), Ordering::Relaxed);
    s.flags.store(NOTE_PRESENT | if n.preempt { NOTE_PREEMPT } else { 0 },
                  Ordering::Release);
}

/// Take `cpu`'s parked switch, if any. # C: O(1)
pub fn take_switch(cpu: usize) -> Option<SwitchNote> {
    if cpu >= MAX_CPUS { return None; }
    let s = &NOTES[cpu];
    let f = s.flags.swap(0, Ordering::AcqRel);
    if f & NOTE_PRESENT == 0 { return None; }
    let (prev_pid, prev_tid) = unpack(s.prev.load(Ordering::Relaxed));
    let (next_pid, next_tid) = unpack(s.next.load(Ordering::Relaxed));
    Some(SwitchNote { prev_pid, prev_tid, next_pid, next_tid,
                      preempt: f & NOTE_PREEMPT != 0 })
}

/// `CpuSw` by discriminant, so `drain`'s index walk names the kind it fires.
const KINDS: [CpuSw; NR_KINDS] = [
    CpuSw::ExecNs, CpuSw::MinFlt, CpuSw::MajFlt, CpuSw::ContextSwitch, CpuSw::Migration,
];

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// One CPU slot per test: the array is process-global, so tests pick
    /// distinct CPUs rather than resetting a shared one.
    fn take(cpu: usize) -> Vec<Charge> {
        let mut out = Vec::new();
        drain(cpu, |c| out.push(c));
        out
    }

    fn c(kind: CpuSw, nr: u64, pid: u32, tid: u32) -> Charge { Charge { kind, nr, pid, tid } }

    #[test]
    fn a_parked_opportunity_is_delivered_exactly_once() {
        let cpu = 0;
        let _ = take(cpu);
        queue(CpuSw::ContextSwitch, cpu, 1, 7, 9);
        assert_eq!(take(cpu), alloc::vec![c(CpuSw::ContextSwitch, 1, 7, 9)]);
        assert_eq!(take(cpu), alloc::vec![], "the drain consumed it");
    }

    #[test]
    fn parking_accumulates_per_kind_and_the_drain_names_each() {
        let cpu = 1;
        let _ = take(cpu);
        queue(CpuSw::ContextSwitch, cpu, 1, 7, 9);
        queue(CpuSw::ContextSwitch, cpu, 2, 7, 9);
        queue(CpuSw::Migration, cpu, 1, 7, 9);
        let got = take(cpu);
        assert!(got.contains(&c(CpuSw::ContextSwitch, 3, 7, 9)), "{got:?}");
        assert!(got.contains(&c(CpuSw::Migration, 1, 7, 9)), "{got:?}");
    }

    /// The whole point of the ring: two tasks charging the same event on the
    /// same CPU between drains stay SEPARATE records with their own identities.
    /// Merging them (or keeping one per-kind counter, as this did before) hands
    /// both switches to whichever task the drain happened to see.
    #[test]
    fn charges_from_different_tasks_are_never_merged() {
        let cpu = 9;
        let _ = take(cpu);
        queue(CpuSw::ContextSwitch, cpu, 1, 100, 101);
        queue(CpuSw::ContextSwitch, cpu, 1, 200, 201);
        queue(CpuSw::ContextSwitch, cpu, 1, 100, 101);
        assert_eq!(take(cpu), alloc::vec![
            c(CpuSw::ContextSwitch, 1, 100, 101),
            c(CpuSw::ContextSwitch, 1, 200, 201),
            c(CpuSw::ContextSwitch, 1, 100, 101),
        ]);
    }

    /// Consecutive charges from the SAME task and event still coalesce, which
    /// is what keeps the ring shallow in steady state.
    #[test]
    fn consecutive_charges_from_one_task_coalesce() {
        let cpu = 10;
        let _ = take(cpu);
        for _ in 0..5 { queue(CpuSw::ContextSwitch, cpu, 1, 7, 9); }
        assert_eq!(take(cpu), alloc::vec![c(CpuSw::ContextSwitch, 5, 7, 9)]);
    }

    #[test]
    fn the_queue_is_per_cpu() {
        let (a, b) = (2, 3);
        let _ = take(a); let _ = take(b);
        queue(CpuSw::Migration, a, 5, 7, 9);
        assert_eq!(take(b), alloc::vec![]);
        assert_eq!(take(a), alloc::vec![c(CpuSw::Migration, 5, 7, 9)]);
    }

    /// Distinct tasks cannot coalesce, so the ring is what bounds them: it
    /// fills and drops rather than growing or overwriting an undrained slot.
    #[test]
    fn parking_saturates_rather_than_growing_without_bound() {
        let cpu = 4;
        let _ = take(cpu);
        // Alternating identities defeat the merge, so each charge takes a slot.
        for i in 0..(PENDING_MAX + 10) { queue(CpuSw::ContextSwitch, cpu, 1, 0, i % 2); }
        let parked = peek(cpu);
        assert_eq!(parked.len(), RING - 1, "the ring holds RING-1 undrained slots");
        assert_eq!(take(cpu).len(), RING - 1);
        assert_eq!(take(cpu), alloc::vec![], "the drain consumed them all");
    }

    #[test]
    fn an_out_of_range_cpu_parks_nothing_and_drains_nothing() {
        queue(CpuSw::ContextSwitch, MAX_CPUS, 1, 7, 9);
        assert_eq!(peek(MAX_CPUS), alloc::vec![]);
        let mut hits = 0;
        drain(MAX_CPUS, |_| hits += 1);
        assert_eq!(hits, 0);
    }

    /// The switch note survives the park→drain round trip with both sides'
    /// identities intact, and a drain with nothing parked reports nothing.
    #[test]
    fn a_parked_switch_note_carries_both_sides_and_drains_once() {
        let cpu = 6;
        let _ = take_switch(cpu);
        assert_eq!(take_switch(cpu), None);
        let n = SwitchNote { prev_pid: 10, prev_tid: 11, next_pid: 20, next_tid: 21,
                             preempt: true };
        note_switch(cpu, n);
        assert_eq!(take_switch(cpu), Some(n));
        assert_eq!(take_switch(cpu), None, "the drain consumed it");
        note_switch(cpu, SwitchNote { preempt: false, ..n });
        assert_eq!(take_switch(cpu).map(|x| x.preempt), Some(false));
    }

    #[test]
    fn switch_notes_are_per_cpu_and_an_out_of_range_cpu_parks_nothing() {
        let _ = take_switch(7); let _ = take_switch(8);
        note_switch(7, SwitchNote { prev_tid: 1, ..SwitchNote::default() });
        assert_eq!(take_switch(8), None);
        assert_eq!(take_switch(7).map(|n| n.prev_tid), Some(1));
        note_switch(MAX_CPUS, SwitchNote::default());
        assert_eq!(take_switch(MAX_CPUS), None);
    }

    /// The index walk in `drain` must report the kind that was parked; a
    /// mismatched `KINDS` table would silently sample the wrong software event.
    #[test]
    fn the_kind_table_matches_the_discriminants() {
        for (i, k) in KINDS.iter().enumerate() { assert_eq!(*k as usize, i); }
    }
}
