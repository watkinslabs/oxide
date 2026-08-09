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
// Lock-free by construction — the queue side runs with a raw spinlock held and
// must not take another.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use cpu::MAX_CPUS;

use super::{CpuSw, NR_KINDS};

/// Ceiling on opportunities parked for one `(kind, cpu)` between drains. The
/// drain runs on every context switch, so the steady-state depth is 1; the cap
/// only bounds the pathological case where a CPU charges without ever reaching
/// its switch tail, and its effect is to drop sampling opportunities (the
/// counters are unaffected) rather than to let the queue grow without bound.
pub const PENDING_MAX: u32 = 64;

static PENDING: [[AtomicU32; MAX_CPUS]; NR_KINDS] =
    [const { [const { AtomicU32::new(0) }; MAX_CPUS] }; NR_KINDS];

/// Snapshot of one CPU's parked opportunities, for the tests that pin the
/// saturation ceiling. The live drain consumes the slots rather than reading
/// them, so nothing in the kernel build needs this.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pending {
    pub ctxsw:     u32,
    pub migration: u32,
}

/// Park `n` opportunities for `kind` on `cpu`. # C: O(1)
pub fn queue(kind: CpuSw, cpu: usize, n: u64) {
    if cpu >= MAX_CPUS || n == 0 { return; }
    let slot = &PENDING[kind as usize][cpu];
    let add = n.min(PENDING_MAX as u64) as u32;
    let _ = slot.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |cur| Some(cur.saturating_add(add).min(PENDING_MAX)));
}

/// Take every parked opportunity on `cpu` and hand each `(kind, count)` to
/// `f`. Each slot is claimed with a swap, so a concurrent `queue` on the same
/// CPU parks against the next drain rather than being lost. # C: O(NR_KINDS)
pub fn drain(cpu: usize, mut f: impl FnMut(CpuSw, u64)) {
    if cpu >= MAX_CPUS { return; }
    for (i, kind) in KINDS.iter().enumerate() {
        let n = PENDING[i][cpu].swap(0, Ordering::AcqRel);
        if n != 0 { f(*kind, n as u64); }
    }
}

/// Parked counts for `cpu` without consuming them. # C: O(1)
#[cfg(test)]
pub fn peek(cpu: usize) -> Pending {
    if cpu >= MAX_CPUS { return Pending::default(); }
    Pending {
        ctxsw:     PENDING[CpuSw::ContextSwitch as usize][cpu].load(Ordering::Acquire),
        migration: PENDING[CpuSw::Migration as usize][cpu].load(Ordering::Acquire),
    }
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
    fn take(cpu: usize) -> Vec<(CpuSw, u64)> {
        let mut out = Vec::new();
        drain(cpu, |k, n| out.push((k, n)));
        out
    }

    #[test]
    fn a_parked_opportunity_is_delivered_exactly_once() {
        let cpu = 0;
        let _ = take(cpu);
        queue(CpuSw::ContextSwitch, cpu, 1);
        assert_eq!(take(cpu), alloc::vec![(CpuSw::ContextSwitch, 1)]);
        assert_eq!(take(cpu), alloc::vec![], "the drain consumed it");
    }

    #[test]
    fn parking_accumulates_per_kind_and_the_drain_names_each() {
        let cpu = 1;
        let _ = take(cpu);
        queue(CpuSw::ContextSwitch, cpu, 1);
        queue(CpuSw::ContextSwitch, cpu, 2);
        queue(CpuSw::Migration, cpu, 1);
        let got = take(cpu);
        assert!(got.contains(&(CpuSw::ContextSwitch, 3)), "{got:?}");
        assert!(got.contains(&(CpuSw::Migration, 1)), "{got:?}");
    }

    #[test]
    fn the_queue_is_per_cpu() {
        let (a, b) = (2, 3);
        let _ = take(a); let _ = take(b);
        queue(CpuSw::Migration, a, 5);
        assert_eq!(take(b), alloc::vec![]);
        assert_eq!(take(a), alloc::vec![(CpuSw::Migration, 5)]);
    }

    #[test]
    fn parking_saturates_rather_than_growing_without_bound() {
        let cpu = 4;
        let _ = take(cpu);
        for _ in 0..(PENDING_MAX + 10) { queue(CpuSw::ContextSwitch, cpu, 1); }
        assert_eq!(peek(cpu).ctxsw, PENDING_MAX);
        assert_eq!(take(cpu), alloc::vec![(CpuSw::ContextSwitch, PENDING_MAX as u64)]);
        // A single oversized charge is clamped by the same ceiling.
        queue(CpuSw::ContextSwitch, cpu, u64::MAX);
        assert_eq!(peek(cpu).ctxsw, PENDING_MAX);
        let _ = take(cpu);
    }

    #[test]
    fn an_out_of_range_cpu_parks_nothing_and_drains_nothing() {
        queue(CpuSw::ContextSwitch, MAX_CPUS, 1);
        assert_eq!(peek(MAX_CPUS), Pending::default());
        let mut hits = 0;
        drain(MAX_CPUS, |_, _| hits += 1);
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
