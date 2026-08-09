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

use core::sync::atomic::{AtomicU32, Ordering};

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

    /// The index walk in `drain` must report the kind that was parked; a
    /// mismatched `KINDS` table would silently sample the wrong software event.
    #[test]
    fn the_kind_table_matches_the_discriminants() {
        for (i, k) in KINDS.iter().enumerate() { assert_eq!(*k as usize, i); }
    }
}
