// Ordering contract for the page-teardown gather (Linux `mm/mmu_gather.c`).
//
// These run hosted: `tlb_gather` deliberately sits at the crate root, NOT
// under `user_as` (which is `#[cfg(target_os = "oxide-kernel")]` and would
// compile its tests away silently).

use super::*;
use alloc::vec::Vec;

const PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    Tear(u64),
    Inval(u64),
    Shoot(u64),
    Free(u64),
}

/// Recording `GatherOps` over a fake page table (`va -> pa`).
struct Fake {
    present: Vec<(u64, u64)>,
    log: Vec<Ev>,
}

impl Fake {
    /// `n` present pages starting at `base`, each mapping to a distinct pa.
    fn with_pages(base: u64, n: u64) -> Self {
        let present = (0..n).map(|i| (base + i * PAGE, 0x10_0000 + i * PAGE)).collect();
        Self { present, log: Vec::new() }
    }
}

impl GatherOps for Fake {
    fn tear_leaf(&mut self, va: u64) -> Option<u64> {
        let idx = self.present.iter().position(|(v, _)| *v == va)?;
        let (_, pa) = self.present.remove(idx);
        self.log.push(Ev::Tear(va));
        Some(pa)
    }
    fn invalidate_local(&mut self, va: u64) { self.log.push(Ev::Inval(va)); }
    fn shootdown_others(&mut self, targets: u64) { self.log.push(Ev::Shoot(targets)); }
    fn free_frame(&mut self, pa: u64) { self.log.push(Ev::Free(pa)); }
}

/// The invariant Linux's `tlb_flush_mmu_tlbonly()`-before-`tlb_flush_mmu_free()`
/// enforces: a frame may only be released once a remote shootdown issued AFTER
/// its VA was torn out has completed. `pas_in_tear_order` supplies the frame
/// each `Tear` yielded. Returns the first frame released too early.
fn violating_free(log: &[Ev], pas_in_tear_order: &[u64]) -> Option<u64> {
    let mut torn = pas_in_tear_order.iter().copied();
    let mut pending: Vec<u64> = Vec::new();
    let mut covered: Vec<u64> = Vec::new();
    for ev in log {
        match *ev {
            Ev::Tear(_) => { if let Some(pa) = torn.next() { pending.push(pa); } }
            Ev::Inval(_) => {}
            Ev::Shoot(_) => { covered.append(&mut pending); }
            Ev::Free(pa) => { if !covered.contains(&pa) { return Some(pa); } }
        }
    }
    None
}

/// Frames `Fake::with_pages` hands out, in tear order.
fn pas(n: u64) -> Vec<u64> { (0..n).map(|i| 0x10_0000 + i * PAGE).collect() }

#[test]
fn every_frame_is_invalidated_before_it_is_freed() {
    let mut f = Fake::with_pages(0x1000_0000, 8);
    let mut g = TlbGather::new(0b110);
    for i in 0..8 { g.unmap_one(&mut f, 0x1000_0000 + i * PAGE); }
    g.finish(&mut f);
    assert!(violating_free(&f.log, &pas(8)).is_none(),
        "a frame was released before the TLB invalidate covering it: {:?}", f.log);
}

#[test]
fn no_frame_is_freed_before_the_first_shootdown() {
    let mut f = Fake::with_pages(0x2000_0000, 4);
    let mut g = TlbGather::new(0b1010);
    for i in 0..4 { g.unmap_one(&mut f, 0x2000_0000 + i * PAGE); }
    g.finish(&mut f);
    let first_shoot = f.log.iter().position(|e| matches!(e, Ev::Shoot(_)));
    let first_free = f.log.iter().position(|e| matches!(e, Ev::Free(_)));
    assert!(first_shoot.is_some(), "no remote shootdown was issued at all: {:?}", f.log);
    assert!(first_free.is_some(), "nothing was freed: {:?}", f.log);
    assert!(first_shoot < first_free,
        "free preceded the remote shootdown (use-after-free window): {:?}", f.log);
}

#[test]
fn shootdown_targets_the_owning_mm_cpumask() {
    const MASK: u64 = 0b1011_0000;
    let mut f = Fake::with_pages(0x3000_0000, 2);
    let mut g = TlbGather::new(MASK);
    for i in 0..2 { g.unmap_one(&mut f, 0x3000_0000 + i * PAGE); }
    g.finish(&mut f);
    let shot: Vec<u64> = f.log.iter().filter_map(|e| match e { Ev::Shoot(m) => Some(*m), _ => None }).collect();
    assert!(!shot.is_empty(), "no shootdown issued");
    for m in shot { assert_eq!(m, MASK, "shootdown used the wrong cpumask"); }
}

#[test]
fn absent_leaves_neither_invalidate_nor_free() {
    let mut f = Fake::with_pages(0x4000_0000, 1);
    let mut g = TlbGather::new(0b10);
    // Second VA is not present in the fake table.
    assert!(g.unmap_one(&mut f, 0x4000_0000));
    assert!(!g.unmap_one(&mut f, 0x4000_1000));
    g.finish(&mut f);
    let frees = f.log.iter().filter(|e| matches!(e, Ev::Free(_))).count();
    assert_eq!(frees, 1, "an absent leaf produced a frame release: {:?}", f.log);
}

#[test]
fn batch_boundary_still_flushes_before_freeing() {
    // Cross a full batch so the mid-loop forced flush is exercised.
    let n = GATHER_BATCH_PAGES as u64 + 3;
    let mut f = Fake::with_pages(0x5000_0000, n);
    let mut g = TlbGather::new(0b110);
    for i in 0..n { g.unmap_one(&mut f, 0x5000_0000 + i * PAGE); }
    g.finish(&mut f);
    assert!(violating_free(&f.log, &pas(n)).is_none(),
        "batch-boundary flush released a frame before invalidating it");
    let frees = f.log.iter().filter(|e| matches!(e, Ev::Free(_))).count();
    assert_eq!(frees, n as usize, "not every torn frame was released");
}

#[test]
fn gather_holds_frames_until_a_flush() {
    let mut f = Fake::with_pages(0x6000_0000, 3);
    let mut g = TlbGather::new(0b110);
    for i in 0..3 { g.unmap_one(&mut f, 0x6000_0000 + i * PAGE); }
    assert_eq!(g.pending(), 3, "frames must be batched, not freed inline");
    assert!(!f.log.iter().any(|e| matches!(e, Ev::Free(_))),
        "a frame was released before any flush: {:?}", f.log);
    g.finish(&mut f);
    assert_eq!(f.log.iter().filter(|e| matches!(e, Ev::Free(_))).count(), 3);
}

/// The checker must actually reject the pre-fix ordering, otherwise the tests
/// above prove nothing. This replays exactly what `evict_foreign_pages_in_range`
/// used to emit — tear then free, with no invalidate and no shootdown — and
/// asserts the invariant catches it.
#[test]
fn checker_rejects_the_pre_fix_free_without_flush() {
    let pas_order = [0x10_0000u64, 0x10_1000];
    let buggy = [
        Ev::Tear(0x7000_0000), Ev::Free(0x10_0000),
        Ev::Tear(0x7000_1000), Ev::Free(0x10_1000),
    ];
    assert_eq!(violating_free(&buggy, &pas_order), Some(0x10_0000),
        "the ordering checker fails to detect free-before-flush");
}

/// A flush that invalidates locally but never shoots down peers is still a
/// use-after-free on x86 (no hardware broadcast) — the checker must reject it.
#[test]
fn checker_rejects_local_invalidate_without_remote_shootdown() {
    let pas_order = [0x10_0000u64];
    let buggy = [Ev::Tear(0x8000_0000), Ev::Inval(0x8000_0000), Ev::Free(0x10_0000)];
    assert_eq!(violating_free(&buggy, &pas_order), Some(0x10_0000),
        "local-only invalidate must not count as covering a remote CPU");
}
