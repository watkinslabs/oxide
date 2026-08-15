use alloc::boxed::Box;
use alloc::vec::Vec;

use hal::Pfn;

use crate::{reclaim_state, PageFlags, PageMeta, PageMetaArr, ReclaimPageState};
use super::{Lru, Reclaim, ReclaimError};
use crate::irq_gate::PmmIrq;

fn meta(count: usize) -> PageMetaArr {
    let pages: Vec<PageMeta> = (0..count).map(|_| PageMeta::new()).collect();
    PageMetaArr::new(0, Box::leak(pages.into_boxed_slice()))
}

fn flags(meta: &PageMetaArr, pfn: u64) -> PageFlags { meta.flags(Pfn(pfn)).unwrap() }

#[test]
fn classification_membership_is_page_meta_truth() {
    let meta = meta(2);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    assert_eq!(reclaim_state(flags(&meta, 0)),
        ReclaimPageState::OnLru { active: false, unevictable: false });
    assert_eq!(reclaim.len(Lru::InactiveAnon), 1);
    assert_eq!(reclaim.add(&meta, Pfn(0), Lru::InactiveAnon), Err(ReclaimError::State));
    assert_eq!(reclaim.add(&meta, Pfn(1), Lru::InactiveAnon), Err(ReclaimError::Class));
}

#[test]
fn isolation_has_exactly_one_terminal_transition() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::FILE).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::ActiveFile).unwrap();
    let isolated = reclaim.isolate(&meta, Lru::ActiveFile).unwrap().unwrap();
    assert_eq!(reclaim.len(Lru::ActiveFile), 0);
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::Isolated { active: true });
    reclaim.putback(&meta, isolated).unwrap();
    assert_eq!(reclaim.len(Lru::ActiveFile), 1);
    assert_eq!(reclaim.release(&meta, isolated), Err(ReclaimError::State));
    let isolated = reclaim.isolate(&meta, Lru::ActiveFile).unwrap().unwrap();
    reclaim.release(&meta, isolated).unwrap();
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::NotOnLru);
}

#[test]
fn fifo_isolation_preserves_each_pages_original_lru() {
    let meta = meta(3);
    for pfn in 0..3 { meta.set_flags(Pfn(pfn), PageFlags::ANON).unwrap(); }
    let reclaim = Reclaim::<PmmIrq>::new();
    for pfn in 0..3 { reclaim.add(&meta, Pfn(pfn), Lru::InactiveAnon).unwrap(); }
    let first = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
    assert_eq!(first.pfn(), Pfn(0));
    reclaim.putback(&meta, first).unwrap();
    let second = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
    assert_eq!(second.pfn(), Pfn(1));
    reclaim.release(&meta, second).unwrap();
    assert_eq!(reclaim.len(Lru::InactiveAnon), 2);
}

#[test]
fn memcg_isolation_skips_unrelated_pages_without_reordering_them() {
    const FIRST_MEMCG: u64 = 41;
    const TARGET_MEMCG: u64 = 42;
    let meta = meta(3);
    for pfn in 0..3 { meta.set_flags(Pfn(pfn), PageFlags::ANON).unwrap(); }
    meta.set_memcg(Pfn(0), FIRST_MEMCG).unwrap();
    meta.set_memcg(Pfn(1), TARGET_MEMCG).unwrap();
    meta.set_memcg(Pfn(2), FIRST_MEMCG).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    for pfn in 0..3 { reclaim.add(&meta, Pfn(pfn), Lru::InactiveAnon).unwrap(); }
    let isolated = reclaim.isolate_memcg(&meta, Lru::InactiveAnon, TARGET_MEMCG).unwrap().unwrap();
    assert_eq!(isolated.pfn(), Pfn(1));
    reclaim.release(&meta, isolated).unwrap();
    let first = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
    assert_eq!(first.pfn(), Pfn(2));
}

#[test]
fn unevictable_cannot_carry_active_or_isolated_conflicts() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::Unevictable).unwrap();
    assert_eq!(reclaim_state(flags(&meta, 0)),
        ReclaimPageState::OnLru { active: false, unevictable: true });
    meta.set_flags(Pfn(0), PageFlags::ACTIVE).unwrap();
    assert_eq!(reclaim.isolate(&meta, Lru::Unevictable), Err(ReclaimError::State));
    // The stale index was consumed but never claimed as page ownership.
    assert_eq!(reclaim.len(Lru::Unevictable), 0);
}

#[test]
fn stale_queue_index_is_discarded_when_page_class_changes() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    meta.clear_flags(Pfn(0), PageFlags::ANON).unwrap();
    meta.set_flags(Pfn(0), PageFlags::FILE).unwrap();
    assert_eq!(reclaim.isolate(&meta, Lru::InactiveAnon), Err(ReclaimError::Class));
    assert_eq!(reclaim.len(Lru::InactiveAnon), 0);
}

#[test]
fn final_free_unlinks_exactly_one_lru_membership() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    reclaim.unlink_for_free(&meta, Pfn(0)).unwrap();
    assert_eq!(reclaim.len(Lru::InactiveAnon), 0);
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::NotOnLru);
    // Direct non-reclaim frames and a second final-free observation carry no
    // queue ownership and therefore have no second transition to perform.
    reclaim.unlink_for_free(&meta, Pfn(0)).unwrap();
}

#[test]
fn exact_middle_unlink_preserves_large_lru_fifo() {
    const PAGES: u64 = 1024;
    const REMOVED: u64 = 777;
    let meta = meta(PAGES as usize);
    let reclaim = Reclaim::<PmmIrq>::new();
    for pfn in 0..PAGES {
        meta.set_flags(Pfn(pfn), PageFlags::ANON).unwrap();
        reclaim.add(&meta, Pfn(pfn), Lru::InactiveAnon).unwrap();
    }

    reclaim.unlink_for_free(&meta, Pfn(REMOVED)).unwrap();
    assert_eq!(reclaim.len(Lru::InactiveAnon), PAGES as usize - 1);
    for expected in (0..PAGES).filter(|pfn| *pfn != REMOVED) {
        let isolated = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
        assert_eq!(isolated.pfn(), Pfn(expected));
        reclaim.release(&meta, isolated).unwrap();
    }
    assert_eq!(reclaim.isolate(&meta, Lru::InactiveAnon), Ok(None));
}

#[test]
fn isolated_page_cannot_bypass_reclaim_terminal_transition() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    let _isolated = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
    assert_eq!(reclaim.unlink_for_free(&meta, Pfn(0)), Err(ReclaimError::State));
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::Isolated { active: false });
}

#[test]
fn referenced_inactive_anon_promotes_and_consumes_its_sample() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    reclaim.mark_anon_referenced(&meta, Pfn(0)).unwrap();
    let aged = reclaim.age_anon(&meta, 1).unwrap();
    assert_eq!(aged.scanned, 1);
    assert_eq!(aged.activated, 1);
    assert_eq!(aged.deactivated, 0);
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::OnLru { active: true, unevictable: false });
    assert!(!flags(&meta, 0).contains(PageFlags::REFERENCED));
    assert_eq!(reclaim.len(Lru::InactiveAnon), 0);
    assert_eq!(reclaim.len(Lru::ActiveAnon), 1);
}

#[test]
fn active_anon_requires_two_unreferenced_samples_before_reclaimable() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::ActiveAnon).unwrap();
    reclaim.mark_anon_referenced(&meta, Pfn(0)).unwrap();
    let first = reclaim.age_anon(&meta, 1).unwrap();
    assert_eq!(first, super::Aging { scanned: 1, activated: 0, deactivated: 0 });
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::OnLru { active: true, unevictable: false });
    assert!(!flags(&meta, 0).contains(PageFlags::REFERENCED));
    let second = reclaim.age_anon(&meta, 1).unwrap();
    assert_eq!(second, super::Aging { scanned: 1, activated: 0, deactivated: 1 });
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::OnLru { active: false, unevictable: false });
}

#[test]
fn age_budget_is_per_lru_and_preserves_fifo_order() {
    let meta = meta(3);
    for pfn in 0..3 { meta.set_flags(Pfn(pfn), PageFlags::ANON).unwrap(); }
    let reclaim = Reclaim::<PmmIrq>::new();
    for pfn in 0..3 { reclaim.add(&meta, Pfn(pfn), Lru::InactiveAnon).unwrap(); }
    reclaim.mark_anon_referenced(&meta, Pfn(0)).unwrap();
    reclaim.mark_anon_referenced(&meta, Pfn(1)).unwrap();
    let aged = reclaim.age_anon(&meta, 1).unwrap();
    assert_eq!(aged, super::Aging { scanned: 1, activated: 1, deactivated: 0 });
    let oldest_inactive = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
    assert_eq!(oldest_inactive.pfn(), Pfn(1));
    reclaim.putback(&meta, oldest_inactive).unwrap();
    let oldest_active = reclaim.isolate(&meta, Lru::ActiveAnon).unwrap().unwrap();
    assert_eq!(oldest_active.pfn(), Pfn(0));
}

#[test]
fn reference_rejects_file_unmapped_and_unevictable_pages() {
    let meta = meta(3);
    meta.set_flags(Pfn(0), PageFlags::FILE).unwrap();
    meta.set_flags(Pfn(1), PageFlags::ANON).unwrap();
    meta.set_flags(Pfn(2), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveFile).unwrap();
    reclaim.add(&meta, Pfn(2), Lru::Unevictable).unwrap();
    assert_eq!(reclaim.mark_anon_referenced(&meta, Pfn(0)), Err(ReclaimError::Class));
    assert_eq!(reclaim.mark_anon_referenced(&meta, Pfn(1)), Err(ReclaimError::State));
    assert_eq!(reclaim.mark_anon_referenced(&meta, Pfn(2)), Err(ReclaimError::State));
}

#[test]
fn referenced_file_page_promotes_then_demotes_on_file_lrus() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::FILE).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveFile).unwrap();
    reclaim.mark_referenced(&meta, Pfn(0)).unwrap();
    assert_eq!(reclaim.age_file(&meta, 1).unwrap(), super::Aging {
        scanned: 1, activated: 1, deactivated: 0,
    });
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::OnLru { active: true, unevictable: false });
    assert_eq!(reclaim.age_file(&meta, 1).unwrap(), super::Aging {
        scanned: 1, activated: 0, deactivated: 1,
    });
    assert_eq!(reclaim_state(flags(&meta, 0)), ReclaimPageState::OnLru { active: false, unevictable: false });
}

#[test]
fn mlock_moves_file_and_shmem_pages_without_reclassifying_them() {
    let meta = meta(2);
    meta.set_flags(Pfn(0), PageFlags::FILE).unwrap();
    meta.set_flags(Pfn(1), PageFlags::SHMEM).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveFile).unwrap();
    reclaim.add(&meta, Pfn(1), Lru::InactiveAnon).unwrap();
    reclaim.set_unevictable(&meta, Pfn(0), true).unwrap();
    reclaim.set_unevictable(&meta, Pfn(1), true).unwrap();
    assert_eq!(reclaim.snapshot(), super::ReclaimSnapshot { unevictable: 2, ..Default::default() });
    reclaim.set_unevictable(&meta, Pfn(0), false).unwrap();
    reclaim.set_unevictable(&meta, Pfn(1), false).unwrap();
    assert_eq!(reclaim.snapshot(), super::ReclaimSnapshot {
        inactive_anon: 1, inactive_file: 1, ..Default::default()
    });
    assert!(flags(&meta, 0).contains(PageFlags::FILE));
    assert!(flags(&meta, 1).contains(PageFlags::SHMEM));
}

#[test]
fn shmem_rmap_preserves_lru_class_at_final_free() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::SHMEM).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    assert!(flags(&meta, 0).contains(PageFlags::SHMEM));
    assert!(!flags(&meta, 0).contains(PageFlags::FILE));
    reclaim.unlink_for_free(&meta, Pfn(0)).unwrap();
    assert_eq!(reclaim.len(Lru::InactiveAnon), 0);
}

#[test]
fn explicit_pageout_isolates_exact_anon_lru_member_without_pfn_scan() {
    let meta = meta(3);
    for pfn in 0..3 { meta.set_flags(Pfn(pfn), PageFlags::ANON).unwrap(); }
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    reclaim.add(&meta, Pfn(1), Lru::ActiveAnon).unwrap();
    let isolated = reclaim.isolate_anon_pfn(&meta, Pfn(1)).unwrap().unwrap();
    assert_eq!(isolated.pfn(), Pfn(1));
    assert_eq!(isolated.lru(), Lru::ActiveAnon);
    assert_eq!(reclaim.len(Lru::InactiveAnon), 1);
    assert_eq!(reclaim.len(Lru::ActiveAnon), 0);
    reclaim.putback(&meta, isolated).unwrap();
    assert_eq!(reclaim.len(Lru::ActiveAnon), 1);
    assert_eq!(reclaim.isolate_anon_pfn(&meta, Pfn(2)), Ok(None));
}

#[test]
fn snapshot_tracks_lru_transitions_without_inventing_pages() {
    let meta = meta(3);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    meta.set_flags(Pfn(1), PageFlags::ANON).unwrap();
    meta.set_flags(Pfn(2), PageFlags::FILE).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    reclaim.add(&meta, Pfn(1), Lru::ActiveAnon).unwrap();
    reclaim.add(&meta, Pfn(2), Lru::InactiveFile).unwrap();
    assert_eq!(reclaim.snapshot(), super::ReclaimSnapshot {
        inactive_anon: 1, active_anon: 1, inactive_file: 1, ..Default::default()
    });
    reclaim.mark_anon_referenced(&meta, Pfn(0)).unwrap();
    assert_eq!(reclaim.age_anon(&meta, 1).unwrap(), super::Aging {
        scanned: 2, activated: 1, deactivated: 1,
    });
    let isolated = reclaim.isolate(&meta, Lru::InactiveAnon).unwrap().unwrap();
    reclaim.release(&meta, isolated).unwrap();
    assert_eq!(reclaim.snapshot(), super::ReclaimSnapshot {
        active_anon: 1, inactive_file: 1,
        scanned: 3, stolen: 1, activated: 1, deactivated: 1,
        ..Default::default()
    });
}

#[test]
fn failed_reclaim_transition_counts_the_scan_but_not_a_state_transition() {
    let meta = meta(1);
    meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
    let reclaim = Reclaim::<PmmIrq>::new();
    reclaim.add(&meta, Pfn(0), Lru::InactiveAnon).unwrap();
    let before = reclaim.snapshot();
    meta.clear_flags(Pfn(0), PageFlags::ANON).unwrap();
    meta.set_flags(Pfn(0), PageFlags::FILE).unwrap();
    assert_eq!(reclaim.isolate(&meta, Lru::InactiveAnon), Err(ReclaimError::Class));
    assert_eq!(reclaim.snapshot(), super::ReclaimSnapshot { scanned: before.scanned + 1, ..before });
}

/// Every LRU mutation must run with local interrupts masked.
///
/// `free_one_frame` unlinks a page from its LRU on its way to the buddy free
/// list, and that path runs in interrupt context too — a completion softirq
/// dropping the driver's last reference to a page. Taken plainly, the lock
/// deadlocks the CPU against itself: the interrupt spins for a lock the
/// interrupted task on that same CPU already holds, interrupts masked, no tick
/// left to break it. One boot died exactly there, spinning inside
/// `free_one_frame` with a soft lockup and zero context switches for 40 s.
///
/// The probe gate counts mask/restore pairs, so a lock taken plainly scores
/// zero and this goes red.
mod irq_masking {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static MASKED: AtomicUsize = AtomicUsize::new(0);
    static DEPTH: AtomicUsize = AtomicUsize::new(0);
    /// Highest nesting depth seen — proves the section was entered, not just
    /// that the gate was called.
    static PEAK: AtomicUsize = AtomicUsize::new(0);

    struct ProbeIrq;
    impl sync::IrqGate for ProbeIrq {
        unsafe fn save_disable() -> u64 {
            MASKED.fetch_add(1, Ordering::SeqCst);
            let d = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
            PEAK.fetch_max(d, Ordering::SeqCst);
            0
        }
        unsafe fn save_enable() -> u64 { 0 }
        unsafe fn restore(_flags: u64) { DEPTH.fetch_sub(1, Ordering::SeqCst); }
    }

    fn observe(op: impl FnOnce(&Reclaim<ProbeIrq>, &PageMetaArr)) -> (usize, usize) {
        MASKED.store(0, Ordering::SeqCst);
        DEPTH.store(0, Ordering::SeqCst);
        PEAK.store(0, Ordering::SeqCst);
        let meta = meta(1);
        meta.set_flags(Pfn(0), PageFlags::ANON).unwrap();
        let reclaim = Reclaim::<ProbeIrq>::new();
        MASKED.store(0, Ordering::SeqCst);
        PEAK.store(0, Ordering::SeqCst);
        op(&reclaim, &meta);
        (MASKED.load(Ordering::SeqCst), PEAK.load(Ordering::SeqCst))
    }

    /// The path the wedge was on: the terminal unlink before a frame reaches
    /// the buddy free list.
    #[test]
    fn the_final_free_unlink_masks_interrupts() {
        let (masked, peak) = observe(|r, meta| {
            r.add(meta, Pfn(0), Lru::InactiveAnon).unwrap();
            r.unlink_for_free(meta, Pfn(0)).unwrap();
        });
        assert!(masked >= 2, "add + unlink_for_free must each mask: {masked}");
        assert_eq!(peak, 1, "the section must actually be entered, once, unnested");
    }

    /// ...and every other mutator, so a later edit cannot reintroduce a plain
    /// acquisition on one path while the others stay safe.
    #[test]
    fn every_lru_mutation_masks_interrupts() {
        for (name, masked) in [
            ("add", observe(|r, m| { r.add(m, Pfn(0), Lru::InactiveAnon).unwrap(); }).0),
            ("len", observe(|r, _| { let _ = r.len(Lru::InactiveAnon); }).0),
            ("snapshot", observe(|r, _| { let _ = r.snapshot(); }).0),
            ("isolate", observe(|r, m| {
                r.add(m, Pfn(0), Lru::InactiveAnon).unwrap();
                let _ = r.isolate(m, Lru::InactiveAnon);
            }).0),
        ] {
            assert!(masked >= 1, "{name} took the LRU lock without masking interrupts");
        }
    }

    /// The gate is balanced: a mutation must not leave interrupts masked.
    #[test]
    fn the_masked_section_is_released() {
        observe(|r, m| { r.add(m, Pfn(0), Lru::InactiveAnon).unwrap(); });
        assert_eq!(DEPTH.load(Ordering::SeqCst), 0, "LRU lock left interrupts masked");
    }
}
