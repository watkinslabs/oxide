use super::*;

#[test]
fn free_snapshot_drains_pcp_and_exact_claim_is_reversible() {
    let pmm = build(128);
    let cached = pmm.alloc(Order(0)).unwrap();
    // SAFETY: cached is this test's live order-0 allocation.
    unsafe { pmm.free(cached, Order(0)) };
    assert_eq!(pmm.pcp_cached_pages().iter().sum::<u64>(), 1,
        "positive control did not place the page in PCP");

    let before = pmm.hibernate_free_snapshot();
    assert_eq!(before.free_pages(), 128);
    assert!(before.contains(Pfn(37)));
    assert_eq!(pmm.pcp_cached_pages().iter().sum::<u64>(), 0,
        "snapshot did not drain every PCP");

    let exact = pmm.claim_hibernate_pfn(Pfn(37)).expect("free target must be claimable");
    assert_eq!(exact.pfn(), Pfn(37));
    let held = pmm.hibernate_free_snapshot();
    assert!(!held.contains(Pfn(37)));
    assert_eq!(held.free_pages(), 127);
    assert!(pmm.claim_hibernate_pfn(Pfn(37)).is_none(),
        "an owned target must report a collision");

    drop(exact);
    let released = pmm.hibernate_free_snapshot();
    assert!(released.contains(Pfn(37)));
    assert_eq!(released.free_pages(), 128);
    // SAFETY: hosted single-thread; audit takes its own lock.
    unsafe { pmm.audit() };
}

#[test]
fn copy_and_destination_owners_are_disjoint_until_drop() {
    let pmm = build(128);
    let copy = pmm.alloc_hibernate_frame().unwrap();
    let destination_pfn = if copy.pfn() == Pfn(91) { Pfn(90) } else { Pfn(91) };
    let destination = pmm.claim_hibernate_pfn(destination_pfn).unwrap();
    assert_ne!(copy.pfn(), destination.pfn());

    let held = pmm.hibernate_free_snapshot();
    assert!(!held.contains(copy.pfn()));
    assert!(!held.contains(destination.pfn()));
    drop(destination);
    drop(copy);
    assert_eq!(pmm.hibernate_free_snapshot().free_pages(), 128);
}

#[test]
fn exclusion_membership_negative_control_catches_missing_claim() {
    let pmm = build(64);
    let target = Pfn(19);
    let free = pmm.hibernate_free_snapshot();
    assert!(free.contains(target), "positive control requires a free target");
    let owner = pmm.claim_hibernate_pfn(target).unwrap();
    assert!(!pmm.hibernate_free_snapshot().contains(target),
        "removing the exact-claim exclusion must fail this oracle");
    drop(owner);
}

#[test]
fn permanent_boot_reservation_is_the_same_hibernation_exclusion_truth() {
    let pmm = build(128);
    pmm.reserve_early_nosave(Pfn(40), 3).unwrap();
    for pfn in 40..43 { assert!(pmm.hibernate_pfn_forbidden(Pfn(pfn))); }
    let snapshot = pmm.hibernate_free_snapshot();
    for pfn in 40..43 { assert!(snapshot.forbidden(Pfn(pfn))); }
    assert!(!pmm.hibernate_pfn_forbidden(Pfn(39)));
    assert!(!pmm.hibernate_pfn_forbidden(Pfn(43)));
}

#[test]
fn ordinary_reservation_does_not_silently_acquire_nosave_policy() {
    let pmm = build(64);
    pmm.reserve_early(Pfn(9), 1).unwrap();
    assert!(!pmm.hibernate_pfn_forbidden(Pfn(9)));
    pmm.reserve_early_nosave(Pfn(10), 1).unwrap();
    assert!(pmm.hibernate_pfn_forbidden(Pfn(10)));
    pmm.reserve_early_nosave(Pfn(9), 1).unwrap();
    assert!(pmm.hibernate_pfn_forbidden(Pfn(9)), "named nosave promotes an earlier reservation");
}

#[test]
fn a_permanent_forbid_can_neither_be_claimed_nor_cleared_by_drop() {
    let pmm = build(64);
    pmm.reserve_early_nosave(Pfn(17), 1).unwrap();
    assert!(pmm.claim_hibernate_pfn(Pfn(17)).is_none());
    let temporary = pmm.alloc_hibernate_frame().unwrap();
    drop(temporary);
    assert!(pmm.hibernate_pfn_forbidden(Pfn(17)));
}

#[test]
fn hibernation_temporary_is_forbidden_exactly_for_owner_lifetime() {
    let pmm = build(64);
    let ordinary = pmm.alloc(Order(0)).unwrap();
    assert!(!pmm.hibernate_pfn_forbidden(ordinary),
        "ordinary live memory belongs in the image");
    let temporary = pmm.alloc_hibernate_frame().unwrap();
    let temporary_pfn = temporary.pfn();
    assert!(pmm.hibernate_pfn_forbidden(temporary_pfn));
    drop(temporary);
    assert!(!pmm.hibernate_pfn_forbidden(temporary_pfn));
    // SAFETY: ordinary remains this test's sole allocation.
    unsafe { pmm.free(ordinary, Order(0)) };
}

#[test]
fn saved_state_is_owned_but_remains_image_saveable() {
    let pmm = build(64);
    let state = pmm.alloc_hibernate_saved_frame().unwrap();
    let state_pfn = state.pfn();
    let frozen = pmm.hibernate_free_snapshot();
    assert!(!frozen.contains(state_pfn), "saved state must be allocated before selection");
    assert!(!frozen.forbidden(state_pfn),
        "positive control: saved state must not use the temporary nosave role");
    drop(state);
    assert!(pmm.hibernate_free_snapshot().contains(state_pfn));
}

#[test]
fn large_hibernation_pool_releases_through_pcp_batches_without_list_drift() {
    const PAGES: u64 = 32_768;
    const HELD: usize = 24_000;
    const BATCH: usize = 256;
    let pmm = build(PAGES);
    let mut frames = Vec::new();
    frames.try_reserve_exact(HELD).unwrap();
    for _ in 0..HELD { frames.push(pmm.alloc_hibernate_frame().unwrap()); }
    while !frames.is_empty() {
        frames.truncate(frames.len().saturating_sub(BATCH));
        // SAFETY: the retained owners exclude every still-live frame; audit
        // takes the allocator lock after the released batch has completed.
        unsafe { pmm.audit() };
    }
    pmm.drain_pcp_for_test();
    assert_eq!(pmm.free_pages(), PAGES);
    // SAFETY: every hibernation owner was dropped and PCP drain completed.
    unsafe { pmm.audit() };
}

#[test]
fn restored_buddy_links_are_rebuilt_without_reading_omitted_free_page_bytes() {
    const PAGES: u64 = 4096;
    let pmm = build(PAGES);
    for pfn in 0..PAGES {
        // SAFETY: every page is free and allocation is quiesced; zeroing its
        // body models a cold restore image which omitted all free-page bytes.
        unsafe { core::ptr::write_bytes(pmm.page_ptr(Pfn(pfn)), 0, PAGE) };
    }
    let broken = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: test is single-threaded; failure is the RED proof that the
        // restored bitmap alone does not repair page-body list links.
        unsafe { pmm.audit() };
    }));
    assert!(broken.is_err(), "destroyed free-page links unexpectedly remained usable");
    pmm.hibernate_restore_free_lists();
    assert_eq!(pmm.free_pages(), PAGES);
    // SAFETY: reconstruction completed under the allocator owner.
    unsafe { pmm.audit() };
}
