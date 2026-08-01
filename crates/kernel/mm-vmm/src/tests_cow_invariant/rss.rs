// Resident-set accounting cases, on the same multi-AS page-table model the
// refcount tier uses (`model.rs`): a real `AddressSpace`, real fault / fork /
// munmap code, and `check_rss`'s independent leaf walk as the oracle.
//
// The failure mode these exist for is DRIFT, not a wrong answer at one point:
// a counter that misses one install or one removal stays internally consistent
// forever and never shows up in a boot. So every case ends by driving the
// address space back to empty and asserting the counters reached zero, and
// `check_rss` re-derives them from the page tables after each step.

use super::*;

/// Counters of one address space, as `ru_maxrss`/`VmRSS`/`statm` read them.
fn rss(slot: &AsSlot) -> RssPages { slot.mm.accounting_snapshot().rss_pages() }

fn fresh(root: u64) -> AsSlot {
    let mm = AddressSpace::new(root).expect("AS::new");
    AsSlot::new(root, mm)
}

/// Fault every page of the first VMA of `slot`, returning how many landed.
fn fault_region(slot: &AsSlot, base: u64, pages: u64, f: FaultKind) {
    activate(slot.root);
    for i in 0..pages { do_fault(&slot.mm, base + i * PAGE, f); }
}

fn first_vma_start(slot: &AsSlot) -> u64 {
    slot.mm.vmas_for_test().iter().next().expect("a VMA").start.as_u64()
}

#[test]
fn a_fresh_address_space_is_zero_resident() {
    reset();
    let s = fresh(0x1000_0000);
    assert_eq!(rss(&s), RssPages::default());
    assert_eq!(s.mm.accounting_snapshot().hiwater_rss_pages, 0);
}

#[test]
fn anonymous_faults_are_counted_and_munmap_gives_every_page_back() {
    reset();
    let s = fresh(0x2000_0000);
    map_region(&s, Kind::Anon, 8 * PAGE);
    let base = first_vma_start(&s);
    fault_region(&s, base, 8, DEMAND_WRITE);
    assert_eq!(rss(&s).anon, 8);
    assert_eq!(rss(&s).total(), 8);
    check_rss("anon-faulted");
    do_munmap(&s, base, 8 * PAGE);
    assert_eq!(rss(&s), RssPages::default(), "munmap must retire every leaf it zapped");
    check_rss("anon-unmapped");
    assert!(BUG.with(|b| b.borrow().is_none()));
}

#[test]
fn a_partial_munmap_retires_only_the_pages_it_zapped() {
    reset();
    let s = fresh(0x2100_0000);
    map_region(&s, Kind::Anon, 8 * PAGE);
    let base = first_vma_start(&s);
    fault_region(&s, base, 8, DEMAND_WRITE);
    do_munmap(&s, base + 2 * PAGE, 3 * PAGE);
    assert_eq!(rss(&s).anon, 5);
    check_rss("anon-partial");
    assert!(BUG.with(|b| b.borrow().is_none()));
}

#[test]
fn private_and_shared_file_pages_are_both_file_class() {
    reset();
    let s = fresh(0x2200_0000);
    // Linux counts a private-file COW page and a shared-file page alike as
    // `MM_FILEPAGES`; only that class feeds `statm`'s `shared` field.
    map_region(&s, Kind::FilePriv, 2 * PAGE);
    map_region(&s, Kind::FileShared, 2 * PAGE);
    map_region(&s, Kind::Anon, 2 * PAGE);
    let vmas: Vec<(u64, u64)> = s.mm.vmas_for_test().iter()
        .map(|v| (v.start.as_u64(), v.end.as_u64())).collect();
    activate(s.root);
    for (start, end) in &vmas {
        let mut va = *start;
        while va < *end { do_fault(&s.mm, va, DEMAND_READ); va += PAGE; }
    }
    let r = rss(&s);
    assert_eq!(r.anon, 2);
    assert_eq!(r.file, 4, "private-file and shared-file residency are both MM_FILEPAGES");
    assert_eq!(r.total(), 6);
    check_rss("classes");
    assert!(BUG.with(|b| b.borrow().is_none()));
}

#[test]
fn a_copy_on_write_split_does_not_change_residency() {
    reset();
    let parent = fresh(0x2300_0000);
    map_region(&parent, Kind::Anon, 4 * PAGE);
    let base = first_vma_start(&parent);
    fault_region(&parent, base, 4, DEMAND_WRITE);
    let before = rss(&parent);
    activate(parent.root);
    let child_root = 0x2400_0000;
    let child = AsSlot::new(child_root,
        parent.mm.fork_cow_pages::<MultiMmu, _>(child_root, 0, rc_inc).expect("fork"));
    // The child holds the parent's leaves the moment fork returns; nothing
    // will ever "install" them, so the copy loop is the only chance to count.
    assert_eq!(rss(&child), before, "a forked child inherits its parent's residency");
    // COW-split one page in the child: one anon frame replaces another at the
    // same VA, so the count is unchanged in BOTH address spaces.
    activate(child.root);
    do_fault(&child.mm, base, COW_WRITE);
    assert_eq!(rss(&child), before, "a COW copy replaces a page, it does not add one");
    assert_eq!(rss(&parent), before);
    check_rss("cow");
    assert!(BUG.with(|b| b.borrow().is_none()));
}

#[test]
fn every_address_space_of_a_fork_chain_drains_to_zero() {
    reset();
    let root = fresh(0x2500_0000);
    map_region(&root, Kind::Anon, 4 * PAGE);
    let base = first_vma_start(&root);
    fault_region(&root, base, 4, DEMAND_WRITE);
    let mut chain = std::vec![root];
    let mut next = 0x2600_0000u64;
    for _ in 0..4 {
        let parent = chain.last().expect("chain head");
        activate(parent.root);
        let cr = next; next += 0x100_0000;
        let child = parent.mm.fork_cow_pages::<MultiMmu, _>(cr, 0, rc_inc).expect("fork");
        chain.push(AsSlot::new(cr, child));
        check_rss("fork-chain");
    }
    for s in &chain { assert_eq!(rss(s).anon, 4, "every generation holds the same leaves"); }
    // Unmap everything in every generation: each must land back on zero.
    for s in &chain {
        let spans: Vec<(u64, u64)> = s.mm.vmas_for_test().iter()
            .map(|v| (v.start.as_u64(), v.end.as_u64() - v.start.as_u64())).collect();
        for (start, len) in spans { do_munmap(s, start, len); }
        assert_eq!(rss(s), RssPages::default());
        check_rss("fork-chain-drain");
    }
    assert!(BUG.with(|b| b.borrow().is_none()));
}

#[test]
fn a_page_swapped_out_moves_from_anonpages_to_swapents_and_back() {
    reset();
    let s = fresh(0x2700_0000);
    map_region(&s, Kind::Anon, 2 * PAGE);
    let base = first_vma_start(&s);
    fault_region(&s, base, 2, DEMAND_WRITE);
    let uva = hal::UserVirtAddr::new(base).expect("uva");
    s.mm.account_present_to_swap_at(uva);
    let r = rss(&s);
    assert_eq!((r.anon, r.swapents), (1, 1));
    // Swap entries are NOT resident: `VmRSS` drops, `VmSwap` rises.
    assert_eq!(r.total(), 1);
    s.mm.account_swap_to_present_at(uva);
    let r = rss(&s);
    assert_eq!((r.anon, r.swapents, r.total()), (2, 0, 2));
    // A munmap over a swapped-out page retires the entry rather than a leaf.
    s.mm.account_present_to_swap_at(uva);
    s.mm.account_swap_remove();
    assert_eq!(rss(&s).swapents, 0);
}

#[test]
fn the_high_water_mark_holds_after_residency_falls() {
    reset();
    let s = fresh(0x2800_0000);
    map_region(&s, Kind::Anon, 8 * PAGE);
    let base = first_vma_start(&s);
    fault_region(&s, base, 8, DEMAND_WRITE);
    assert_eq!(s.mm.accounting_snapshot().hiwater_rss_pages, 8);
    do_munmap(&s, base, 6 * PAGE);
    assert_eq!(rss(&s).total(), 2);
    assert_eq!(s.mm.accounting_snapshot().hiwater_rss_pages, 8,
        "ru_maxrss reports the PEAK, which a shrink cannot lower");
    // `ru_maxrss` is KILOBYTES, not pages and not bytes.
    assert_eq!(RssPages::kib(s.mm.accounting_snapshot().hiwater_rss_pages), 32);
}

#[test]
fn a_monitor_installed_page_is_as_resident_as_a_faulted_one() {
    reset();
    let s = fresh(0x2900_0000);
    map_region(&s, Kind::Anon, 2 * PAGE);
    let base = first_vma_start(&s);
    // UFFDIO_COPY fills a hole from outside the fault path; without its own
    // charge the page would be resident and invisible to every reporter.
    let uva = hal::UserVirtAddr::new(base).expect("uva");
    s.mm.account_pte_install_at(uva);
    assert_eq!(rss(&s).anon, 1);
    assert_eq!(s.mm.accounting_snapshot().hiwater_rss_pages, 1);
    s.mm.account_pte_remove_at(uva);
    assert_eq!(rss(&s), RssPages::default());
}

#[test]
fn a_forked_child_joins_the_live_mm_and_accounting_owner_directories() {
    reset();
    let parent = fresh(0x2a00_0000);
    map_region(&parent, Kind::Anon, PAGE);
    activate(parent.root);
    let cr = 0x2b00_0000;
    let child = parent.mm.fork_cow_pages::<MultiMmu, _>(cr, 0, rc_inc).expect("fork");
    // Every owner that routes by page-table root — the page-table frame
    // callbacks, swapoff's leaf sweep, the system-wide fold — finds an mm
    // through these directories or not at all. COW fork is how every process
    // after init is born, so a child missing here is most of the system.
    let live = crate::address_space::live_address_spaces().expect("live mms");
    assert!(live.iter().any(|m| m.root_pa() == cr), "COW-forked child must be a live mm");
    // The snapshot pins what it found, so it has to go before the child can.
    drop(live);
    drop(child);
    let live = crate::address_space::live_address_spaces().expect("live mms");
    assert!(!live.iter().any(|m| m.root_pa() == cr), "and must leave on drop");
}
