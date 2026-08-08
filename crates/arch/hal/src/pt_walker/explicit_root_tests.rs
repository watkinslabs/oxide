use super::*;

const TEST_VALID: u64 = 1;
const TEST_WRITE: u64 = 1 << 9;
const TEST_UFFD_WP: u64 = 1 << 10;
/// Hosted stand-in for the non-present marker encoding: a kind bitfield above
/// a bit that identifies the leaf as a marker.
const TEST_PTE_MARKER: u64 = 1 << 12;
const TEST_MARKER_KIND_SHIFT: u8 = 13;
/// Hosted stand-in for the non-present swap and migration encodings. Every
/// field is disjoint from the write, write-protect and marker bits, so the
/// same collision rule the architectures obey holds here.
const TEST_SWAP: u64 = 1 << 11;
const TEST_MIGRATION: u64 = 1 << 6;
const TEST_SWAP_KIND_SHIFT: u8 = 1;
const TEST_PAYLOAD_SHIFT: u8 = 16;
const TEST_VA: u64 = 0x0000_1234_5678_9000;
const TEST_PA: u64 = 0x0000_0000_dead_b000;

#[repr(align(4096))]
struct Table([u64; ENTRIES_PER_TABLE]);

struct RootWalker;

impl PtWalker for RootWalker {
    const PHYS_MASK: u64 = 0xffff_ffff_ffff_f000;
    unsafe fn read_pt_base(_: u64) -> u64 { 0 }
    unsafe fn flush_va(_: u64) {}
    fn is_valid(e: u64) -> bool { e & TEST_VALID != 0 }
    fn is_huge_or_block(_: u64) -> bool { false }
    fn pack_table(pa: u64) -> u64 { (pa & Self::PHYS_MASK) | TEST_VALID }
    fn pack_device_leaf(pa: u64) -> u64 { (pa & Self::PHYS_MASK) | TEST_VALID }
    fn pack_4k_leaf(pa: u64, flags: crate::PageFlags) -> u64 {
        let mut e = (pa & Self::PHYS_MASK) | TEST_VALID;
        if flags.contains(crate::PageFlags::UFFD_WP)   { e |= TEST_UFFD_WP; }
        else if flags.contains(crate::PageFlags::WRITE) { e |= TEST_WRITE; }
        e
    }
    fn pack_block_leaf(pa: u64, flags: crate::PageFlags) -> u64 { Self::pack_4k_leaf(pa, flags) }
    fn pack_swap_entry(e: SwapEntry) -> u64 {
        TEST_SWAP | ((e.kind() as u64) << TEST_SWAP_KIND_SHIFT) | (e.offset() << TEST_PAYLOAD_SHIFT)
    }
    fn unpack_swap_entry(raw: u64) -> Option<SwapEntry> {
        if raw & TEST_VALID != 0 || raw & TEST_SWAP == 0 { return None; }
        SwapEntry::new(((raw >> TEST_SWAP_KIND_SHIFT) & SwapEntry::MAX_KIND as u64) as u8,
                       (raw >> TEST_PAYLOAD_SHIFT) & SwapEntry::MAX_OFFSET)
    }
    fn pack_migration_entry(e: MigrationEntry) -> u64 {
        TEST_MIGRATION | (e.token() << TEST_PAYLOAD_SHIFT)
    }
    fn unpack_migration_entry(raw: u64) -> Option<MigrationEntry> {
        if raw & TEST_VALID != 0 || raw & TEST_MIGRATION == 0 { return None; }
        MigrationEntry::new((raw >> TEST_PAYLOAD_SHIFT) & MigrationEntry::MAX_TOKEN)
    }
    fn can_split_kernel_leaf() -> bool { true }
    fn split_child_leaf(block: u64, child_pa: u64, _child_level: u8) -> u64 {
        (block & !Self::PHYS_MASK) | (child_pa & Self::PHYS_MASK)
    }
    fn publish_table_barrier() {}
    fn leaf_set_present(raw: u64, present: bool) -> u64 {
        if present { raw | TEST_VALID } else { raw & !TEST_VALID }
    }
    fn leaf_wrprotect(raw: u64) -> u64 { raw & !TEST_WRITE }
    fn leaf_set_uffd_wp(raw: u64) -> u64 { raw | TEST_UFFD_WP }
    fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw & !TEST_UFFD_WP }
    fn leaf_is_uffd_wp(raw: u64) -> bool { raw & TEST_VALID != 0 && raw & TEST_UFFD_WP != 0 }
    fn nonpresent_set_uffd_wp(raw: u64) -> u64 { raw | TEST_UFFD_WP }
    fn nonpresent_clear_uffd_wp(raw: u64) -> u64 { raw & !TEST_UFFD_WP }
    fn nonpresent_is_uffd_wp(raw: u64) -> bool { raw & TEST_VALID == 0 && raw & TEST_UFFD_WP != 0 }
    fn pack_pte_marker(m: PteMarker) -> u64 {
        TEST_PTE_MARKER | ((m.bits() as u64) << TEST_MARKER_KIND_SHIFT)
    }
    fn unpack_pte_marker(raw: u64) -> Option<PteMarker> {
        if raw & TEST_VALID != 0 || raw & TEST_PTE_MARKER == 0 { return None; }
        PteMarker::from_bits(((raw >> TEST_MARKER_KIND_SHIFT) as u32) & PteMarker::MASK)
    }
}

/// The write-protect walk must take write permission away and leave the marker
/// the fault path keys on, and the resolve walk must clear the marker WITHOUT
/// handing write permission back — an unprotect that re-granted write would let
/// a monitor's resolve silently skip the fault that decides COW.
#[test]
fn uffd_wp_walk_drops_write_then_resolve_clears_marker_only() {
    let mut root = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
    let mut tables = alloc::vec::Vec::new();
    let mut alloc = || -> Option<u64> {
        let table = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
        let pa = table.0.as_ptr() as u64;
        tables.push(table);
        Some(pa)
    };
    let root_pa = root.0.as_mut_ptr() as u64;
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    // SAFETY: the boxed root and every child table live for the test.
    assert_eq!(unsafe { map_at_level_with_root::<RootWalker, _>(root_pa, TEST_VA, 3, RootWalker::pack_4k_leaf(TEST_PA, rw), 0, &mut alloc) }, Ok(()));
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the test owns the root and serializes the range rewrite.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
    // SAFETY: read-only walk of the live root.
    let leaf = unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap();
    assert_eq!(leaf & TEST_WRITE, 0, "protect must drop write permission");
    assert!(RootWalker::leaf_is_uffd_wp(leaf), "protect must set the marker");
    // SAFETY: same owned root; the resolve pass.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, false, true, 0, &mut alloc) }, 1);
    // SAFETY: read-only walk of the live root.
    let leaf = unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap();
    assert!(!RootWalker::leaf_is_uffd_wp(leaf), "resolve must clear the marker");
    assert_eq!(leaf & TEST_WRITE, 0, "resolve must NOT restore write permission");
}

/// Without the protection over unpopulated addresses, an absent leaf carries no
/// write permission to remove, so the walk reports it untouched rather than
/// manufacturing an entry for it.
#[test]
fn uffd_wp_walk_skips_absent_leaves_unless_markers_are_in_use() {
    let mut root = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
    let mut tables = alloc::vec::Vec::new();
    let mut alloc = || -> Option<u64> {
        let table = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
        let pa = table.0.as_ptr() as u64;
        tables.push(table);
        Some(pa)
    };
    let root_pa = root.0.as_mut_ptr() as u64;
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the boxed root is live and has no populated tables.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, false, 0, &mut alloc) }, 0);
    // SAFETY: read-only walk of the live root.
    assert!(unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.is_none());
}

/// With the protection extended over unpopulated addresses, the walk BUILDS the
/// tables the address never needed and leaves a marker there — that marker is
/// the only place the state can live when there is no page to carry it, and
/// without it a write to an untouched address escapes the barrier entirely.
#[test]
fn uffd_wp_walk_plants_a_marker_on_an_untouched_address_and_resolving_removes_it() {
    let mut root = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
    let mut tables = alloc::vec::Vec::new();
    let mut alloc = || -> Option<u64> {
        let table = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
        let pa = table.0.as_ptr() as u64;
        tables.push(table);
        Some(pa)
    };
    let root_pa = root.0.as_mut_ptr() as u64;
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the boxed root and every table the walk allocates live for the test.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
    // SAFETY: read-only walk of the live root.
    let leaf = unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap();
    assert!(RootWalker::is_uffd_wp_marker(leaf), "the address must now carry the marker");
    assert!(!RootWalker::is_valid(leaf), "and must still be non-present");
    // SAFETY: same owned root; the resolve pass.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, false, true, 0, &mut alloc) }, 1);
    // SAFETY: read-only walk of the live root.
    let leaf = unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap();
    assert_eq!(leaf, 0, "resolving must leave an ordinary hole, not a marker that means nothing");
}

/// A marker must be non-present and distinguishable from an absent leaf, or a
/// poisoned page would silently demand-fault into fresh zeroes.
#[test]
fn poison_marker_is_non_present_and_distinct_from_absent() {
    let marker = RootWalker::pack_poison_marker();
    assert!(!RootWalker::is_valid(marker));
    assert!(RootWalker::is_poison_marker(marker));
    assert!(!RootWalker::is_poison_marker(0), "an absent leaf is not poisoned");
    assert!(!RootWalker::is_poison_marker(RootWalker::pack_uffd_wp_marker()),
            "a write-protected hole is not a memory error");
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    assert!(!RootWalker::is_poison_marker(RootWalker::pack_4k_leaf(TEST_PA, rw)));
}

#[test]
fn explicit_root_permission_rewrite_does_not_touch_peer_root() {
    let mut root_a = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
    let mut root_b = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
    let mut tables = alloc::vec::Vec::new();
    let mut alloc = || -> Option<u64> {
        let table = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
        let pa = table.0.as_ptr() as u64;
        tables.push(table);
        Some(pa)
    };
    let a_pa = root_a.0.as_mut_ptr() as u64;
    let b_pa = root_b.0.as_mut_ptr() as u64;
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    // SAFETY: each boxed root and every allocated child table live for the test.
    assert_eq!(unsafe { map_at_level_with_root::<RootWalker, _>(a_pa, TEST_VA, 3, RootWalker::pack_4k_leaf(TEST_PA, rw), 0, &mut alloc) }, Ok(()));
    // SAFETY: the second boxed root is independent and live for the test.
    assert_eq!(unsafe { map_at_level_with_root::<RootWalker, _>(b_pa, TEST_VA, 3, RootWalker::pack_4k_leaf(TEST_PA, rw), 0, &mut alloc) }, Ok(()));
    let ro = crate::PageFlags::READ | crate::PageFlags::USER;
    // SAFETY: the test owns root B and serializes its exact-leaf rewrite.
    assert!(unsafe { replace_present_4k_flags_if_pa_at_root::<RootWalker>(b_pa, TEST_VA, TEST_PA, ro, 0) });
    // SAFETY: both roots remain live; these are read-only walks.
    let a_leaf = unsafe { translate_4k_at_root::<RootWalker>(a_pa, TEST_VA, 0) }.unwrap().1;
    // SAFETY: both roots remain live; these are read-only walks.
    let b_leaf = unsafe { translate_4k_at_root::<RootWalker>(b_pa, TEST_VA, 0) }.unwrap().1;
    assert_ne!(a_leaf & TEST_WRITE, 0, "peer root must retain writable leaf");
    assert_eq!(b_leaf & TEST_WRITE, 0, "target root must receive read-only leaf");
}

/// One boxed root plus every table a walk allocates, kept alive for a test.
struct Tree {
    root: alloc::boxed::Box<Table>,
    tables: alloc::vec::Vec<alloc::boxed::Box<Table>>,
}

impl Tree {
    fn new() -> Self {
        Self { root: alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE])), tables: alloc::vec::Vec::new() }
    }
    fn root_pa(&mut self) -> u64 { self.root.0.as_mut_ptr() as u64 }
    /// Map `TEST_VA` read-write and return the root.
    fn with_writable_page(&mut self) -> u64 {
        let root_pa = self.root_pa();
        let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
        let leaf = RootWalker::pack_4k_leaf(TEST_PA, rw);
        let mut alloc = || -> Option<u64> {
            let t = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
            let pa = t.0.as_ptr() as u64;
            self.tables.push(t);
            Some(pa)
        };
        // SAFETY: the boxed root and every child table live as long as this `Tree`.
        assert_eq!(unsafe { map_at_level_with_root::<RootWalker, _>(root_pa, TEST_VA, 3, leaf, 0, &mut alloc) }, Ok(()));
        root_pa
    }
    fn leaf(&mut self) -> u64 {
        let root_pa = self.root_pa();
        // SAFETY: read-only walk of a live, test-owned root.
        unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap()
    }
}

const TEST_SLOT: SwapEntry = match SwapEntry::new(3, 0x5150) { Some(e) => e, None => panic!() };

/// A write-protected page that gets RECLAIMED must come back write-protected.
///
/// This is the whole point of putting the state in the entry: eviction replaces
/// the leaf's permissions — where the barrier lived — with a slot reference, and
/// the fault that brings the page back builds a FRESH leaf from the mapping's
/// permissions, which are writable. Without the state riding on the swap entry
/// the barrier silently lapses, and the first write after a reclaim takes the
/// ordinary path instead of being reported to the monitor.
#[test]
fn a_write_protected_page_that_is_evicted_comes_back_write_protected() {
    let mut tree = Tree::new();
    let root_pa = tree.with_writable_page();
    let mut alloc = || -> Option<u64> { None };
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the test owns the root and serializes the range rewrite.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
    assert!(RootWalker::leaf_is_uffd_wp(tree.leaf()));

    // Evict: the present leaf becomes a slot reference.
    // SAFETY: the test owns the root and no other party walks it.
    let displaced = unsafe { replace_present_4k_with_swap_if_pa_at_root::<RootWalker>(root_pa, TEST_VA, TEST_PA, TEST_SLOT, 0) };
    assert!(displaced.is_some(), "the exact resident page must be the one evicted");
    let swapped = tree.leaf();
    assert_eq!(RootWalker::unpack_swap_entry(swapped), Some(TEST_SLOT), "the slot reference must be intact");
    assert!(RootWalker::nonpresent_is_uffd_wp(swapped), "eviction must not disarm the barrier");

    // Fault it back in from the mapping's own (writable) permissions.
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    // SAFETY: the test owns the root; the helper checks the exact entry first.
    assert!(unsafe { replace_swap_4k_with_present_at_root::<RootWalker>(root_pa, TEST_VA, TEST_SLOT, TEST_PA, rw, 0) });
    let restored = tree.leaf();
    assert!(RootWalker::is_valid(restored));
    assert!(RootWalker::leaf_is_uffd_wp(restored), "the barrier must survive the round trip");
    assert_eq!(restored & TEST_WRITE, 0, "and the page it comes back as must not be writable");
}

/// A page evicted while UNPROTECTED must come back writable. The carry has to be
/// conditional, or every reclaimed page would return protected and every write
/// would fault into a monitor that armed nothing.
#[test]
fn a_page_evicted_without_a_barrier_comes_back_writable() {
    let mut tree = Tree::new();
    let root_pa = tree.with_writable_page();
    // SAFETY: the test owns the root and no other party walks it.
    assert!(unsafe { replace_present_4k_with_swap_if_pa_at_root::<RootWalker>(root_pa, TEST_VA, TEST_PA, TEST_SLOT, 0) }.is_some());
    assert!(!RootWalker::nonpresent_is_uffd_wp(tree.leaf()));
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    // SAFETY: the test owns the root; the helper checks the exact entry first.
    assert!(unsafe { replace_swap_4k_with_present_at_root::<RootWalker>(root_pa, TEST_VA, TEST_SLOT, TEST_PA, rw, 0) });
    let restored = tree.leaf();
    assert!(!RootWalker::leaf_is_uffd_wp(restored));
    assert_ne!(restored & TEST_WRITE, 0, "an unprotected page must return writable");
}

/// Arming a range whose page is ALREADY out in swap must reach the entry, and
/// resolving must put it back exactly as it was. Without this the barrier can
/// only ever be armed over pages that happen to be resident at the time.
#[test]
fn arming_a_range_reaches_a_page_that_is_already_out_in_swap() {
    let mut tree = Tree::new();
    let root_pa = tree.with_writable_page();
    // SAFETY: the test owns the root and no other party walks it.
    assert!(unsafe { replace_present_4k_with_swap_if_pa_at_root::<RootWalker>(root_pa, TEST_VA, TEST_PA, TEST_SLOT, 0) }.is_some());
    let bare = tree.leaf();
    let mut alloc = || -> Option<u64> { None };
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the test owns the root and serializes the range rewrite.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
    assert!(RootWalker::nonpresent_is_uffd_wp(tree.leaf()));
    assert_eq!(RootWalker::unpack_swap_entry(tree.leaf()), Some(TEST_SLOT));
    // SAFETY: same owned root; the resolve pass.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, false, true, 0, &mut alloc) }, 1);
    assert_eq!(tree.leaf(), bare, "resolving must restore the exact entry it armed");
}

/// Tearing a mapping down must release the slot behind a PROTECTED swap leaf too.
/// The clear is keyed on the entry's identity, and comparing the raw word instead
/// would refuse exactly the protected entries — leaking their slots.
#[test]
fn tearing_down_a_protected_swap_leaf_still_releases_its_slot() {
    let mut tree = Tree::new();
    let root_pa = tree.with_writable_page();
    // SAFETY: the test owns the root and no other party walks it.
    assert!(unsafe { replace_present_4k_with_swap_if_pa_at_root::<RootWalker>(root_pa, TEST_VA, TEST_PA, TEST_SLOT, 0) }.is_some());
    let mut alloc = || -> Option<u64> { None };
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the test owns the root and serializes the range rewrite.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
    // SAFETY: the test owns the root; the helper checks the exact entry first.
    assert!(unsafe { clear_swap_4k_at_root::<RootWalker>(root_pa, TEST_VA, TEST_SLOT, 0) },
            "a protected swap leaf must still be recognised as its own entry");
    assert_eq!(tree.leaf(), 0);
}

/// A protection rewrite changes permissions; it does not decide whether a
/// monitor is watching. Page-out write-protects its source through this helper
/// before copying it, so losing the barrier here would disarm every page the
/// reclaimer touches — before the eviction that was supposed to carry it.
#[test]
fn a_protection_rewrite_keeps_the_barrier_the_leaf_already_carried() {
    let mut tree = Tree::new();
    let root_pa = tree.with_writable_page();
    let mut alloc = || -> Option<u64> { None };
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the test owns the root and serializes the range rewrite.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
    let ro = crate::PageFlags::READ | crate::PageFlags::USER;
    // SAFETY: the test owns the root and serializes its exact-leaf rewrite.
    assert!(unsafe { replace_present_4k_flags_if_pa_at_root::<RootWalker>(root_pa, TEST_VA, TEST_PA, ro, 0) });
    assert!(RootWalker::leaf_is_uffd_wp(tree.leaf()), "a permission rewrite must not disarm the page");
}

/// A page in transit is a page that is elsewhere, so it carries the barrier the
/// same way a swapped-out page does — including across the commit that turns a
/// migration into a swap slot, and the rollback that brings it back resident.
#[test]
fn a_page_in_transit_carries_the_barrier_through_every_migration_outcome() {
    let token = MigrationEntry::new(0x1234).expect("representable migration entry");
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    let page = 1u64 << L3_SHIFT;
    for commit_to_swap in [false, true] {
        let mut tree = Tree::new();
        let root_pa = tree.with_writable_page();
        let mut alloc = || -> Option<u64> { None };
        // SAFETY: the test owns the root and serializes the range rewrite.
        assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker, _>(root_pa, TEST_VA, TEST_VA + page, true, true, 0, &mut alloc) }, 1);
        // SAFETY: the test owns the root and no other party walks it.
        assert!(unsafe { replace_present_4k_with_migration_if_pa_at_root::<RootWalker>(root_pa, TEST_VA, TEST_PA, token, 0) });
        assert!(RootWalker::nonpresent_is_uffd_wp(tree.leaf()), "the move must not disarm the barrier");
        if commit_to_swap {
            // SAFETY: the test owns the root; the helper checks the exact marker first.
            assert!(unsafe { replace_migration_4k_with_swap_at_root::<RootWalker>(root_pa, TEST_VA, token, TEST_SLOT, 0) });
            assert!(RootWalker::nonpresent_is_uffd_wp(tree.leaf()));
            assert_eq!(RootWalker::unpack_swap_entry(tree.leaf()), Some(TEST_SLOT));
        } else {
            // SAFETY: the test owns the root; the helper checks the exact marker first.
            assert!(unsafe { replace_migration_4k_with_present_at_root::<RootWalker>(root_pa, TEST_VA, token, TEST_PA, rw, 0) });
            assert!(RootWalker::leaf_is_uffd_wp(tree.leaf()), "the page must come back protected");
            assert_eq!(tree.leaf() & TEST_WRITE, 0);
        }
    }
}

/// The barrier and write permission are ONE fact at pack time: asking for the
/// barrier produces a leaf that is already unwritable. That is what lets a fill
/// publish a protected page in the single store that makes it visible, instead
/// of installing it writable and re-protecting it afterwards — a window in which
/// a peer thread's write escapes the barrier exactly once.
#[test]
fn a_leaf_asked_for_protected_is_built_protected_not_protected_afterwards() {
    let rw = crate::PageFlags::READ | crate::PageFlags::WRITE | crate::PageFlags::USER;
    let built = RootWalker::pack_4k_leaf(TEST_PA, rw | crate::PageFlags::UFFD_WP);
    assert!(RootWalker::is_valid(built), "the page is present the moment it is published");
    assert!(RootWalker::leaf_is_uffd_wp(built), "and already carries the barrier");
    assert_eq!(built & TEST_WRITE, 0, "and is not writable for any window at all");
    // Identical to arming a writable leaf after the fact — same destination,
    // reached without ever publishing the writable one.
    assert_eq!(built, RootWalker::leaf_set_uffd_wp(RootWalker::leaf_wrprotect(
        RootWalker::pack_4k_leaf(TEST_PA, rw))));
}
