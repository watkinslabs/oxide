use super::*;

const TEST_VALID: u64 = 1;
const TEST_WRITE: u64 = 1 << 9;
const TEST_UFFD_WP: u64 = 1 << 10;
const TEST_POISON: u64 = 1 << 12;
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
        (pa & Self::PHYS_MASK) | TEST_VALID | if flags.contains(crate::PageFlags::WRITE) { TEST_WRITE } else { 0 }
    }
    fn pack_block_leaf(pa: u64, flags: crate::PageFlags) -> u64 { Self::pack_4k_leaf(pa, flags) }
    fn pack_swap_entry(_: SwapEntry) -> u64 { 0 }
    fn unpack_swap_entry(_: u64) -> Option<SwapEntry> { None }
    fn leaf_wrprotect(raw: u64) -> u64 { raw & !TEST_WRITE }
    fn leaf_set_uffd_wp(raw: u64) -> u64 { raw | TEST_UFFD_WP }
    fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw & !TEST_UFFD_WP }
    fn leaf_is_uffd_wp(raw: u64) -> bool { raw & TEST_VALID != 0 && raw & TEST_UFFD_WP != 0 }
    fn pack_poison_marker() -> u64 { TEST_POISON }
    fn is_poison_marker(raw: u64) -> bool { raw & TEST_VALID == 0 && raw & TEST_POISON != 0 }
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
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker>(root_pa, TEST_VA, TEST_VA + page, true, 0) }, 1);
    // SAFETY: read-only walk of the live root.
    let leaf = unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap();
    assert_eq!(leaf & TEST_WRITE, 0, "protect must drop write permission");
    assert!(RootWalker::leaf_is_uffd_wp(leaf), "protect must set the marker");
    // SAFETY: same owned root; the resolve pass.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker>(root_pa, TEST_VA, TEST_VA + page, false, 0) }, 1);
    // SAFETY: read-only walk of the live root.
    let leaf = unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.unwrap();
    assert!(!RootWalker::leaf_is_uffd_wp(leaf), "resolve must clear the marker");
    assert_eq!(leaf & TEST_WRITE, 0, "resolve must NOT restore write permission");
}

/// An absent leaf carries no write permission to remove, so the walk must
/// report it as untouched rather than manufacturing an entry for it.
#[test]
fn uffd_wp_walk_skips_absent_leaves() {
    let mut root = alloc::boxed::Box::new(Table([0; ENTRIES_PER_TABLE]));
    let root_pa = root.0.as_mut_ptr() as u64;
    let page = 1u64 << L3_SHIFT;
    // SAFETY: the boxed root is live and has no populated tables.
    assert_eq!(unsafe { uffd_wp_range_at_root::<RootWalker>(root_pa, TEST_VA, TEST_VA + page, true, 0) }, 0);
    // SAFETY: read-only walk of the live root.
    assert!(unsafe { read_leaf_4k_at_root::<RootWalker>(root_pa, TEST_VA, 0) }.is_none());
}

/// The poison marker must be non-present and distinguishable from an absent
/// leaf, or a poisoned page would silently demand-fault into fresh zeroes.
#[test]
fn poison_marker_is_non_present_and_distinct_from_absent() {
    let marker = RootWalker::pack_poison_marker();
    assert!(!RootWalker::is_valid(marker));
    assert!(RootWalker::is_poison_marker(marker));
    assert!(!RootWalker::is_poison_marker(0), "an absent leaf is not poisoned");
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
