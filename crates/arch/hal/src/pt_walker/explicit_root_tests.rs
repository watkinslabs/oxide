use super::*;

const TEST_VALID: u64 = 1;
const TEST_WRITE: u64 = 1 << 9;
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
