// The hosted stand-in page-table tree every walker case runs against: one
// architecture-shaped bit encoding, a static fake root, and the serialization
// that lets cases share it.

use super::super::*;

    use std::sync::Mutex;

    // Tests share the static fake-root tree; `cargo test` runs in
    // parallel by default. Serialize via this mutex.
    pub(super) static SERIAL: Mutex<()> = Mutex::new(());
    /// Test encoding bit marking a valid page-table entry.
    pub(super) const TEST_PTE_VALID: u64 = 1;
    /// Test encoding bit marking a huge/block entry or swap entry.
    pub(super) const TEST_PTE_BLOCK_OR_SWAP: u64 = 1 << 1;
    /// Shift of the swap kind field in the hosted test PTE encoding.
    pub(super) const TEST_SWAP_KIND_SHIFT: u8 = 2;
    /// Shift of the swap offset field in the hosted test PTE encoding.
    pub(super) const TEST_SWAP_OFFSET_SHIFT: u8 = 12;
    /// A software-only non-present bit distinct from the hosted swap shape.
    pub(super) const TEST_MIGRATION_MARKER: u64 = 1 << 11;
    /// Write permission in the hosted test PTE encoding.
    pub(super) const TEST_WRITE: u64 = 1 << 8;
    /// Hosted stand-in for the software userfaultfd write-protect marker.
    pub(super) const TEST_UFFD_WP: u64 = 1 << 10;
    /// Hosted stand-in for the non-present marker encoding: a kind bitfield
    /// above a bit that identifies the leaf as a marker.
    pub(super) const TEST_PTE_MARKER: u64 = 1 << 9;
    pub(super) const TEST_MARKER_KIND_SHIFT: u8 = 52;
    /// HHDM offset in a hosted synthetic page-table tree.
    pub(super) const TEST_HHDM_OFFSET: u64 = 0;
    /// Empty scalar stored in zero-initialized test page tables.
    pub(super) const TEST_EMPTY_PTE: u64 = 0;

    /// Hosted PtWalker stub — verifies the walk-driver loop end-to-
    /// end on a synthetic in-memory tree without privileged regs.
    pub(super) struct HostWalker;
    pub(super) static mut FAKE_ROOT: [u64; ENTRIES_PER_TABLE] = [0; ENTRIES_PER_TABLE];
    pub(super) static mut FAKE_FLUSH_COUNT: u32 = 0;

    /// HHDM offset = 0 for the host test (PA == VA on the in-process heap).
    impl PtWalker for HostWalker {
        const PHYS_MASK: u64 = 0xffff_ffff_ffff_f000;
        unsafe fn read_pt_base(_va: u64) -> u64 {
            // Hosted test; raw-ref-to-`static mut` needs no unsafe.
            (&raw mut FAKE_ROOT).cast::<u8>() as u64
        }
        unsafe fn flush_va(_va: u64) {
            // SAFETY: hosted test; mutate the test-only counter.
            unsafe { FAKE_FLUSH_COUNT += 1; }
        }
        fn is_valid(e: u64) -> bool { (e & 1) != 0 }
        fn is_huge_or_block(e: u64) -> bool { (e & 2) != 0 }
        fn pack_table(child_pa: u64) -> u64 { (child_pa & Self::PHYS_MASK) | 1 }
        fn pack_device_leaf(pa: u64) -> u64 { (pa & Self::PHYS_MASK) | 1 | 4 }
        fn pack_4k_leaf(pa: u64, _flags: crate::PageFlags) -> u64 {
            // Test stub: same shape as pack_device_leaf so the
            // walk loop sees a valid leaf; per-arch impls translate
            // PageFlags to real bits.
            (pa & Self::PHYS_MASK) | 1 | 4
        }
        fn pack_block_leaf(pa: u64, _flags: crate::PageFlags) -> u64 {
            // Test stub: bit 0 = valid, bit 1 = huge-or-block (so
            // `is_huge_or_block` returns true for translate/unmap
            // walks), bit 5 marks "this is a block/huge leaf"
            // distinct from the 4 KiB page leaf (bit 4).
            (pa & Self::PHYS_MASK) | 1 | 2 | 0x20
        }
        fn pack_swap_entry(entry: SwapEntry) -> u64 {
            TEST_PTE_BLOCK_OR_SWAP
                | ((entry.kind() as u64) << TEST_SWAP_KIND_SHIFT)
                | (entry.offset() << TEST_SWAP_OFFSET_SHIFT)
        }
        fn unpack_swap_entry(raw: u64) -> Option<SwapEntry> {
            if raw & TEST_PTE_VALID != TEST_EMPTY_PTE
                || raw & TEST_PTE_BLOCK_OR_SWAP == TEST_EMPTY_PTE
                || raw & TEST_MIGRATION_MARKER != TEST_EMPTY_PTE
            { return None; }
            SwapEntry::new(
                ((raw >> TEST_SWAP_KIND_SHIFT) & SwapEntry::MAX_KIND as u64) as u8,
                raw >> TEST_SWAP_OFFSET_SHIFT,
            )
        }
        fn pack_migration_entry(entry: MigrationEntry) -> u64 {
            TEST_MIGRATION_MARKER | (entry.token() << TEST_SWAP_OFFSET_SHIFT)
        }
        fn unpack_migration_entry(raw: u64) -> Option<MigrationEntry> {
            if raw & TEST_PTE_VALID != TEST_EMPTY_PTE || raw & TEST_MIGRATION_MARKER == TEST_EMPTY_PTE {
                return None;
            }
            MigrationEntry::new(raw >> TEST_SWAP_OFFSET_SHIFT)
        }
        fn leaf_wrprotect(raw: u64) -> u64 { raw & !TEST_WRITE }
        fn can_split_kernel_leaf() -> bool { true }
        fn split_child_leaf(block: u64, child_pa: u64, child_level: u8) -> u64 {
            // Mirrors the real impls' one structural obligation: a bottom-level
            // child must not still claim to be a block.
            let attrs = block & !Self::PHYS_MASK;
            let attrs = if child_level == 3 { attrs & !TEST_PTE_BLOCK_OR_SWAP } else { attrs };
            attrs | (child_pa & Self::PHYS_MASK)
        }
        fn publish_table_barrier() {}
        fn leaf_set_present(raw: u64, present: bool) -> u64 {
            if present { raw | TEST_PTE_VALID } else { raw & !TEST_PTE_VALID }
        }
        fn leaf_set_uffd_wp(raw: u64) -> u64 { raw | TEST_UFFD_WP }
        fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw & !TEST_UFFD_WP }
        fn leaf_is_uffd_wp(raw: u64) -> bool {
            raw & TEST_PTE_VALID != TEST_EMPTY_PTE && raw & TEST_UFFD_WP != TEST_EMPTY_PTE
        }
        fn nonpresent_set_uffd_wp(raw: u64) -> u64 { raw | TEST_UFFD_WP }
        fn nonpresent_clear_uffd_wp(raw: u64) -> u64 { raw & !TEST_UFFD_WP }
        fn nonpresent_is_uffd_wp(raw: u64) -> bool {
            raw & TEST_PTE_VALID == TEST_EMPTY_PTE && raw & TEST_UFFD_WP != TEST_EMPTY_PTE
        }
        fn pack_pte_marker(m: PteMarker) -> u64 {
            TEST_PTE_MARKER | ((m.bits() as u64) << TEST_MARKER_KIND_SHIFT)
        }
        fn unpack_pte_marker(raw: u64) -> Option<PteMarker> {
            if raw & TEST_PTE_VALID != TEST_EMPTY_PTE || raw & TEST_PTE_MARKER == TEST_EMPTY_PTE {
                return None;
            }
            PteMarker::from_bits(((raw >> TEST_MARKER_KIND_SHIFT) as u32) & PteMarker::MASK)
        }
    }

    /// 4 KiB-aligned wrapper so `Box::new(AlignedTable(_))` returns
    /// a heap allocation that satisfies `PHYS_MASK & addr == addr`.
    /// The default heap allocator doesn't guarantee 4 KiB alignment;
    /// without this wrapper the walker masks low bits off the pa
    /// stored in parent slots and reads garbage.
    #[repr(align(4096))]
    pub(super) struct AlignedTable(pub(super) [u64; ENTRIES_PER_TABLE]);

    /// Reset shared test state. Caller holds `SERIAL`.
    pub(super) fn reset() -> alloc::vec::Vec<alloc::boxed::Box<AlignedTable>> {
        // SAFETY: SERIAL held; no other test thread reads/writes these.
        unsafe { FAKE_ROOT = [0; ENTRIES_PER_TABLE]; FAKE_FLUSH_COUNT = 0; }
        alloc::vec::Vec::new()
    }
