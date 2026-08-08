// Kernel-linear-map leaf split: turn a block leaf covering `va` into a table
// of smaller leaves, repeatedly, until a bottom-level 4 KiB leaf exists.
//
// The linear map is built from the largest blocks that fit because that is what
// keeps its translations nearly free. Removing ONE page from it — which is the
// entire contract of a secret memory mapping — therefore needs the block
// covering that page broken down first, on demand, exactly at the address the
// caller named. Nothing collapses it back: a split region stays split, so a
// second request in the same block costs one walk and no allocation.
//
// A split changes granularity only. Every child carries the parent's output
// address for its own slot and the parent's attributes verbatim, so no CPU can
// observe a permission or memory-type change through this path — which is also
// what makes the transient window in which a TLB may hold both granularities
// harmless on an architecture that tolerates it at all
// (`PtWalker::can_split_kernel_leaf`).

use core::ptr;

use super::{PtWalker, WalkErr, ENTRIES_PER_TABLE, L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT, TABLE_IDX_MASK};

/// Level indices of the shared four-level walk, top first.
const SHIFTS: [u32; 4] = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
/// Bottom (4 KiB) level.
pub const LEAF_LEVEL_4K: u8 = 3;
/// Highest level at which a block leaf is legal on either architecture. A leaf
/// at the root level would span 512 GiB and neither architecture maps one.
pub const TOP_SPLITTABLE_LEVEL: u8 = 1;

/// What the walk must do with the entry found at `level`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SplitStep {
    /// Nothing is mapped here; there is no block to break down.
    Absent,
    /// Ordinary table entry — descend.
    Descend,
    /// Block leaf that must become a table of `level + 1` leaves.
    SplitTo(u8),
    /// The walk already reached a bottom-level leaf.
    Done,
}

/// Decide the walk's next move from the entry's observable properties alone.
/// Split policy lives here, ungated and independent of any live page table, so
/// the decision is checkable without one.
/// # C: O(1)
pub const fn split_step(level: u8, valid: bool, block: bool) -> SplitStep {
    if !valid { return SplitStep::Absent; }
    if level >= LEAF_LEVEL_4K { return SplitStep::Done; }
    // A block claim at the root level is not representable on either
    // architecture; treat the entry as the table it must be.
    if block && level >= TOP_SPLITTABLE_LEVEL { return SplitStep::SplitTo(level + 1); }
    SplitStep::Descend
}

/// Bytes one leaf at `level` spans.
/// # C: O(1)
pub const fn level_span_bytes(level: u8) -> u64 { 1u64 << SHIFTS[level as usize] }

/// Output address of the block leaf found at `level`, with any attribute bit
/// that shares the descriptor's address field masked away. A block's address
/// field is narrower than the bottom-level one, and the bits that fall out of
/// it are attributes, not address — reading them as address would give every
/// child a bogus base.
/// # C: O(1)
pub const fn block_output_pa(raw_pa: u64, level: u8) -> u64 {
    raw_pa & !(level_span_bytes(level) - 1)
}

/// Output address of child slot `slot` of a block at `level`.
/// # C: O(1)
pub const fn child_output_pa(block_pa: u64, level: u8, slot: usize) -> u64 {
    block_pa + (slot as u64) * level_span_bytes(level + 1)
}

/// Break every block leaf on the walk to `va` in the tree rooted at `root_pa`
/// down to a bottom-level 4 KiB leaf. Returns `Ok(())` when a 4 KiB leaf exists
/// afterwards OR when nothing is mapped at `va` — an absent range has no
/// granularity to change, which is not an error.
///
/// `Err(HitHugeOrBlock)` means this architecture refuses to re-granularise a
/// live kernel mapping at all; `Err(AllocFailed)` means a child table could not
/// be allocated and the tree is left exactly as it was found.
///
/// Idempotent, and safe to lose a race against a peer performing the same
/// split: a caller that finds the entry already a table simply descends.
///
/// # SAFETY: caller asserts (a) `root_pa` is a live page-table root, (b) HHDM
/// covers page-table memory, (c) `alloc_pa` yields fresh kernel-owned 4 KiB
/// frames, and (d) the linear-map serialization lock is held, so no peer is
/// mutating the same entries.
/// # C: O(walk depth * entries per table)
/// # Ctx: under the kernel page-attribute lock
pub unsafe fn split_kernel_leaf_at_root<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64, va: u64, hhdm_offset: u64, mut alloc_pa: F,
) -> Result<(), WalkErr> {
    if !W::can_split_kernel_leaf() { return Err(WalkErr::HitHugeOrBlock); }
    let mut current_pa = root_pa;
    let mut level = 0u8;
    while level < LEAF_LEVEL_4K {
        let idx = ((va >> SHIFTS[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: `current_pa` is a 4 KiB-aligned table reached through the
        // caller-asserted live root; HHDM maps it; the page-attribute lock the
        // caller holds makes this slot exclusively ours for the read-modify.
        let slot = unsafe { ((hhdm_offset.wrapping_add(current_pa)) as *mut u64).add(idx) };
        // SAFETY: same slot pointer, just established as a live table entry.
        let entry = unsafe { ptr::read_volatile(slot) };
        match split_step(level, W::is_valid(entry), W::is_huge_or_block(entry)) {
            SplitStep::Absent => return Ok(()),
            SplitStep::Done => return Ok(()),
            SplitStep::Descend => { current_pa = entry & W::PHYS_MASK; level += 1; }
            SplitStep::SplitTo(child_level) => {
                let table_pa = alloc_pa().ok_or(WalkErr::AllocFailed)?;
                let block_pa = block_output_pa(entry & W::PHYS_MASK, level);
                // SAFETY: `table_pa` is a fresh kernel-owned frame reachable
                // through HHDM and not yet published, so nothing else can read
                // it while it is being filled.
                unsafe {
                    let child = (hhdm_offset.wrapping_add(table_pa)) as *mut u64;
                    for k in 0..ENTRIES_PER_TABLE {
                        let pa = child_output_pa(block_pa, level, k);
                        ptr::write_volatile(child.add(k), W::split_child_leaf(entry, pa, child_level));
                    }
                }
                // Every child must be visible to a hardware walker before the
                // entry pointing at them is; otherwise a peer walks a table of
                // uninitialised entries.
                W::publish_table_barrier();
                // SAFETY: exclusive under the caller's lock; the replacement
                // describes the same output addresses and attributes.
                unsafe { ptr::write_volatile(slot, W::pack_table(table_pa)); }
                // SAFETY: privileged local invalidate of the split address.
                unsafe { W::flush_va(va); }
                current_pa = table_pa;
                level = child_level;
            }
        }
    }
    Ok(())
}

/// Rewrite the bottom-level leaf mapping `va` so it does or does not translate,
/// preserving its output address and attributes. Returns `false` when no
/// bottom-level leaf covers `va` — the caller must split first.
///
/// No TLB invalidation beyond this CPU: the caller decides when the change has
/// to be visible everywhere, because a caller that is about to publish the page
/// elsewhere batches one range flush after the rewrite rather than paying a
/// cross-CPU round trip per page.
///
/// # SAFETY: same contract as [`split_kernel_leaf_at_root`].
/// # C: O(walk depth)
/// # Ctx: under the kernel page-attribute lock
pub unsafe fn set_leaf_present_at_root<W: PtWalker>(
    root_pa: u64, va: u64, present: bool, hhdm_offset: u64,
) -> bool {
    let mut current_pa = root_pa;
    for level in 0..=LEAF_LEVEL_4K {
        let idx = ((va >> SHIFTS[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: live root plus HHDM-mapped tables per the fn contract.
        let slot = unsafe { ((hhdm_offset.wrapping_add(current_pa)) as *mut u64).add(idx) };
        // SAFETY: as above.
        let entry = unsafe { ptr::read_volatile(slot) };
        if level == LEAF_LEVEL_4K {
            // A leaf that already translates is `is_valid`; one this function
            // previously cleared is not, and must still be found by its slot.
            // SAFETY: exclusive under the caller's lock.
            unsafe { ptr::write_volatile(slot, W::leaf_set_present(entry, present)); }
            // SAFETY: privileged local invalidate.
            unsafe { W::flush_va(va); }
            return true;
        }
        if !W::is_valid(entry) || W::is_huge_or_block(entry) { return false; }
        current_pa = entry & W::PHYS_MASK;
    }
    false
}

/// Whether the bottom-level leaf mapping `va` currently translates. A missing
/// or block-level entry answers `true`: the linear map still reaches the page
/// through it, which is precisely what the caller is asking about.
/// # SAFETY: HHDM covers page-table memory; `root_pa` is a live root.
/// # C: O(walk depth)
pub unsafe fn leaf_present_at_root<W: PtWalker>(root_pa: u64, va: u64, hhdm_offset: u64) -> bool {
    let mut current_pa = root_pa;
    for level in 0..=LEAF_LEVEL_4K {
        let idx = ((va >> SHIFTS[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: read-only walk of HHDM-mapped tables per the fn contract.
        let entry = unsafe { ptr::read_volatile(((hhdm_offset.wrapping_add(current_pa)) as *const u64).add(idx)) };
        if level == LEAF_LEVEL_4K { return W::is_valid(entry); }
        if !W::is_valid(entry) { return false; }
        if W::is_huge_or_block(entry) { return true; }
        current_pa = entry & W::PHYS_MASK;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::alloc::boxed::Box;
    use super::super::alloc::vec::Vec;

    const T_VALID: u64 = 1;
    const T_BLOCK: u64 = 1 << 1;
    /// Stands in for an attribute that must survive a split unchanged.
    const T_ATTR: u64 = 1 << 5;

    #[repr(align(4096))]
    struct Table([u64; ENTRIES_PER_TABLE]);

    struct SplitWalker;

    impl PtWalker for SplitWalker {
        const PHYS_MASK: u64 = 0xffff_ffff_ffff_f000;
        unsafe fn read_pt_base(_: u64) -> u64 { 0 }
        unsafe fn flush_va(_: u64) {}
        fn is_valid(e: u64) -> bool { e & T_VALID != 0 }
        fn is_huge_or_block(e: u64) -> bool { e & T_BLOCK != 0 }
        fn pack_table(pa: u64) -> u64 { (pa & Self::PHYS_MASK) | T_VALID }
        fn pack_device_leaf(pa: u64) -> u64 { (pa & Self::PHYS_MASK) | T_VALID }
        fn pack_4k_leaf(pa: u64, _f: crate::PageFlags) -> u64 { (pa & Self::PHYS_MASK) | T_VALID }
        fn pack_block_leaf(pa: u64, _f: crate::PageFlags) -> u64 {
            (pa & Self::PHYS_MASK) | T_VALID | T_BLOCK | T_ATTR
        }
        fn pack_swap_entry(_: super::super::SwapEntry) -> u64 { 0 }
        fn unpack_swap_entry(_: u64) -> Option<super::super::SwapEntry> { None }
        fn can_split_kernel_leaf() -> bool { true }
        fn split_child_leaf(block: u64, child_pa: u64, child_level: u8) -> u64 {
            let attrs = block & !Self::PHYS_MASK;
            let attrs = if child_level == LEAF_LEVEL_4K { attrs & !T_BLOCK } else { attrs };
            attrs | (child_pa & Self::PHYS_MASK)
        }
        fn publish_table_barrier() {}
        fn leaf_set_present(raw: u64, present: bool) -> u64 {
            if present { raw | T_VALID } else { raw & !T_VALID }
        }
        fn leaf_wrprotect(raw: u64) -> u64 { raw }
        fn leaf_set_uffd_wp(raw: u64) -> u64 { raw }
        fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw }
        fn leaf_is_uffd_wp(_: u64) -> bool { false }
        fn pack_poison_marker() -> u64 { 0 }
        fn is_poison_marker(_: u64) -> bool { false }
    }

    /// A tree whose root points at one block leaf covering `va`, mirroring a
    /// linear map built from the largest blocks that fit.
    struct Tree { root_pa: u64, _root: Box<Table>, _l1: Box<Table>, tables: Vec<Box<Table>> }

    fn block_tree(va: u64, block_pa: u64) -> Tree {
        let mut l1 = Box::new(Table([0; ENTRIES_PER_TABLE]));
        let mut root = Box::new(Table([0; ENTRIES_PER_TABLE]));
        let i1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
        let i0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
        l1.0[i1] = SplitWalker::pack_block_leaf(block_pa, crate::PageFlags::READ);
        let l1_pa = l1.0.as_mut_ptr() as u64;
        root.0[i0] = SplitWalker::pack_table(l1_pa);
        let root_pa = root.0.as_mut_ptr() as u64;
        Tree { root_pa, _root: root, _l1: l1, tables: Vec::new() }
    }

    fn allocator(tables: &mut Vec<Box<Table>>) -> impl FnMut() -> Option<u64> + '_ {
        move || {
            let t = Box::new(Table([0; ENTRIES_PER_TABLE]));
            let pa = t.0.as_ptr() as u64;
            tables.push(t);
            Some(pa)
        }
    }

    /// A block covering the address becomes a bottom-level leaf that translates
    /// the SAME address with the SAME attributes — the whole safety argument for
    /// doing this to a live mapping.
    #[test]
    fn split_reaches_bottom_level_preserving_address_and_attributes() {
        let va = (5u64 << L1_SHIFT) | (7 << L2_SHIFT) | (9 << L3_SHIFT);
        let block_pa = 5u64 << L1_SHIFT;
        let mut tree = block_tree(va, block_pa);
        let root_pa = tree.root_pa;
        let mut tables = core::mem::take(&mut tree.tables);
        // SAFETY: hosted synthetic tree owned by this test; HHDM offset 0 makes
        // physical and virtual addresses identical on the host heap.
        let r = unsafe { split_kernel_leaf_at_root::<SplitWalker, _>(root_pa, va, 0, allocator(&mut tables)) };
        assert_eq!(r, Ok(()));
        // SAFETY: same owned tree.
        assert!(unsafe { leaf_present_at_root::<SplitWalker>(root_pa, va, 0) });
        let expect_pa = block_pa + (7 << L2_SHIFT) + (9 << L3_SHIFT);
        // SAFETY: read-only walk of the owned tree.
        let leaf = unsafe { read_bottom_leaf(root_pa, va) };
        assert_eq!(leaf & SplitWalker::PHYS_MASK, expect_pa, "split must not move the translation");
        assert_ne!(leaf & T_ATTR, 0, "split must carry the block's attributes down");
        assert_eq!(leaf & T_BLOCK, 0, "a bottom-level leaf must not claim to be a block");
        tree.tables = tables;
    }

    /// SAFETY: `root_pa` is a hosted tree owned by the calling test.
    unsafe fn read_bottom_leaf(root_pa: u64, va: u64) -> u64 {
        let mut pa = root_pa;
        for level in 0..=LEAF_LEVEL_4K {
            let idx = ((va >> SHIFTS[level as usize]) & TABLE_IDX_MASK) as usize;
            // SAFETY: per fn contract; read-only.
            let e = unsafe { ptr::read_volatile((pa as *const u64).add(idx)) };
            if level == LEAF_LEVEL_4K { return e; }
            pa = e & SplitWalker::PHYS_MASK;
        }
        0
    }

    /// Every sibling of the split leaf must still translate its own address, or
    /// the split silently unmaps 511 pages of the linear map per level.
    #[test]
    fn split_leaves_every_sibling_translating_its_own_address() {
        // A block base deliberately different from the virtual base, so an
        // offset error cannot pass by coincidence.
        let va = (2u64 << L1_SHIFT) | (3 << L2_SHIFT);
        let block_pa = 11u64 << L1_SHIFT;
        let va_block_base = va & !(level_span_bytes(1) - 1);
        let mut tree = block_tree(va, block_pa);
        let root_pa = tree.root_pa;
        let mut tables = core::mem::take(&mut tree.tables);
        // SAFETY: hosted synthetic tree owned by this test.
        assert_eq!(unsafe { split_kernel_leaf_at_root::<SplitWalker, _>(root_pa, va, 0, allocator(&mut tables)) }, Ok(()));
        let leaf_base = va & !(level_span_bytes(2) - 1);
        for slot in [0usize, 1, 255, ENTRIES_PER_TABLE - 1] {
            let sib = leaf_base + (slot as u64) * level_span_bytes(3);
            // SAFETY: same owned tree.
            let leaf = unsafe { read_bottom_leaf(root_pa, sib) };
            assert_ne!(leaf & T_VALID, 0, "sibling must stay mapped");
            assert_eq!(leaf & SplitWalker::PHYS_MASK, block_pa + (sib - va_block_base),
                       "sibling must translate to its own address");
        }
        // The 2 MiB siblings the first level produced must also still cover
        // their own thirds of the original block.
        let other_2m = va_block_base + 5 * level_span_bytes(2);
        // SAFETY: same owned tree.
        assert!(unsafe { leaf_present_at_root::<SplitWalker>(root_pa, other_2m, 0) });
        tree.tables = tables;
    }

    /// Splitting is idempotent: a second request finds tables, allocates
    /// nothing, and leaves the translation alone.
    #[test]
    fn second_split_of_the_same_address_allocates_nothing() {
        let va = 9u64 << L1_SHIFT;
        let mut tree = block_tree(va, 9u64 << L1_SHIFT);
        let root_pa = tree.root_pa;
        let mut tables = core::mem::take(&mut tree.tables);
        // SAFETY: hosted synthetic tree owned by this test.
        assert_eq!(unsafe { split_kernel_leaf_at_root::<SplitWalker, _>(root_pa, va, 0, allocator(&mut tables)) }, Ok(()));
        let after_first = tables.len();
        // SAFETY: same owned tree.
        assert_eq!(unsafe { split_kernel_leaf_at_root::<SplitWalker, _>(root_pa, va, 0, allocator(&mut tables)) }, Ok(()));
        assert_eq!(tables.len(), after_first, "an already-split address must not allocate again");
        tree.tables = tables;
    }

    /// Clearing the leaf removes exactly one page from the linear map and the
    /// inverse call restores the identical translation.
    #[test]
    fn clearing_and_restoring_one_leaf_is_exactly_reversible() {
        let va = (1u64 << L1_SHIFT) | (4 << L2_SHIFT) | (6 << L3_SHIFT);
        let mut tree = block_tree(va, 1u64 << L1_SHIFT);
        let root_pa = tree.root_pa;
        let mut tables = core::mem::take(&mut tree.tables);
        // SAFETY: hosted synthetic tree owned by this test.
        assert_eq!(unsafe { split_kernel_leaf_at_root::<SplitWalker, _>(root_pa, va, 0, allocator(&mut tables)) }, Ok(()));
        // SAFETY: same owned tree.
        let before = unsafe { read_bottom_leaf(root_pa, va) };
        // SAFETY: same owned tree.
        assert!(unsafe { set_leaf_present_at_root::<SplitWalker>(root_pa, va, false, 0) });
        // SAFETY: same owned tree.
        assert!(!unsafe { leaf_present_at_root::<SplitWalker>(root_pa, va, 0) });
        let neighbour = va + (1 << L3_SHIFT);
        // SAFETY: same owned tree.
        assert!(unsafe { leaf_present_at_root::<SplitWalker>(root_pa, neighbour, 0) },
                "only the named page leaves the linear map");
        // SAFETY: same owned tree.
        assert!(unsafe { set_leaf_present_at_root::<SplitWalker>(root_pa, va, true, 0) });
        // SAFETY: same owned tree.
        assert_eq!(unsafe { read_bottom_leaf(root_pa, va) }, before, "restore must be exact");
        tree.tables = tables;
    }

    /// An architecture that cannot re-granularise a live kernel mapping must
    /// say so rather than perform an unsound split.
    #[test]
    fn a_refusing_architecture_reports_the_block_it_would_not_split() {
        struct NoSplit;
        impl PtWalker for NoSplit {
            const PHYS_MASK: u64 = SplitWalker::PHYS_MASK;
            unsafe fn read_pt_base(_: u64) -> u64 { 0 }
            unsafe fn flush_va(_: u64) {}
            fn is_valid(e: u64) -> bool { SplitWalker::is_valid(e) }
            fn is_huge_or_block(e: u64) -> bool { SplitWalker::is_huge_or_block(e) }
            fn pack_table(pa: u64) -> u64 { SplitWalker::pack_table(pa) }
            fn pack_device_leaf(pa: u64) -> u64 { SplitWalker::pack_device_leaf(pa) }
            fn pack_4k_leaf(pa: u64, f: crate::PageFlags) -> u64 { SplitWalker::pack_4k_leaf(pa, f) }
            fn pack_block_leaf(pa: u64, f: crate::PageFlags) -> u64 { SplitWalker::pack_block_leaf(pa, f) }
            fn pack_swap_entry(_: super::super::SwapEntry) -> u64 { 0 }
            fn unpack_swap_entry(_: u64) -> Option<super::super::SwapEntry> { None }
            fn can_split_kernel_leaf() -> bool { false }
            fn split_child_leaf(b: u64, p: u64, l: u8) -> u64 { SplitWalker::split_child_leaf(b, p, l) }
            fn publish_table_barrier() {}
            fn leaf_set_present(raw: u64, p: bool) -> u64 { SplitWalker::leaf_set_present(raw, p) }
            fn leaf_wrprotect(raw: u64) -> u64 { raw }
            fn leaf_set_uffd_wp(raw: u64) -> u64 { raw }
            fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw }
            fn leaf_is_uffd_wp(_: u64) -> bool { false }
            fn pack_poison_marker() -> u64 { 0 }
            fn is_poison_marker(_: u64) -> bool { false }
        }
        let va = 3u64 << L1_SHIFT;
        let mut tree = block_tree(va, 3u64 << L1_SHIFT);
        let root_pa = tree.root_pa;
        let mut tables = core::mem::take(&mut tree.tables);
        // SAFETY: hosted synthetic tree owned by this test.
        let r = unsafe { split_kernel_leaf_at_root::<NoSplit, _>(root_pa, va, 0, allocator(&mut tables)) };
        assert_eq!(r, Err(WalkErr::HitHugeOrBlock));
        assert!(tables.is_empty(), "a refusal must not allocate");
        tree.tables = tables;
    }

    /// A range nothing maps has no granularity to change; that is not a
    /// failure, and it must not allocate.
    #[test]
    fn absent_address_splits_to_nothing() {
        let mut root = Box::new(Table([0; ENTRIES_PER_TABLE]));
        let root_pa = root.0.as_mut_ptr() as u64;
        let mut tables: Vec<Box<Table>> = Vec::new();
        // SAFETY: hosted synthetic tree owned by this test.
        let r = unsafe { split_kernel_leaf_at_root::<SplitWalker, _>(root_pa, 1 << L1_SHIFT, 0, allocator(&mut tables)) };
        assert_eq!(r, Ok(()));
        assert!(tables.is_empty());
    }

    #[test]
    fn absent_entry_has_nothing_to_split() {
        assert_eq!(split_step(1, false, false), SplitStep::Absent);
        assert_eq!(split_step(1, false, true), SplitStep::Absent);
    }

    #[test]
    fn block_at_root_level_is_not_a_split_candidate() {
        // A leaf at the root level would span 512 GiB; neither architecture
        // maps one, so a block claim there is descended, never split.
        assert_eq!(split_step(0, true, true), SplitStep::Descend);
        assert_eq!(split_step(0, true, false), SplitStep::Descend);
    }

    #[test]
    fn block_levels_split_one_level_down() {
        assert_eq!(split_step(1, true, true), SplitStep::SplitTo(2));
        assert_eq!(split_step(2, true, true), SplitStep::SplitTo(3));
    }

    #[test]
    fn bottom_level_is_already_the_target_granularity() {
        assert_eq!(split_step(3, true, false), SplitStep::Done);
        assert_eq!(split_step(3, true, true), SplitStep::Done);
    }

    #[test]
    fn level_spans_are_the_four_level_walk_sizes() {
        assert_eq!(level_span_bytes(0), 512 << 30);
        assert_eq!(level_span_bytes(1), 1 << 30);
        assert_eq!(level_span_bytes(2), 2 << 20);
        assert_eq!(level_span_bytes(3), 4 << 10);
    }

    #[test]
    fn block_output_drops_attribute_bits_inside_the_address_field() {
        // A block descriptor's address field is narrower than the bottom-level
        // one; the low bits it does not use carry attributes. Reading them as
        // address would offset every child.
        let raw = (3u64 << 30) | (1 << 12);
        assert_eq!(block_output_pa(raw, 1), 3 << 30);
        let raw2 = (7u64 << 21) | (1 << 12);
        assert_eq!(block_output_pa(raw2, 2), 7 << 21);
    }

    #[test]
    fn children_tile_the_parent_block_exactly() {
        let base = 4u64 << 30;
        assert_eq!(child_output_pa(base, 1, 0), base);
        assert_eq!(child_output_pa(base, 1, 1), base + (2 << 20));
        assert_eq!(child_output_pa(base, 1, ENTRIES_PER_TABLE - 1), base + (1 << 30) - (2 << 20));
        assert_eq!(
            child_output_pa(base, 1, ENTRIES_PER_TABLE - 1) + (2 << 20),
            base + level_span_bytes(1),
        );
        let m = 6u64 << 21;
        assert_eq!(child_output_pa(m, 2, 0), m);
        assert_eq!(child_output_pa(m, 2, ENTRIES_PER_TABLE - 1), m + (2 << 20) - (4 << 10));
    }
}
