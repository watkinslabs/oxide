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
mod tests;
