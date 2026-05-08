// Arch-generic 4-level 4 KiB page-table walker per `20§5` / `21§5`.
//
// Both x86_64 (PML4→PDPT→PD→PT) and aarch64 EL1 with 4 KiB granule
// (L0→L1→L2→L3) use a 4-level table tree with 512 entries per
// table and the same VA-bit shifts (39/30/21/12). Only the entry
// bit semantics + privileged register access differ. The walk
// driver here owns the loop and HHDM-based table access; the
// per-arch `PtWalker` impl supplies the bit semantics.
//
// Used so far for splicing Device-attr MMIO leaves into the live
// tables; future callers (real `MmuOps::map`, page-fault handler
// installs) ride the same driver.

use core::ptr;

/// Entries per 4 KiB page table — fixed for both arches.
pub const ENTRIES_PER_TABLE: usize = 512;

/// VA-bit shift for the L0/PML4 index (4-level walk).
pub const L0_SHIFT: u32 = 39;
/// VA-bit shift for the L1/PDPT index.
pub const L1_SHIFT: u32 = 30;
/// VA-bit shift for the L2/PD index.
pub const L2_SHIFT: u32 = 21;
/// VA-bit shift for the L3/PT index (leaf).
pub const L3_SHIFT: u32 = 12;
/// Mask of one table-index field (9 bits = 512 entries).
pub const TABLE_IDX_MASK: u64 = 0x1ff;

/// Errors `map_device_4k` can return.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WalkErr {
    /// Frame allocator returned `None` mid-walk.
    AllocFailed,
    /// An intermediate entry is a huge page / block descriptor and
    /// would need to be split. Caller policy decides if that's an
    /// error or a "split first then retry"; this driver doesn't.
    HitHugeOrBlock,
    /// Leaf already present at `va` and points elsewhere.
    AlreadyMapped,
}

/// Per-arch bit semantics for the 4-level walker. Static methods
/// only; impls are zero-sized markers.
///
/// Generic at the call site (per `07§5` no-`dyn` rule): the walker
/// monomorphizes per impl.
///
/// # C: each method is O(1).
pub trait PtWalker {
    /// Mask of the physical-address field in a PTE (12-bit aligned;
    /// excludes flag bits). `0x000f_ffff_ffff_f000` on x86_64,
    /// `0x0000_ffff_ffff_f000` on aarch64.
    const PHYS_MASK: u64;

    /// Read the active page-table base PA for the walk targeting
    /// `va`. On x86_64 there's a single CR3 so `va` is ignored. On
    /// aarch64 the TTBR0_EL1 / TTBR1_EL1 split is keyed off bit 55
    /// of the VA (per ARM ARM D5.2.4): high-half VAs (kernel) use
    /// TTBR1, low-half (user) use TTBR0. Letting the walker pick
    /// per-call lets `MmuOps::map(USER_VA, ...)` plumb into the
    /// user tree without a separate impl.
    /// # SAFETY: privileged read; legal at CPL=0 / EL1.
    unsafe fn read_pt_base(va: u64) -> u64;

    /// Local-CPU TLB invalidate of a single 4 KiB page at `va`.
    /// # SAFETY: privileged.
    unsafe fn flush_va(va: u64);

    /// True when `entry`'s "present/valid" bit is set.
    fn is_valid(entry: u64) -> bool;

    /// True when a present `entry` describes a leaf at a
    /// non-bottom level (huge page on x86; block descriptor on
    /// arm). At L3 this is always false because L3 entries are
    /// always page leaves.
    fn is_huge_or_block(entry: u64) -> bool;

    /// Pack a fresh intermediate (table) entry pointing to
    /// `child_pa`. Sets only the table-descriptor bits — child
    /// permissions ride through as the leaf is installed.
    fn pack_table(child_pa: u64) -> u64;

    /// Pack a 4 KiB Device-attr leaf at `pa` (PCD|PWT|NX on x86;
    /// AttrIdx=Device|Inner-Shareable|AF|PXN|UXN on arm).
    fn pack_device_leaf(pa: u64) -> u64;

    /// Pack a 4 KiB leaf from arch-neutral `PageFlags`. Used by
    /// `MmuOps::map` per `20§5`/`21§5`. Each impl translates:
    /// WRITE → writable; EXEC clear → set NX (x86) / UXN+PXN
    /// according to USER (arm); USER → user-accessible; NO_CACHE +
    /// WRITE_THROUGH → device/non-cacheable bits.
    fn pack_4k_leaf(pa: u64, flags: crate::PageFlags) -> u64;

    /// Pack a huge/block leaf at `pa` (2 MiB or 1 GiB; same bit
    /// pattern at either level for both arches — x86 sets PS=1
    /// at PD/PDPT, arm clears the TABLE bit at L1/L2). Native
    /// flags translate identically to `pack_4k_leaf`.
    fn pack_block_leaf(pa: u64, flags: crate::PageFlags) -> u64;
}

/// Install a Device-attr 4 KiB leaf `va → pa` in the active 4-level
/// page-table tree. Walks via HHDM, allocating intermediate tables
/// from `alloc_pa` as needed; zero-initializes new tables before
/// linking so partial walks behave as "not present".
///
/// `alloc_pa()` returns the physical address of a fresh, page-
/// aligned, kernel-owned 4 KiB frame. Caller (kernel) typically
/// wraps PMM: `|| pmm.alloc(Order(0)).ok().map(|pfn| pfn.0 * 4096)`.
///
/// # SAFETY: caller asserts (a) `va` is canonical and not currently
/// owned by another subsystem, (b) `pa` is a real device MMIO base,
/// (c) `hhdm_offset` covers RAM holding page-table memory, (d)
/// `alloc_pa` returns frames the kernel exclusively owns. Single-
/// CPU, IRQ-off context (no concurrent walkers).
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn map_device_4k<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    pa: u64,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: per fn contract — privileged register read, legal in
    // kernel mode; result is the live root-table PA.
    let l0_pa = unsafe { W::read_pt_base(va) };

    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: per fn contract — HHDM covers page-table memory; alloc_pa returns kernel-owned frames; single-CPU + IRQs off prevents concurrent walkers; the leaf write at the bottom runs only after every intermediate is in place.
    unsafe {
        let l1_pa = walk_or_alloc::<W, _>(l0_pa, i_l0, hhdm_offset, &mut alloc_pa)?;
        let l2_pa = walk_or_alloc::<W, _>(l1_pa, i_l1, hhdm_offset, &mut alloc_pa)?;
        let l3_pa = walk_or_alloc::<W, _>(l2_pa, i_l2, hhdm_offset, &mut alloc_pa)?;
        let l3_va = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
        let slot = l3_va.add(i_l3);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (pa & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, W::pack_device_leaf(pa));
        W::flush_va(va);
    }
    Ok(())
}

/// Install a 4 KiB leaf with arch-neutral flags `va → pa`. Mirrors
/// `map_device_4k`'s walk discipline; the only difference is the
/// leaf bit pattern comes from `W::pack_4k_leaf(pa, flags)` rather
/// than the hardcoded device-attr packer. Used by `MmuOps::map`
/// per `20§5`/`21§5`.
///
/// # SAFETY: same contract as `map_device_4k`.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init or under PT lock; single-CPU walker.
pub unsafe fn map_4k<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    pa: u64,
    flags: crate::PageFlags,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: privileged read; legal in kernel mode.
    let l0_pa = unsafe { W::read_pt_base(va) };

    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: per fn contract; mirrors `map_device_4k`'s body.
    unsafe {
        let l1_pa = walk_or_alloc::<W, _>(l0_pa, i_l0, hhdm_offset, &mut alloc_pa)?;
        let l2_pa = walk_or_alloc::<W, _>(l1_pa, i_l1, hhdm_offset, &mut alloc_pa)?;
        let l3_pa = walk_or_alloc::<W, _>(l2_pa, i_l2, hhdm_offset, &mut alloc_pa)?;
        let l3_va = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
        let slot = l3_va.add(i_l3);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (pa & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, W::pack_4k_leaf(pa, flags));
        W::flush_va(va);
    }
    Ok(())
}

/// Install a leaf at the requested level — `1` = 1 GiB block (L1),
/// `2` = 2 MiB block (L2), `3` = 4 KiB page (L3). The walker
/// descends to the parent of `leaf_level`, allocating intermediate
/// tables as it goes, then writes `leaf` at the parent table's
/// index for `va`.
///
/// `va` and the embedded `pa` in `leaf` must be aligned to the
/// page size implied by `leaf_level` (caller satisfies; checked by
/// the `MmuOps::map` wrapper via `kassert!`).
///
/// # SAFETY: same contract as `map_4k`.
/// # C: O(leaf_level) — at most 4
/// # Ctx: pre-init or under PT lock; single-CPU walker.
pub unsafe fn map_at_level<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    leaf_level: u8,
    leaf: u64,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: privileged read; legal in kernel mode.
    let root_pa = unsafe { W::read_pt_base(va) };
    // SAFETY: delegated; root_pa is the active root.
    unsafe { map_at_level_with_root::<W, _>(root_pa, va, leaf_level, leaf, hhdm_offset, &mut alloc_pa) }
}

/// Like `map_at_level` but installs into the tree rooted at
/// `root_pa` instead of reading from the active CR3 / TTBR0.
/// Used by `AddressSpace::fork` per docs/11§7 to populate child
/// page tables without temporarily activating them.
///
/// # SAFETY: caller asserts (a) `root_pa` is a valid kernel-owned
/// PT root, (b) other map_at_level preconditions per the
/// active-root form. Single-CPU walker; per-AS PT lock held.
/// # C: O(leaf_level)
pub unsafe fn map_at_level_with_root<W: PtWalker, F: FnMut() -> Option<u64>>(
    root_pa: u64,
    va: u64,
    leaf_level: u8,
    leaf: u64,
    hhdm_offset: u64,
    mut alloc_pa: &mut F,
) -> Result<(), WalkErr> {
    let mut current_pa = root_pa;
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    // Walk levels 0..(leaf_level - 1), descending into table entries.
    for level in 0..leaf_level {
        let idx = ((va >> shifts[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: per fn contract; descend through one level of tables.
        current_pa = unsafe { walk_or_alloc::<W, _>(current_pa, idx, hhdm_offset, &mut alloc_pa)? };
    }
    // `current_pa` is the parent of the leaf level. Write the leaf
    // at the appropriate index.
    let leaf_idx = ((va >> shifts[leaf_level as usize]) & TABLE_IDX_MASK) as usize;
    // SAFETY: HHDM covers page-table memory per fn contract; we own
    // the slot for the duration of the write per single-CPU walker.
    unsafe {
        let table_va = (hhdm_offset.wrapping_add(current_pa)) as *mut u64;
        let slot = table_va.add(leaf_idx);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (leaf & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, leaf);
        W::flush_va(va);
    }
    Ok(())
}

/// Translate `va` to (`pa`, raw_leaf_entry) by walking the live
/// tables. Returns `None` if the leaf is missing or sits at a
/// non-bottom level (huge/block — caller decides). Reads only;
/// safe to call without holding a PT-write lock if the caller
/// accepts a torn-walk view (some entries from before, some from
/// after a concurrent write).
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) the active root is stable for the walk duration. Single-
/// CPU + IRQ-off makes (b) trivially hold.
/// # C: O(walk depth) = O(4)
/// # Ctx: read-only walk
pub unsafe fn translate_4k<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<(u64, u64)> {
    // SAFETY: privileged read; legal in kernel mode.
    let l0_pa = unsafe { W::read_pt_base(va) };
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: HHDM covers page-table memory per fn contract; reads only.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(l0_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1_pa = e0 & W::PHYS_MASK;
        let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2_pa = e1 & W::PHYS_MASK;
        let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3_pa = e2 & W::PHYS_MASK;
        let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
        let leaf = ptr::read_volatile(l3.add(i_l3));
        if !W::is_valid(leaf) { return None; }
        Some((leaf & W::PHYS_MASK, leaf))
    }
}

/// Same as `translate_4k` but walks tables rooted at the
/// caller-supplied `root_pa` instead of the active CR3 / TTBR.
/// Used for foreign-mm reads (e.g. ptrace PEEK reading another
/// task's user memory) where we have the AddressSpace's
/// `root_pa()` but the target is not the running task.
///
/// # SAFETY: same as `translate_4k`, plus caller asserts
/// `root_pa` is a valid 4 KiB-aligned page-table root frame
/// owned by a live AddressSpace; the AS must outlive the walk
/// (caller holds an Arc keeping it alive).
/// # C: O(walk depth) = O(4)
/// # Ctx: read-only walk
pub unsafe fn translate_4k_at_root<W: PtWalker>(
    root_pa: u64, va: u64, hhdm_offset: u64,
) -> Option<(u64, u64)> {
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
    // SAFETY: HHDM covers page-table memory per fn contract; reads only.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1_pa = e0 & W::PHYS_MASK;
        let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2_pa = e1 & W::PHYS_MASK;
        let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3_pa = e2 & W::PHYS_MASK;
        let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *const u64;
        let leaf = ptr::read_volatile(l3.add(i_l3));
        if !W::is_valid(leaf) { return None; }
        Some((leaf & W::PHYS_MASK, leaf))
    }
}

/// Walk `[va_start, va_end)` in 4 KiB steps and rewrite each
/// present 4 KiB leaf with `W::pack_4k_leaf(pa, new_flags)`,
/// preserving the leaf's PA. Skips not-present and huge/block
/// leaves (per-page mprotect on a huge mapping needs split-down
/// first; rare in v1 — most user mappings are 4 KiB). Returns
/// the count of leaves actually rewritten.
///
/// Caller is responsible for TLB invalidation of every va in
/// the range AFTER this returns; this fn writes the PTE entries
/// only.
///
/// # SAFETY: same contract as `translate_4k_at_root` plus
/// caller asserts no concurrent walker / fault path is racing
/// with the rewrite (single-CPU + IRQ-off or per-AS PT lock).
/// # C: O((va_end - va_start) / 4096 * walk_depth)
/// # Ctx: under PT lock or pre-init single-CPU.
pub unsafe fn protect_4k_at_root<W: PtWalker>(
    root_pa: u64, va_start: u64, va_end: u64, new_flags: crate::PageFlags,
    hhdm_offset: u64,
) -> usize {
    let mut updated = 0usize;
    let mut va = va_start & !((1u64 << L3_SHIFT) - 1);
    while va < va_end {
        let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;
        // SAFETY: HHDM covers PT memory per fn contract; reads/writes only the L3 leaf slot which is exclusive under the PT lock.
        unsafe {
            let l0 = (hhdm_offset.wrapping_add(root_pa)) as *const u64;
            let e0 = ptr::read_volatile(l0.add(i_l0));
            if W::is_valid(e0) && !W::is_huge_or_block(e0) {
                let l1_pa = e0 & W::PHYS_MASK;
                let l1 = (hhdm_offset.wrapping_add(l1_pa)) as *const u64;
                let e1 = ptr::read_volatile(l1.add(i_l1));
                if W::is_valid(e1) && !W::is_huge_or_block(e1) {
                    let l2_pa = e1 & W::PHYS_MASK;
                    let l2 = (hhdm_offset.wrapping_add(l2_pa)) as *const u64;
                    let e2 = ptr::read_volatile(l2.add(i_l2));
                    if W::is_valid(e2) && !W::is_huge_or_block(e2) {
                        let l3_pa = e2 & W::PHYS_MASK;
                        let l3 = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
                        let leaf = ptr::read_volatile(l3.add(i_l3));
                        if W::is_valid(leaf) {
                            let pa = leaf & W::PHYS_MASK;
                            let new_leaf = W::pack_4k_leaf(pa, new_flags);
                            ptr::write_volatile(l3.add(i_l3), new_leaf);
                            updated += 1;
                        }
                    }
                }
            }
        }
        va = va.wrapping_add(1u64 << L3_SHIFT);
    }
    updated
}

/// Translate `va` walking the live tables, recognising huge/block
/// leaves at intermediate levels. Returns
/// `Some((pa_for_va, raw_leaf, leaf_level))` where:
/// - `pa_for_va` includes the in-leaf offset (so `va`'s low bits
///   appear in the result).
/// - `raw_leaf` is the unmodified leaf entry (caller decodes flags).
/// - `leaf_level` ∈ {1 (1 GiB block), 2 (2 MiB block), 3 (4 KiB page)}.
///
/// Returns `None` if no leaf is present along the walk.
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) the active root is stable for the walk duration. Reads only.
/// # C: O(walk depth) = O(4)
/// # Ctx: read-only walk
pub unsafe fn translate_at_va<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<(u64, u64, u8)> {
    // SAFETY: privileged read; legal in kernel mode.
    let mut current_pa = unsafe { W::read_pt_base(va) };
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    for level in 0..4u8 {
        let idx = ((va >> shifts[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: HHDM covers page-table memory per fn contract; reads only.
        let entry = unsafe {
            let table = (hhdm_offset.wrapping_add(current_pa)) as *const u64;
            ptr::read_volatile(table.add(idx))
        };
        if !W::is_valid(entry) { return None; }
        if level == 3 {
            // L3 page leaf — final descent.
            let page_pa = entry & W::PHYS_MASK;
            let offset = va & ((1u64 << L3_SHIFT) - 1);
            return Some((page_pa | offset, entry, 3));
        }
        if W::is_huge_or_block(entry) {
            // Block leaf at L1 (1 GiB) or L2 (2 MiB). L0 huge isn't
            // legal on either arch in v1 — bail to avoid a 512 GiB
            // misread.
            if level == 0 { return None; }
            let block_pa = entry & W::PHYS_MASK;
            let offset = va & ((1u64 << shifts[level as usize]) - 1);
            return Some((block_pa | offset, entry, level));
        }
        current_pa = entry & W::PHYS_MASK;
    }
    None
}

/// Tear down a leaf at `va` regardless of size. Walks live tables,
/// stops at the first leaf encountered (4 KiB page or huge block),
/// zeroes its slot, and locally flushes the TLB. Returns the
/// `(torn_leaf, leaf_level)` on success or `None` if no leaf is
/// present.
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) `va` exclusively owned (no concurrent walker/use), (c)
/// caller will perform any cross-CPU TLB shootdown beyond the
/// local invalidate this function does.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init or under PT-write lock.
pub unsafe fn unmap_at_va<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<(u64, u8)> {
    // SAFETY: privileged read; legal in kernel mode.
    let mut current_pa = unsafe { W::read_pt_base(va) };
    let shifts = [L0_SHIFT, L1_SHIFT, L2_SHIFT, L3_SHIFT];
    for level in 0..4u8 {
        let idx = ((va >> shifts[level as usize]) & TABLE_IDX_MASK) as usize;
        // SAFETY: HHDM covers page-table memory; va exclusively owned per fn contract.
        unsafe {
            let table = (hhdm_offset.wrapping_add(current_pa)) as *mut u64;
            let slot = table.add(idx);
            let entry = ptr::read_volatile(slot);
            if !W::is_valid(entry) { return None; }
            let is_leaf = level == 3 || (W::is_huge_or_block(entry) && level != 0);
            if is_leaf {
                ptr::write_volatile(slot, 0);
                W::flush_va(va);
                return Some((entry, level));
            }
            // L0 with huge bit set is malformed; bail.
            if W::is_huge_or_block(entry) { return None; }
            current_pa = entry & W::PHYS_MASK;
        }
    }
    None
}

/// Tear down a 4 KiB leaf at `va` if present. No-op if not mapped
/// or if a non-bottom-level entry blocks the walk. Returns the
/// torn-down leaf entry on success.
///
/// # SAFETY: caller asserts (a) HHDM covers page-table memory,
/// (b) `va` exclusively owned (no concurrent walker/use), (c)
/// caller will perform any cross-CPU TLB shootdown beyond the
/// local invalidate this function does.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init or under PT-write lock.
pub unsafe fn unmap_4k<W: PtWalker>(va: u64, hhdm_offset: u64) -> Option<u64> {
    // SAFETY: privileged read; legal in kernel mode.
    let l0_pa = unsafe { W::read_pt_base(va) };
    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: HHDM covers page-table memory; va owned by caller;
    // single writer per fn contract.
    unsafe {
        let l0 = (hhdm_offset.wrapping_add(l0_pa)) as *const u64;
        let e0 = ptr::read_volatile(l0.add(i_l0));
        if !W::is_valid(e0) || W::is_huge_or_block(e0) { return None; }
        let l1 = (hhdm_offset.wrapping_add(e0 & W::PHYS_MASK)) as *const u64;
        let e1 = ptr::read_volatile(l1.add(i_l1));
        if !W::is_valid(e1) || W::is_huge_or_block(e1) { return None; }
        let l2 = (hhdm_offset.wrapping_add(e1 & W::PHYS_MASK)) as *const u64;
        let e2 = ptr::read_volatile(l2.add(i_l2));
        if !W::is_valid(e2) || W::is_huge_or_block(e2) { return None; }
        let l3 = (hhdm_offset.wrapping_add(e2 & W::PHYS_MASK)) as *mut u64;
        let slot = l3.add(i_l3);
        let leaf = ptr::read_volatile(slot);
        if !W::is_valid(leaf) { return None; }
        ptr::write_volatile(slot, 0);
        W::flush_va(va);
        Some(leaf)
    }
}

/// Read entry `[idx]` in the table at PA `parent_pa` (via HHDM).
/// If empty, allocate + zero-init + link a fresh child table and
/// return its PA. If present and a non-bottom-level leaf, error.
///
/// # SAFETY: see `map_device_4k`.
unsafe fn walk_or_alloc<W: PtWalker, F: FnMut() -> Option<u64>>(
    parent_pa: u64,
    idx: usize,
    hhdm_offset: u64,
    alloc_pa: &mut F,
) -> Result<u64, WalkErr> {
    // SAFETY: parent_pa references a 4 KiB-aligned table page; HHDM maps it into kernel VA; single-CPU/IRQs-off per `map_device_4k`'s contract.
    unsafe {
        let parent_va = (hhdm_offset.wrapping_add(parent_pa)) as *mut u64;
        let slot = parent_va.add(idx);
        let entry = ptr::read_volatile(slot);
        if !W::is_valid(entry) {
            let child_pa = alloc_pa().ok_or(WalkErr::AllocFailed)?;
            // Fresh kernel-owned frame; zero every entry through HHDM
            // so a missing leaf below acts as "not present".
            let child_va = (hhdm_offset.wrapping_add(child_pa)) as *mut u64;
            for k in 0..ENTRIES_PER_TABLE {
                ptr::write_volatile(child_va.add(k), 0);
            }
            ptr::write_volatile(slot, W::pack_table(child_pa));
            return Ok(child_pa);
        }
        if W::is_huge_or_block(entry) {
            return Err(WalkErr::HitHugeOrBlock);
        }
        Ok(entry & W::PHYS_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests share the static fake-root tree; `cargo test` runs in
    // parallel by default. Serialize via this mutex.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Hosted PtWalker stub — verifies the walk-driver loop end-to-
    /// end on a synthetic in-memory tree without privileged regs.
    struct HostWalker;
    static mut FAKE_ROOT: [u64; ENTRIES_PER_TABLE] = [0; ENTRIES_PER_TABLE];
    static mut FAKE_FLUSH_COUNT: u32 = 0;

    /// HHDM offset = 0 for the host test (PA == VA on the in-process heap).
    impl PtWalker for HostWalker {
        const PHYS_MASK: u64 = 0xffff_ffff_ffff_f000;
        unsafe fn read_pt_base(_va: u64) -> u64 {
            // SAFETY: hosted test; FAKE_ROOT is `static mut` test state.
            unsafe { (&raw mut FAKE_ROOT).cast::<u8>() as u64 }
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
    }

    /// 4 KiB-aligned wrapper so `Box::new(AlignedTable(_))` returns
    /// a heap allocation that satisfies `PHYS_MASK & addr == addr`.
    /// The default heap allocator doesn't guarantee 4 KiB alignment;
    /// without this wrapper the walker masks low bits off the pa
    /// stored in parent slots and reads garbage.
    #[repr(align(4096))]
    struct AlignedTable([u64; ENTRIES_PER_TABLE]);

    /// Reset shared test state. Caller holds `SERIAL`.
    fn reset() -> alloc::vec::Vec<alloc::boxed::Box<AlignedTable>> {
        // SAFETY: SERIAL held; no other test thread reads/writes these.
        unsafe { FAKE_ROOT = [0; ENTRIES_PER_TABLE]; FAKE_FLUSH_COUNT = 0; }
        alloc::vec::Vec::new()
    }

    #[test]
    fn map_device_4k_allocates_three_tables_and_installs_leaf() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut allocated = 0usize;
        let alloc = || -> Option<u64> {
            allocated += 1;
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0005_6000_u64;
        let pa = 0x0000_0000_dead_b000_u64;
        // SAFETY: hosted test; synthetic root + boxed children owned by this scope.
        let r = unsafe { map_device_4k::<HostWalker, _>(va, pa, 0, alloc) };
        assert_eq!(r, Ok(()));
        assert_eq!(allocated, 3, "L1+L2+L3 tables allocated");
        // SAFETY: SERIAL mutex serializes test threads accessing FAKE_FLUSH_COUNT.
        assert_eq!(unsafe { FAKE_FLUSH_COUNT }, 1, "flush_va called exactly once");
    }

    #[test]
    fn map_device_4k_already_mapped_when_leaf_points_elsewhere() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0005_6000_u64;
        // SAFETY: hosted test; install a first leaf.
        let r1 = unsafe { map_device_4k::<HostWalker, _>(va, 0xaaaa_b000, 0, &mut alloc) };
        assert_eq!(r1, Ok(()));
        // SAFETY: hosted test; same VA, different PA → AlreadyMapped.
        let r2 = unsafe { map_device_4k::<HostWalker, _>(va, 0xbbbb_b000, 0, &mut alloc) };
        assert_eq!(r2, Err(WalkErr::AlreadyMapped));
    }

    #[test]
    fn map_at_level_2m_writes_at_l2_index() {
        // 2 MiB block leaf: walker descends L0 → L1 → L2, then
        // writes the leaf at L2[i_l2]. Two table allocs (L1 + L2);
        // the L3 step is skipped entirely.
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut allocated = 0usize;
        let mut alloc = || -> Option<u64> {
            allocated += 1;
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0020_0000_u64;             // 2 MiB-aligned
        let pa = 0x0000_0000_dee0_0000_u64;             // 2 MiB-aligned
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ | crate::PageFlags::WRITE);
        // SAFETY: hosted test; synthetic root + boxed children owned by this scope.
        let r = unsafe { map_at_level::<HostWalker, _>(va, 2, leaf, 0, &mut alloc) };
        assert_eq!(r, Ok(()));
        assert_eq!(allocated, 2, "L1 + L2 tables allocated; L3 skipped");
        let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
        // SAFETY: SERIAL held; FAKE_ROOT + child boxes single-thread accessible in-test.
        unsafe {
            let l1_pa = FAKE_ROOT[i_l0] & HostWalker::PHYS_MASK;
            let l1 = l1_pa as *const u64;
            let l2_pa = (*l1.add(i_l1)) & HostWalker::PHYS_MASK;
            let l2 = l2_pa as *const u64;
            assert_eq!(*l2.add(i_l2), leaf);
        }
    }

    #[test]
    fn map_at_level_1g_writes_at_l1_index() {
        // 1 GiB block leaf: walker descends L0 → L1, writes leaf at
        // L1[i_l1]. One table alloc.
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut allocated = 0usize;
        let mut alloc = || -> Option<u64> {
            allocated += 1;
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_4000_0000_u64;             // 1 GiB-aligned
        let pa = 0x0000_0000_4000_0000_u64;             // 1 GiB-aligned
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ);
        // SAFETY: hosted test; synthetic root + boxed children owned by this scope.
        let r = unsafe { map_at_level::<HostWalker, _>(va, 1, leaf, 0, &mut alloc) };
        assert_eq!(r, Ok(()));
        assert_eq!(allocated, 1, "L1 table allocated; L2/L3 skipped");
    }

    #[test]
    fn translate_at_va_recognises_2m_block_leaf() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0020_0000_u64;
        let pa = 0x0000_0000_dee0_0000_u64;
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ | crate::PageFlags::WRITE);
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let r = unsafe { map_at_level::<HostWalker, _>(va, 2, leaf, 0, &mut alloc) };
        assert_eq!(r, Ok(()));

        // Pick an in-block offset whose only set bits are below the
        // 4 KiB page-frame boundary so `resolved & PHYS_MASK` still
        // equals `pa`. Larger offsets within the 2 MiB block also
        // work but mask differently; the tested invariant here is
        // that the walker reconstructs `pa | offset` verbatim.
        let off = 0xa3_u64;
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let t = unsafe { translate_at_va::<HostWalker>(va | off, 0) };
        let (resolved, raw, level) = t.expect("leaf should be present");
        assert_eq!(level, 2);
        assert_eq!(raw, leaf);
        assert_eq!(resolved, pa | off);
    }

    #[test]
    fn unmap_at_va_clears_2m_block_leaf() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0020_0000_u64;
        let pa = 0x0000_0000_dee0_0000_u64;
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ);
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let _ = unsafe { map_at_level::<HostWalker, _>(va, 2, leaf, 0, &mut alloc) };

        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let u = unsafe { unmap_at_va::<HostWalker>(va, 0) };
        let (got, level) = u.expect("leaf should have been there");
        assert_eq!(level, 2);
        assert_eq!(got, leaf);
        // After unmap, translate returns None.
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        assert_eq!(unsafe { translate_at_va::<HostWalker>(va, 0) }, None);
    }

    #[test]
    fn map_device_4k_propagates_alloc_failure() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let _ = reset();
        let alloc = || -> Option<u64> { None };
        // SAFETY: hosted test; allocator returns None at the first request.
        let r = unsafe { map_device_4k::<HostWalker, _>(0, 0x1000, 0, alloc) };
        assert_eq!(r, Err(WalkErr::AllocFailed));
    }
}

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;
