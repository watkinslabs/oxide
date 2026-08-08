// x86_64 page-table walker per `20§5`. Splices a Device-attr 4 KiB
// leaf into the live PML4 (CR3) tree.
//
// The walk loop is shared with aarch64 in `hal::pt_walker`; this
// file supplies the x86 bit semantics + privileged-register access
// via the `PtWalker` trait. Per `07§5` no-`dyn`-on-HAL: the
// `map_device_4k` shim is generic-only at the call site and
// monomorphizes to a single instance per arch.
//
// PCD|PWT remains PAT slot 3 (Strong UC) after the kernel installs Linux's
// PAT layout. Write-combining uses slot 1 and write-through uses slot 7.

use hal::pt_walker::{self, PtWalker, WalkErr};

const P_BIT:  u64 = 1 << 0;
const RW_BIT: u64 = 1 << 1;
const PS_BIT: u64 = 1 << 7;
const DIRTY_BIT: u64 = 1 << 6;
/// High memory-type selector bit position in a block (non-bottom-level) leaf.
const BLOCK_TYPE_HI_SHIFT: u32 = 12;
/// Same selector's position in a bottom-level 4 KiB leaf.
const LEAF_TYPE_HI_SHIFT: u32 = 7;
/// Bottom (4 KiB) level index in the shared four-level walker.
const LEAF_LEVEL_4K: u8 = 3;
const NX_BIT: u64 = 1 << 63;
const PHYS_MASK_X86: u64 = 0x000f_ffff_ffff_f000;
const SWAP_MARKER: u64 = 1 << 1;
const SWAP_TYPE_SHIFT: u8 = 2;
const SWAP_OFFSET_SHIFT: u8 = 12;
// Non-present x86 PTE bit 11 is software-available (Intel SDM Vol. 3
// 4.8); hardware ignores it when P=0.  Keeping it outside the 40-bit
// payload makes a migration marker distinguishable from every swap type.
const MIGRATION_MARKER: u64 = 1 << 11;
// Bit 57 is software-available on this architecture (ignored by the translation
// hardware whether or not the entry is present), which is what lets a leaf carry
// the userfaultfd write-protect marker without changing how the CPU walks it.
//
// The SAME bit carries the state on a NON-PRESENT leaf, and it can do so
// without ambiguity: it lies outside every field the three non-present
// encodings are identified or decoded by. Swap entries are named by bit 1 and
// decode bits 2..=6 and 12..=51; migration entries are named by bit 11 and
// decode 12..=51; markers are named by bit 10 and decode 12..=13. Bit 57 is in
// none of those, so setting it changes no identity and no payload, and the
// "present or not" question — which the two predicates below split on — is
// exactly what separates a page's own barrier from the barrier riding on a
// reference to a page that is elsewhere.
const UFFD_WP_BIT: u64 = 1 << 57;
// Non-present bit 10, disjoint from the swap (bit 1) and migration (bit 11)
// markers, so a marker leaf decodes as neither and neither decodes as a marker.
// The kinds ride in the same payload field the swap offset and the migration
// token occupy: that field can never make a swap or migration entry out of a
// marker, because those two are identified by bits 1 and 11 and a marker sets
// neither.
const PTE_MARKER: u64 = 1 << 10;
const PTE_MARKER_KIND_SHIFT: u8 = 12;

/// Errors `map_device_4k` can return. Mirrors `WalkErr` 1:1; kept
/// as a separate type so callers don't depend on the hal-internal
/// generic walker's enum directly.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MapErr {
    /// Frame allocator returned `None` mid-walk.
    AllocFailed,
    /// An intermediate entry exists but is a 1 GiB / 2 MiB huge
    /// page (PS=1). We don't break those apart in this routine.
    HitHugePage,
    /// Leaf already present at `va` and points elsewhere.
    AlreadyMapped,
}

impl From<WalkErr> for MapErr {
    fn from(e: WalkErr) -> Self {
        match e {
            WalkErr::AllocFailed   => MapErr::AllocFailed,
            WalkErr::HitHugeOrBlock => MapErr::HitHugePage,
            WalkErr::AlreadyMapped => MapErr::AlreadyMapped,
        }
    }
}

/// x86_64 walker bit semantics.
pub struct PtWalkerX86;

impl PtWalker for PtWalkerX86 {
    const PHYS_MASK: u64 = PHYS_MASK_X86;

    /// `mov {}, cr3` — privileged but legal at CPL=0.
    /// # SAFETY: per trait contract; CPL=0.
    unsafe fn read_pt_base(_va: u64) -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            let v: u64;
            // SAFETY: `mov r, cr3` is privileged but legal at CPL=0; no memory effect; result is the CR3 register including PCID bits.
            unsafe {
                core::arch::asm!(
                    "mov {}, cr3",
                    out(reg) v,
                    options(nomem, nostack, preserves_flags),
                );
            }
            return v & Self::PHYS_MASK;
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// `invlpg [va]` — invalidate the local TLB entry for `va`.
    /// # SAFETY: per trait contract; CPL=0.
    unsafe fn flush_va(va: u64) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `invlpg [m]` is privileged but legal at CPL=0; invalidates a single 4 KiB TLB entry on this CPU.
            unsafe {
                core::arch::asm!(
                    "invlpg [{}]",
                    in(reg) va,
                    options(nostack, preserves_flags),
                );
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { let _ = va; }
    }

    fn is_valid(entry: u64) -> bool { (entry & P_BIT) != 0 }

    fn is_huge_or_block(entry: u64) -> bool { (entry & PS_BIT) != 0 }

    fn pack_table(child_pa: u64) -> u64 {
        // Interior entries set U/S=1 unconditionally so any user-leaf
        // along the walk is reachable; the leaf U bit alone gates user
        // access. Kernel-only leaves still set U=0 → CPL=3 access
        // faults at the leaf, regardless of interior bits.
        (child_pa & Self::PHYS_MASK) | P_BIT | RW_BIT | (1 << 2)
    }

    fn pack_device_leaf(pa: u64) -> u64 {
        (pa & Self::PHYS_MASK) | P_BIT | RW_BIT
            | crate::pat::PCD | crate::pat::PWT | NX_BIT
    }

    fn pack_4k_leaf(pa: u64, flags: hal::PageFlags) -> u64 {
        // P_BIT (PRESENT) implicit on a leaf. RW from WRITE.
        // USER from USER. NX = clear iff EXEC. Cache bits come from the one
        // PAT translator shared with reverse translation. GLOBAL from GLOBAL.
        let mut e = (pa & Self::PHYS_MASK) | P_BIT;
        // A monitor's barrier and write permission are one fact: a leaf built
        // protected is never briefly writable, so a peer thread cannot slip a
        // write past the barrier between the install and a later re-protect.
        if flags.contains(hal::PageFlags::UFFD_WP)       { e |= UFFD_WP_BIT; }
        else if flags.contains(hal::PageFlags::WRITE)    { e |= RW_BIT; }
        if flags.contains(hal::PageFlags::USER)          { e |= 1 << 2; }   // U/S
        e |= crate::pat::cache_bits(flags, false);
        if flags.contains(hal::PageFlags::GLOBAL)        { e |= 1 << 8; }   // G
        e |= (flags.pkey() as u64) << 59;
        if !flags.contains(hal::PageFlags::EXEC)         { e |= NX_BIT; }
        e
    }

    fn pack_block_leaf(pa: u64, flags: hal::PageFlags) -> u64 {
        // A huge leaf uses bit 12 for PAT, not the 4 KiB leaf's bit 7 (which
        // is PS here). Build the non-cache controls directly so WT selects
        // Linux PAT slot 7 without corrupting the leaf kind.
        let mut e = (pa & Self::PHYS_MASK) | P_BIT | PS_BIT;
        if flags.contains(hal::PageFlags::UFFD_WP)       { e |= UFFD_WP_BIT; }
        else if flags.contains(hal::PageFlags::WRITE)    { e |= RW_BIT; }
        if flags.contains(hal::PageFlags::USER)          { e |= 1 << 2; }
        e |= crate::pat::cache_bits(flags, true);
        if flags.contains(hal::PageFlags::GLOBAL)        { e |= 1 << 8; }
        e |= (flags.pkey() as u64) << 59;
        if !flags.contains(hal::PageFlags::EXEC)         { e |= NX_BIT; }
        e
    }

    fn pack_swap_entry(entry: hal::pt_walker::SwapEntry) -> u64 {
        SWAP_MARKER | ((entry.kind() as u64) << SWAP_TYPE_SHIFT) | (entry.offset() << SWAP_OFFSET_SHIFT)
    }

    fn unpack_swap_entry(raw: u64) -> Option<hal::pt_walker::SwapEntry> {
        if (raw & P_BIT) != 0 || (raw & SWAP_MARKER) == 0 || (raw & MIGRATION_MARKER) != 0 { return None; }
        let kind = ((raw >> SWAP_TYPE_SHIFT) & hal::pt_walker::SwapEntry::MAX_KIND as u64) as u8;
        let offset = (raw >> SWAP_OFFSET_SHIFT) & hal::pt_walker::SwapEntry::MAX_OFFSET;
        hal::pt_walker::SwapEntry::new(kind, offset)
    }
    fn pack_migration_entry(entry: hal::pt_walker::MigrationEntry) -> u64 {
        MIGRATION_MARKER | (entry.token() << SWAP_OFFSET_SHIFT)
    }
    fn unpack_migration_entry(raw: u64) -> Option<hal::pt_walker::MigrationEntry> {
        if (raw & P_BIT) != 0 || (raw & MIGRATION_MARKER) == 0 { return None; }
        hal::pt_walker::MigrationEntry::new((raw >> SWAP_OFFSET_SHIFT) & hal::pt_walker::MigrationEntry::MAX_TOKEN)
    }

    /// Unconditionally true: a live linear-map block leaf on this architecture
    /// is replaced by a table of smaller leaves with the same output addresses
    /// and attributes, and the hardware tolerates the transient window in which
    /// a TLB may hold both granularities for the same address, provided the two
    /// translations agree — which a same-attribute split guarantees.
    fn can_split_kernel_leaf() -> bool { true }

    fn split_child_leaf(block: u64, child_pa: u64, child_level: u8) -> u64 {
        // The memory-type index's high selector bit lives at descriptor bit 12
        // on a block leaf and at descriptor bit 7 on a bottom-level leaf,
        // because bit 7 is the block-size selector above the bottom level. A
        // split therefore has to MOVE that bit when it produces bottom-level
        // children, or the child silently changes memory type.
        let type_hi = (block >> BLOCK_TYPE_HI_SHIFT) & 1;
        let attrs = block & !Self::PHYS_MASK;
        if child_level == LEAF_LEVEL_4K {
            (attrs & !PS_BIT) | (type_hi << LEAF_TYPE_HI_SHIFT) | (child_pa & Self::PHYS_MASK)
        } else {
            attrs | (type_hi << BLOCK_TYPE_HI_SHIFT) | (child_pa & Self::PHYS_MASK)
        }
    }

    /// Stores on this architecture are already ordered against each other as
    /// seen by any observer, including a table walker, so only the compiler
    /// needs to be prevented from sinking the table fill past the publish.
    fn publish_table_barrier() { core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release); }

    fn leaf_set_present(raw: u64, present: bool) -> u64 {
        if present { raw | P_BIT | RW_BIT } else { raw & !(P_BIT | RW_BIT | DIRTY_BIT) }
    }

    fn leaf_wrprotect(raw: u64) -> u64 { raw & !RW_BIT }
    fn leaf_set_uffd_wp(raw: u64) -> u64 { raw | UFFD_WP_BIT }
    fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw & !UFFD_WP_BIT }
    fn leaf_is_uffd_wp(raw: u64) -> bool { (raw & P_BIT) != 0 && (raw & UFFD_WP_BIT) != 0 }
    fn nonpresent_set_uffd_wp(raw: u64) -> u64 { raw | UFFD_WP_BIT }
    fn nonpresent_clear_uffd_wp(raw: u64) -> u64 { raw & !UFFD_WP_BIT }
    fn nonpresent_is_uffd_wp(raw: u64) -> bool { (raw & P_BIT) == 0 && (raw & UFFD_WP_BIT) != 0 }
    fn pack_pte_marker(m: hal::pt_walker::PteMarker) -> u64 {
        PTE_MARKER | ((m.bits() as u64) << PTE_MARKER_KIND_SHIFT)
    }
    fn unpack_pte_marker(raw: u64) -> Option<hal::pt_walker::PteMarker> {
        if (raw & P_BIT) != 0 || (raw & PTE_MARKER) == 0 { return None; }
        hal::pt_walker::PteMarker::from_bits(
            ((raw >> PTE_MARKER_KIND_SHIFT) as u32) & hal::pt_walker::PteMarker::MASK)
    }
}

/// Install a 4 KiB Device-attr (PCD|PWT, NX) mapping `va → pa` in
/// the active PML4 tree. Walks via HHDM, allocating intermediate
/// PDPT/PD/PT pages from `alloc_pa` as needed.
///
/// `alloc_pa()` returns the physical address of a fresh, zero-able
/// page-aligned frame. Caller (kernel) typically wraps PMM:
/// `|| pmm.alloc(Order(0)).ok().map(|pfn| pfn.0 * 4096)`.
///
/// # SAFETY: caller asserts (a) `va` is canonical and not currently
/// owned by another subsystem, (b) `pa` is a real device MMIO base,
/// (c) `hhdm_offset` covers all RAM that holds page-table memory,
/// (d) `alloc_pa` returns frames the kernel exclusively owns. Single-
/// CPU, IRQ-off context.
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn map_device_4k<F: FnMut() -> Option<u64>>(
    va: u64,
    pa: u64,
    hhdm_offset: u64,
    alloc_pa: F,
) -> Result<(), MapErr> {
    // SAFETY: delegated to the generic walker; preconditions mirror
    // ours per its trait contract.
    unsafe { pt_walker::map_device_4k::<PtWalkerX86, _>(va, pa, hhdm_offset, alloc_pa) }
        .map_err(MapErr::from)
}

#[cfg(test)]
mod tests;
