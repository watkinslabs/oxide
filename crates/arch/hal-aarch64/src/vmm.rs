// aarch64 page-table walker per `21§5`. Splices a Device-nGnRnE
// 4 KiB leaf into the live TTBR1_EL1 tree.
//
// The walk loop is shared with x86_64 in `hal::pt_walker`; this
// file supplies the arm bit semantics + privileged-register access
// via the `PtWalker` trait.
//
// The self-boot trampoline programs MAIR_EL1 = 0x44FF04: Attr0 =
// Device-nGnRE, Attr1 = Normal WB, Attr2 = Normal NC. Linux uses Normal NC
// for `pgprot_writecombine`, so framebuffer mappings select AttrIdx 2.

use hal::pt_walker::{self, PtWalker, WalkErr};

pub mod linear;

const VALID:    u64 = 1 << 0;
const TABLE:    u64 = 1 << 1;       // also "PAGE" at L3
// AttrIndx is descriptor bits[4:2]. AttrIdx1 is bit 2 and AttrIdx2 is bit 3;
// those slots are Normal-WB and Normal-NC respectively in the boot MAIR.
const ATTR_NORMAL_WB: u64 = 1 << 2; // AttrIdx 1
const ATTR_NORMAL_NC: u64 = 1 << 3; // AttrIdx 2
const SH0:      u64 = 1 << 8;
const SH1:      u64 = 1 << 9;       // SH = 0b11 = Inner Shareable
const AF:       u64 = 1 << 10;
/// Contiguous hint — a run of leaves the TLB may fold into one entry.
const CONT:     u64 = 1 << 52;
/// Bottom (4 KiB) level index in the shared four-level walker.
const LEAF_LEVEL_4K: u8 = 3;
const PXN:      u64 = 1 << 53;
const UXN:      u64 = 1 << 54;
const PO_INDEX_SHIFT: u8 = 60;
const PHYS_MASK_ARM: u64 = 0x0000_ffff_ffff_f000;
const SWAP_MARKER: u64 = 1 << 1;
const SWAP_TYPE_SHIFT: u8 = 2;
const SWAP_OFFSET_SHIFT: u8 = 12;
// With VALID=0 this is an invalid descriptor; bits[11:2] are ignored by
// translation under the configured 4 KiB granule/address-size. Bit 11 is
// therefore kernel software state and remains outside the payload.
const MIGRATION_MARKER: u64 = 1 << 11;
// AP[2] — clear = writable, set = read-only, at both exception levels.
const AP2_RDONLY: u64 = 1 << 7;
// Descriptor bit 58 is software-reserved on this architecture, so a leaf can
// carry the userfaultfd write-protect marker without changing translation —
// and with VALID=0 the whole descriptor is software state anyway.
//
// The SAME bit carries the state on a NON-PRESENT leaf without ambiguity: it
// lies outside every field the three non-present encodings are identified or
// decoded by. Swap entries are named by bit 1 and decode bits 2..=6 and
// 12..=51; migration entries are named by bit 11 and decode 12..=51; markers
// are named by bit 10 and decode 12..=13. Bit 58 is in none of those, so it
// changes no identity and no payload, and the "valid or not" question — which
// the two predicates below split on — is exactly what separates a page's own
// barrier from the barrier riding on a reference to a page that is elsewhere.
const UFFD_WP_BIT: u64 = 1 << 58;
// With VALID=0, bit 10 is ignored by translation and is disjoint from the swap
// (bit 1) and migration (bit 11) markers, so a marker leaf decodes as neither
// and neither decodes as a marker. The kinds ride in the same payload field the
// swap offset and the migration token occupy: that field can never make a swap
// or migration entry out of a marker, because those two are identified by bits
// 1 and 11 and a marker sets neither.
const PTE_MARKER: u64 = 1 << 10;
const PTE_MARKER_KIND_SHIFT: u8 = 12;

/// Errors `map_device_4k` can return. Mirrors `WalkErr` 1:1.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MapErr {
    /// Frame allocator returned `None` mid-walk.
    AllocFailed,
    /// An intermediate entry is a BLOCK descriptor (huge page).
    HitBlockDescriptor,
    /// Leaf already present and points elsewhere.
    AlreadyMapped,
}

impl From<WalkErr> for MapErr {
    fn from(e: WalkErr) -> Self {
        match e {
            WalkErr::AllocFailed    => MapErr::AllocFailed,
            WalkErr::HitHugeOrBlock => MapErr::HitBlockDescriptor,
            WalkErr::AlreadyMapped  => MapErr::AlreadyMapped,
        }
    }
}

/// aarch64 walker bit semantics. The TTBR1_EL1 path is what we
/// install kernel-VA mappings into; TTBR0_EL1 (user) rides a
/// future `PtWalkerArmUser` impl with the same shape.
pub struct PtWalkerArm;

impl PtWalker for PtWalkerArm {
    const PHYS_MASK: u64 = PHYS_MASK_ARM;

    /// Pick TTBR0_EL1 (user-half) or TTBR1_EL1 (kernel-half) by the
    /// VA's bit 55 — the standard ARM ARM D5.2.4 split-translation
    /// rule. Bit 55 high → kernel mapping (e.g. 0xFFFF_xxxx_xxxx_xxxx
    /// HHDM addresses); else user (e.g. low-half 0x0000_0000_0040_0000).
    /// Letting MmuOps::map(USER_VA, ...) plumb into TTBR0 without a
    /// separate walker impl.
    /// # SAFETY: per trait contract; privileged read at EL1.
    unsafe fn read_pt_base(va: u64) -> u64 {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            let v: u64;
            let kernel_half = (va >> 55) & 1 == 1;
            // SAFETY: `mrs x, ttbr{0,1}_el1` is privileged at EL1; no memory effect; result is the per-tree page-table root PA.
            unsafe {
                if kernel_half {
                    core::arch::asm!(
                        "mrs {}, ttbr1_el1",
                        out(reg) v,
                        options(nomem, nostack, preserves_flags),
                    );
                } else {
                    core::arch::asm!(
                        "mrs {}, ttbr0_el1",
                        out(reg) v,
                        options(nomem, nostack, preserves_flags),
                    );
                }
            }
            return v & Self::PHYS_MASK;
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { let _ = va; 0 }
    }

    /// `dsb ishst; tlbi vae1is, va>>12; dsb ish; isb` — invalidate
    /// inner-shareable, using Linux's exact arm64 template.
    /// # SAFETY: per trait contract; EL1.
    unsafe fn flush_va(va: u64) {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // The LEADING `dsb ishst` is required, not decorative: it makes
            // the caller's page-table store visible to every other PE's table
            // walker BEFORE the broadcast invalidate runs. Without it a peer
            // walker can re-cache the stale descriptor after the TLBI and the
            // invalidate is silently lost. The `dsb ish` + `isb` tail orders
            // the completed invalidate against subsequent loads.
            // SAFETY: `tlbi vae1is` is an EL1-privileged stage-1 invalidate of
            // the operand VA across the inner-shareable domain, legal here
            // because this trait method is `unsafe` and only runs at EL1; it
            // touches no memory, so the operand needs no mapping.
            unsafe {
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vae1is, {v}",
                    "dsb ish",
                    "isb",
                    v = in(reg) (va >> 12),
                    options(nostack, preserves_flags),
                );
            }
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        { let _ = va; }
    }

    fn is_valid(entry: u64) -> bool { (entry & VALID) != 0 }

    /// At intermediate levels, `TABLE` set => points at next level
    /// (descend); cleared on a present entry => block descriptor
    /// (huge page). At L3 the same bit is repurposed as PAGE; the
    /// driver only calls this on intermediate-level entries (the
    /// L3 leaf is read directly without the huge-block check).
    fn is_huge_or_block(entry: u64) -> bool { (entry & TABLE) == 0 }

    fn pack_table(child_pa: u64) -> u64 {
        (child_pa & Self::PHYS_MASK) | VALID | TABLE
    }

    fn pack_device_leaf(pa: u64) -> u64 {
        // Device MMIO. Self-boot MAIR Attr0=Device-nGnRE,
        // Attr1=Normal-WB → Device uses AttrIdx0 (no AttrIndx bits). This
        // matches the self-boot asm page tables (Device blocks =
        // 0x0401 → AttrIdx0). Mapping device as AttrIdx1 here = Normal-WB
        // (wrong; only TCG-tolerated).
        (pa & Self::PHYS_MASK) | VALID | TABLE | SH0 | SH1 | AF | PXN | UXN
    }

    fn pack_4k_leaf(pa: u64, flags: hal::PageFlags) -> u64 {
        // L3 page leaf: VALID|TABLE always; AF set so the CPU
        // doesn't trap on first access. Inner-Shareable. AttrIdx picks
        // the MAIR_EL1 byte. Cached Normal uses AttrIdx1, write-combining
        // uses Linux's Normal-NC AttrIdx2, and NO_CACHE(Device) uses AttrIdx0.
        // Mapping Normal as AttrIdx0 = Device made every
        // demand-faulted user page Device → unaligned reads took a DFSC
        // 0x21 alignment abort (the arm -smp 2 crash).
        let mut e = (pa & Self::PHYS_MASK) | VALID | TABLE | AF | SH0 | SH1;
        // AP[2:1] in bits 6:7. AP=0b00 = EL1 RW. AP=0b01 = EL0/EL1 RW.
        // AP=0b10 = EL1 RO. AP=0b11 = EL0/EL1 RO.
        let user = flags.contains(hal::PageFlags::USER);
        // A monitor's barrier and write permission are one fact: a leaf built
        // protected is never briefly writable, so a peer thread cannot slip a
        // write past the barrier between the install and a later re-protect.
        let protected = flags.contains(hal::PageFlags::UFFD_WP);
        if protected { e |= UFFD_WP_BIT; }
        let writable = flags.contains(hal::PageFlags::WRITE) && !protected;
        let ap = match (user, writable) {
            (false, true)  => 0b00, // kernel RW
            (false, false) => 0b10, // kernel RO
            (true,  true)  => 0b01, // user RW
            (true,  false) => 0b11, // user RO
        };
        e |= (ap as u64) << 6;
        if flags.contains(hal::PageFlags::NO_CACHE) {
            // AttrIdx0: Device-nGnRE.
        } else if flags.contains(hal::PageFlags::WRITE_COMBINE) {
            e |= ATTR_NORMAL_NC;
        } else {
            e |= ATTR_NORMAL_WB;
        }
        // Execute permission. UXN/PXN per `21§5`. Layout per
        // PageFlags::USER:
        //   USER=1, EXEC=1: user-executable.   PXN=1, UXN=0.
        //   USER=1, EXEC=0: user no-exec.      PXN=1, UXN=1.
        //   USER=0, EXEC=1: kernel executable. PXN=0, UXN=1.
        //   USER=0, EXEC=0: kernel no-exec.    PXN=1, UXN=1.
        let exec = flags.contains(hal::PageFlags::EXEC);
        let (pxn, uxn) = match (user, exec) {
            (false, true)  => (false, true),
            (false, false) => (true,  true),
            (true,  true)  => (true,  false),
            (true,  false) => (true,  true),
        };
        if pxn { e |= PXN; }
        if uxn { e |= UXN; }
        e |= ((flags.pkey() as u64) & 0x7) << PO_INDEX_SHIFT;
        e
    }

    fn pack_block_leaf(pa: u64, flags: hal::PageFlags) -> u64 {
        // L1/L2 block descriptor: same field positions as the L3
        // page leaf except the TABLE bit must be CLEAR (block) rather
        // than set (page/table). Mask it off after the 4K packer.
        let e = Self::pack_4k_leaf(pa, flags);
        e & !TABLE
    }

    fn pack_swap_entry(entry: hal::pt_walker::SwapEntry) -> u64 {
        SWAP_MARKER | ((entry.kind() as u64) << SWAP_TYPE_SHIFT) | (entry.offset() << SWAP_OFFSET_SHIFT)
    }

    fn unpack_swap_entry(raw: u64) -> Option<hal::pt_walker::SwapEntry> {
        if (raw & VALID) != 0 || (raw & SWAP_MARKER) == 0 || (raw & MIGRATION_MARKER) != 0 { return None; }
        let kind = ((raw >> SWAP_TYPE_SHIFT) & hal::pt_walker::SwapEntry::MAX_KIND as u64) as u8;
        let offset = (raw >> SWAP_OFFSET_SHIFT) & hal::pt_walker::SwapEntry::MAX_OFFSET;
        hal::pt_walker::SwapEntry::new(kind, offset)
    }
    fn pack_migration_entry(entry: hal::pt_walker::MigrationEntry) -> u64 {
        MIGRATION_MARKER | (entry.token() << SWAP_OFFSET_SHIFT)
    }
    fn unpack_migration_entry(raw: u64) -> Option<hal::pt_walker::MigrationEntry> {
        if (raw & VALID) != 0 || (raw & MIGRATION_MARKER) == 0 { return None; }
        hal::pt_walker::MigrationEntry::new((raw >> SWAP_OFFSET_SHIFT) & hal::pt_walker::MigrationEntry::MAX_TOKEN)
    }

    /// Answered by `linear::page_removable_from_linear_map`: either the linear
    /// map's RAM already has a bottom-level leaf for every page, in which case
    /// no granularity changes at all, or the implementation advertises that a
    /// live one is free of translation-conflict aborts. The boot policy
    /// supplies the first, so the answer does not depend on the second.
    fn can_split_kernel_leaf() -> bool {
        linear::page_removable_from_linear_map(
            linear::LINEAR_MAP_RAM_PAGE_GRANULAR, linear::read_id_aa64mmfr2())
    }

    fn split_child_leaf(block: u64, child_pa: u64, child_level: u8) -> u64 {
        // Descriptor kind is the only field that differs between a block leaf
        // and a bottom-level page leaf: the same bit reads as "block" when
        // clear above the bottom level and must be SET on a bottom-level page.
        // The contiguous hint is dropped because the split children no longer
        // form the run the hint promised.
        let e = (block & !Self::PHYS_MASK & !CONT) | (child_pa & Self::PHYS_MASK);
        if child_level == LEAF_LEVEL_4K { e | TABLE } else { e & !TABLE }
    }

    /// A table walker on this architecture is not coherent with the store
    /// buffer, so the table fill needs a store barrier — not merely release
    /// ordering — before the entry that publishes it becomes visible.
    fn publish_table_barrier() {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        // SAFETY: `dsb ishst` is an unprivileged store barrier over the
        // inner-shareable domain; it touches no memory and has no operands.
        unsafe { core::arch::asm!("dsb ishst", options(nostack, preserves_flags)); }
    }

    fn leaf_set_present(raw: u64, present: bool) -> u64 {
        if present { raw | VALID } else { raw & !VALID }
    }

    fn leaf_wrprotect(raw: u64) -> u64 { raw | AP2_RDONLY }
    fn leaf_set_uffd_wp(raw: u64) -> u64 { raw | UFFD_WP_BIT }
    fn leaf_clear_uffd_wp(raw: u64) -> u64 { raw & !UFFD_WP_BIT }
    fn leaf_is_uffd_wp(raw: u64) -> bool { (raw & VALID) != 0 && (raw & UFFD_WP_BIT) != 0 }
    fn nonpresent_set_uffd_wp(raw: u64) -> u64 { raw | UFFD_WP_BIT }
    fn nonpresent_clear_uffd_wp(raw: u64) -> u64 { raw & !UFFD_WP_BIT }
    fn nonpresent_is_uffd_wp(raw: u64) -> bool { (raw & VALID) == 0 && (raw & UFFD_WP_BIT) != 0 }
    fn pack_pte_marker(m: hal::pt_walker::PteMarker) -> u64 {
        PTE_MARKER | ((m.bits() as u64) << PTE_MARKER_KIND_SHIFT)
    }
    fn unpack_pte_marker(raw: u64) -> Option<hal::pt_walker::PteMarker> {
        if (raw & VALID) != 0 || (raw & PTE_MARKER) == 0 { return None; }
        hal::pt_walker::PteMarker::from_bits(
            ((raw >> PTE_MARKER_KIND_SHIFT) as u32) & hal::pt_walker::PteMarker::MASK)
    }
}

/// Install a 4 KiB Device-nGnRnE mapping `va → pa` into TTBR1_EL1.
///
/// # SAFETY: caller asserts (a) `va` is in TTBR1 range and not
/// owned by another subsystem, (b) `pa` is a real device MMIO base,
/// (c) `hhdm_offset` covers RAM that holds page tables, (d)
/// `alloc_pa` returns kernel-owned frames. Single-CPU, IRQ-off.
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
    unsafe { pt_walker::map_device_4k::<PtWalkerArm, _>(va, pa, hhdm_offset, alloc_pa) }
        .map_err(MapErr::from)
}

#[cfg(test)]
mod tests;
