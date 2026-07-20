// aarch64 page-table walker per `21§5`. Splices a Device-nGnRnE
// 4 KiB leaf into the live TTBR1_EL1 tree.
//
// The walk loop is shared with x86_64 in `hal::pt_walker`; this
// file supplies the arm bit semantics + privileged-register access
// via the `PtWalker` trait.
//
// Limine programs MAIR_EL1 = 0xff: byte 0 = Normal WB-cacheable,
// bytes 1..7 = Device-nGnRnE. We use AttrIdx = 1.

use hal::pt_walker::{self, PtWalker, WalkErr};

const VALID:    u64 = 1 << 0;
const TABLE:    u64 = 1 << 1;       // also "PAGE" at L3
// AttrIndx is descriptor bits[4:2], so AttrIdx 1 = bit 2 (1<<2). The old
// value (1<<3) is bit 3 = AttrIdx **2**, which only happened to work under
// Limine's MAIR=0xff (Normal@0, Device@2). Self-boot MAIR=0xFF04 puts Normal
// at AttrIdx1 (=0xFF) and Device at AttrIdx0 (=0x04); selecting AttrIdx2 there
// (=0x00) is Device too, so every page came out Device → EL0 unaligned reads
// took a DFSC=0x21 alignment abort. Use the real AttrIdx1 bit.
const ATTR1:    u64 = 1 << 2;       // AttrIdx 1 = Normal-WB under MAIR=0xFF04
const SH0:      u64 = 1 << 8;
const SH1:      u64 = 1 << 9;       // SH = 0b11 = Inner Shareable
const AF:       u64 = 1 << 10;
const PXN:      u64 = 1 << 53;
const UXN:      u64 = 1 << 54;
const AP_READ_ONLY_BIT: u64 = 1 << 7;
const PHYS_MASK_ARM: u64 = 0x0000_ffff_ffff_f000;
const SWAP_MARKER: u64 = 1 << 1;
const SWAP_TYPE_SHIFT: u8 = 2;
const SWAP_OFFSET_SHIFT: u8 = 12;
// With VALID=0 this is an invalid descriptor; bits[11:2] are ignored by
// translation under the configured 4 KiB granule/address-size. Bit 11 is
// therefore kernel software state and remains outside the payload.
const MIGRATION_MARKER: u64 = 1 << 11;

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

    /// `tlbi vae1is, va>>12; dsb ish; isb` — invalidate inner-shareable.
    /// # SAFETY: per trait contract; EL1.
    unsafe fn flush_va(va: u64) {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `tlbi vae1is` invalidates EL1 stage-1 entries matching the operand VA across the inner-shareable domain. dsb+isb serialize page-table writes vs. subsequent loads.
            unsafe {
                core::arch::asm!(
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
        // Device MMIO. Self-boot MAIR_EL1=0xFF04: Attr0=Device-nGnRE,
        // Attr1=Normal-WB → Device uses AttrIdx0 (no ATTR1 bit). The old
        // Limine MAIR (0xff) had Device at AttrIdx1; Limine is gone, so
        // this matches the self-boot asm page tables (Device blocks =
        // 0x0401 → AttrIdx0). Mapping device as AttrIdx1 here = Normal-WB
        // (wrong; only TCG-tolerated).
        (pa & Self::PHYS_MASK) | VALID | TABLE | SH0 | SH1 | AF | PXN | UXN
    }

    fn pack_4k_leaf(pa: u64, flags: hal::PageFlags) -> u64 {
        // L3 page leaf: VALID|TABLE always; AF set so the CPU
        // doesn't trap on first access. Inner-Shareable. AttrIdx picks
        // the MAIR_EL1 byte. Self-boot MAIR=0xFF04: Attr0=Device-nGnRE,
        // Attr1=Normal-WB. So cached(Normal) → AttrIdx1 (ATTR1 set),
        // NO_CACHE(Device) → AttrIdx0. (Limine's 0xff had these swapped;
        // Limine is gone.) Mapping Normal as AttrIdx0 = Device made every
        // demand-faulted user page Device → unaligned reads took a DFSC
        // 0x21 alignment abort (the arm -smp 2 crash).
        let mut e = (pa & Self::PHYS_MASK) | VALID | TABLE | AF | SH0 | SH1;
        // AP[2:1] in bits 6:7. AP=0b00 = EL1 RW. AP=0b01 = EL0/EL1 RW.
        // AP=0b10 = EL1 RO. AP=0b11 = EL0/EL1 RO.
        let user = flags.contains(hal::PageFlags::USER);
        let writable = flags.contains(hal::PageFlags::WRITE);
        let ap = match (user, writable) {
            (false, true)  => 0b00, // kernel RW
            (false, false) => 0b10, // kernel RO
            (true,  true)  => 0b01, // user RW
            (true,  false) => 0b11, // user RO
        };
        e |= (ap as u64) << 6;
        if !flags.contains(hal::PageFlags::NO_CACHE) { e |= ATTR1; }
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
mod tests {
    use super::*;

    #[test]
    fn map_err_distinct() {
        assert_ne!(MapErr::AllocFailed, MapErr::HitBlockDescriptor);
        assert_ne!(MapErr::HitBlockDescriptor, MapErr::AlreadyMapped);
    }

    #[test]
    fn arm_walker_pack_unpack_roundtrip() {
        let pa = 0xdead_b000_u64;
        let leaf = PtWalkerArm::pack_device_leaf(pa);
        assert!(PtWalkerArm::is_valid(leaf));
        // L3 page leaves keep TABLE set; the walker driver only
        // calls is_huge_or_block on intermediate entries.
        assert_eq!(leaf & PtWalkerArm::PHYS_MASK, pa);
        let table = PtWalkerArm::pack_table(pa);
        assert!(PtWalkerArm::is_valid(table));
        assert!(!PtWalkerArm::is_huge_or_block(table));
        assert_eq!(table & PtWalkerArm::PHYS_MASK, pa);
    }

}
