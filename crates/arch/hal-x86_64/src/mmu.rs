// x86_64 MMU primitives per `20§5`. v1 lands the encoding + flush
// surface; the actual page-table walker (`MmuOps::map` / `unmap` /
// `translate`) drives off prerequisites that aren't in yet:
//   - kernel direct-map (linker script + boot bring-up)
//   - PMM handle for allocating intermediate tables
//   - global active-PT root (CR3) tracked at boot
// Once those land, the walker drops in atop the constants + Pte
// encoding here.

use hal::{PageFlags, PageSize};

/// 4-level paging per `20§5`. Each table holds 512 entries × 8 B = 4 KiB.
pub const ENTRIES_PER_TABLE: usize = 512;
pub const PAGE_SHIFT_4K: u32 = 12;
pub const PT_SHIFT:   u32 = 12; // PT entry covers 4 KiB
pub const PD_SHIFT:   u32 = 21; // PD entry covers 2 MiB
pub const PDPT_SHIFT: u32 = 30; // PDPT entry covers 1 GiB
pub const PML4_SHIFT: u32 = 39; // PML4 entry covers 512 GiB

/// Index mask for 9-bit table indices.
pub const TABLE_IDX_MASK: u64 = 0x1ff;

/// Indices into each level for a virtual address per `20§5` Fig. 4-8.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PtIndices {
    pub pml4: u16,
    pub pdpt: u16,
    pub pd:   u16,
    pub pt:   u16,
    pub off:  u16, // 12-bit page offset
}

/// Decompose a 48-bit canonical virtual address into level indices.
/// Sign-extension above bit 47 isn't checked here; caller validates
/// canonicality before walking.
/// # C: O(1)
pub const fn va_to_indices(va: u64) -> PtIndices {
    PtIndices {
        pml4: ((va >> PML4_SHIFT) & TABLE_IDX_MASK) as u16,
        pdpt: ((va >> PDPT_SHIFT) & TABLE_IDX_MASK) as u16,
        pd:   ((va >> PD_SHIFT)   & TABLE_IDX_MASK) as u16,
        pt:   ((va >> PT_SHIFT)   & TABLE_IDX_MASK) as u16,
        off:  (va & 0xfff) as u16,
    }
}

/// Page-table entry per `20§5` (Intel SDM Vol. 3 Tab. 4-19/4-20). The
/// physical-frame field is bits 51:12; bits 62:52 are software-defined
/// or reserved depending on level; bit 63 is NX.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PteX86_64(pub u64);

bitflags::bitflags! {
    /// Per-entry x86_64 control bits. Native bit positions match
    /// Intel SDM exactly; convert to/from `hal::PageFlags` via
    /// `PteX86_64::flags_to_native` / `flags_from_native`.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct PteFlags: u64 {
        const PRESENT     = 1 << 0;
        const WRITABLE    = 1 << 1;
        const USER        = 1 << 2;
        const WRITETHRU   = 1 << 3;
        const NOCACHE     = 1 << 4;
        const ACCESSED    = 1 << 5;
        const DIRTY       = 1 << 6;
        const HUGE        = 1 << 7;   // PD/PDPT level: 2 MiB / 1 GiB leaf
        const GLOBAL      = 1 << 8;
        const NX          = 1 << 63;
    }
}

/// Mask covering the physical-frame field (bits 51:12).
pub const PTE_PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;

impl PteX86_64 {
    /// # C: O(1)
    pub const fn empty() -> Self { Self(0) }

    /// Build a leaf PTE at the requested level.
    /// # C: O(1)
    pub const fn new_leaf(pa: u64, flags: PteFlags) -> Self {
        Self((pa & PTE_PHYS_MASK) | flags.bits())
    }

    /// # C: O(1)
    pub const fn is_present(self) -> bool {
        (self.0 & PteFlags::PRESENT.bits()) != 0
    }

    /// # C: O(1)
    pub const fn is_huge(self) -> bool {
        (self.0 & PteFlags::HUGE.bits()) != 0
    }

    /// Extract physical-frame bits.
    /// # C: O(1)
    pub const fn phys(self) -> u64 { self.0 & PTE_PHYS_MASK }

    /// Extract control flags.
    /// # C: O(1)
    pub const fn flags(self) -> PteFlags {
        PteFlags::from_bits_truncate(self.0 & !PTE_PHYS_MASK)
    }

    /// Convert architecture-neutral `hal::PageFlags` → x86 PTE bits.
    /// PRESENT is implicit (always set on a leaf). USER mirrors arch.
    /// NOCACHE / WRITETHRU mirror; READ is implicit by virtue of the
    /// entry being present; WRITE/EXEC encode as native + NX flip.
    /// # C: O(1)
    pub fn flags_from_native(n: PageFlags) -> PteFlags {
        let mut f = PteFlags::PRESENT;
        if n.contains(PageFlags::WRITE)   { f |= PteFlags::WRITABLE;  }
        if n.contains(PageFlags::USER)    { f |= PteFlags::USER;      }
        if n.contains(PageFlags::GLOBAL)  { f |= PteFlags::GLOBAL;    }
        if n.contains(PageFlags::NO_CACHE) { f |= PteFlags::NOCACHE;  }
        if n.contains(PageFlags::WRITE_THROUGH) { f |= PteFlags::WRITETHRU; }
        // EXEC bit is the *inverse* of NX in x86 — clear NX iff EXEC is set.
        if !n.contains(PageFlags::EXEC)   { f |= PteFlags::NX;        }
        f
    }

    /// Reverse mapping. `flags` is whatever was extracted from a live
    /// PTE; we drop bookkeeping bits (ACCESSED / DIRTY) that don't
    /// have a neutral counterpart.
    /// # C: O(1)
    pub fn flags_to_native(f: PteFlags) -> PageFlags {
        let mut n = PageFlags::READ;
        if f.contains(PteFlags::WRITABLE)  { n |= PageFlags::WRITE;  }
        if f.contains(PteFlags::USER)      { n |= PageFlags::USER;   }
        if f.contains(PteFlags::GLOBAL)    { n |= PageFlags::GLOBAL; }
        if f.contains(PteFlags::NOCACHE)   { n |= PageFlags::NO_CACHE; }
        if f.contains(PteFlags::WRITETHRU) { n |= PageFlags::WRITE_THROUGH; }
        if !f.contains(PteFlags::NX)       { n |= PageFlags::EXEC;   }
        n
    }

    /// Native PTE size used by `MmuOps::map(... size)` to pick the
    /// walk depth. `4 KiB` ⇒ leaf at PT level; `2 MiB` ⇒ PD-level
    /// HUGE; `1 GiB` ⇒ PDPT-level HUGE.
    /// # C: O(1)
    pub const fn level_for(size: PageSize) -> u8 {
        match size {
            PageSize::P4K => 0,
            PageSize::P2M => 1,
            PageSize::P1G => 2,
        }
    }
}

// ---------------------------------------------------------------------------
// TLB flush asm (`20§5` flush_va / flush_all_local)
// ---------------------------------------------------------------------------

/// Invalidate a single VA in the current CPU's TLB. The actual TLB
/// shootdown across CPUs (`MmuOps::flush_va`) layers this with an
/// IPI per `22§*`.
/// # SAFETY: privileged insn; legal at CPL=0.
/// # C: O(1)
pub unsafe fn flush_local_va(va: u64) {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `invlpg` is a privileged invalidation that affects
        // only the local TLB; no memory access beyond reading the
        // operand address as a virtual one. Caller asserts CPL=0.
        unsafe {
            core::arch::asm!(
                "invlpg [{v}]",
                v = in(reg) va,
                options(nostack, preserves_flags),
            );
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = va; }
}

/// Flush the entire TLB on this CPU. `mov cr3, cr3` reloads the
/// current PT root, invalidating all non-global entries. Global
/// entries are flushed via the dedicated PCID path which lands with
/// the KPTI work.
/// # C: O(1)
pub fn flush_local_all() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: privileged but side-effect-bounded — reload of CR3
        // with the same value flushes non-global TLB entries. No
        // memory access; `nostack` keeps codegen tight.
        unsafe {
            core::arch::asm!(
                "mov {tmp}, cr3",
                "mov cr3, {tmp}",
                tmp = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn va_indices_round_trip() {
        // Pick a recognisable VA: PML4=0x100, PDPT=0x080, PD=0x040,
        // PT=0x020, off=0x123.
        let va: u64 = (0x100u64 << PML4_SHIFT)
                    | (0x080u64 << PDPT_SHIFT)
                    | (0x040u64 << PD_SHIFT)
                    | (0x020u64 << PT_SHIFT)
                    | 0x123;
        let i = va_to_indices(va);
        assert_eq!(i.pml4, 0x100);
        assert_eq!(i.pdpt, 0x080);
        assert_eq!(i.pd,   0x040);
        assert_eq!(i.pt,   0x020);
        assert_eq!(i.off,  0x123);
    }

    #[test]
    fn pte_phys_mask_matches_intel_sdm_4_19() {
        // Bits 51:12 — `0x000f_ffff_ffff_f000`.
        assert_eq!(PTE_PHYS_MASK, 0x000f_ffff_ffff_f000);
    }

    #[test]
    fn pte_new_leaf_packs_pa_and_flags() {
        let pa: u64 = 0x1234_5000;
        let f = PteFlags::PRESENT | PteFlags::WRITABLE | PteFlags::NX;
        let pte = PteX86_64::new_leaf(pa, f);
        assert!(pte.is_present());
        assert!(!pte.is_huge());
        assert_eq!(pte.phys(), pa);
        assert_eq!(pte.flags(), f);
    }

    #[test]
    fn pte_native_to_arch_round_trip_rwx() {
        let n = PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER;
        let f = PteX86_64::flags_from_native(n);
        assert!(f.contains(PteFlags::PRESENT));
        assert!(f.contains(PteFlags::WRITABLE));
        assert!(f.contains(PteFlags::USER));
        assert!(!f.contains(PteFlags::NX), "EXEC ⇒ !NX");
        let back = PteX86_64::flags_to_native(f);
        // Round-trip: every neutral bit we set is set back; READ
        // is always implied present.
        assert!(back.contains(PageFlags::READ));
        assert!(back.contains(PageFlags::WRITE));
        assert!(back.contains(PageFlags::USER));
        assert!(back.contains(PageFlags::EXEC));
    }

    #[test]
    fn pte_no_exec_native_sets_nx() {
        let n = PageFlags::READ | PageFlags::WRITE; // no EXEC
        let f = PteX86_64::flags_from_native(n);
        assert!(f.contains(PteFlags::NX), "missing EXEC ⇒ NX set");
    }

    #[test]
    fn level_for_page_size_matches_intel_walk_depth() {
        // 4 KiB leaf at PT (level 0); 2 MiB at PD (level 1);
        // 1 GiB at PDPT (level 2).
        assert_eq!(PteX86_64::level_for(PageSize::P4K), 0);
        assert_eq!(PteX86_64::level_for(PageSize::P2M), 1);
        assert_eq!(PteX86_64::level_for(PageSize::P1G), 2);
    }

    #[test]
    fn flush_ops_compile_on_host() {
        // SAFETY: host fallback paths are no-ops; the asm cfg is off
        // here so we exercise only the stub branches.
        unsafe { flush_local_va(0x1000) };
        flush_local_all();
    }
}
