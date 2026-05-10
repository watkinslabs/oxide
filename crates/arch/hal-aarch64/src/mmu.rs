// aarch64 MMU primitives per `21§5`. v1 lands the encoding + flush
// surface; the actual page-table walker drops in once the kernel
// direct-map (linker script + boot bring-up), PMM handle for
// allocating intermediate tables, and active TTBR1_EL1 tracker exist.

use hal::{PageFlags, PageSize};

/// 4-level paging per `21§5`. Each table holds 512 entries × 8 B.
pub const ENTRIES_PER_TABLE: usize = 512;
pub const L0_SHIFT: u32 = 39; // 512 GiB stride
pub const L1_SHIFT: u32 = 30; // 1 GiB
pub const L2_SHIFT: u32 = 21; // 2 MiB
pub const L3_SHIFT: u32 = 12; // 4 KiB
pub const TABLE_IDX_MASK: u64 = 0x1ff;

/// Indices into each level for a virtual address per `21§5`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PtIndices {
    pub l0:  u16,
    pub l1:  u16,
    pub l2:  u16,
    pub l3:  u16,
    pub off: u16,
}

/// Decompose a 48-bit canonical virtual address into level indices.
/// # C: O(1)
pub const fn va_to_indices(va: u64) -> PtIndices {
    PtIndices {
        l0:  ((va >> L0_SHIFT) & TABLE_IDX_MASK) as u16,
        l1:  ((va >> L1_SHIFT) & TABLE_IDX_MASK) as u16,
        l2:  ((va >> L2_SHIFT) & TABLE_IDX_MASK) as u16,
        l3:  ((va >> L3_SHIFT) & TABLE_IDX_MASK) as u16,
        off: (va & 0xfff) as u16,
    }
}

/// VMSAv8-64 stage 1 descriptor per `21§5` (ARM ARM D5.3). The
/// physical-frame field is bits 47:12; lower attribute bits encode
/// access-perm + cacheability.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PteArm64(pub u64);

bitflags::bitflags! {
    /// VMSAv8 PTE bits — names match ARM ARM nomenclature.
    /// `VALID|TABLE` distinguishes leaf-vs-table at non-leaf levels;
    /// at L3 the encoding is `VALID|PAGE` (=0x3); intermediate
    /// tables use `VALID|TABLE` (=0x3 too — disambiguation is by
    /// level, not bit). `BLOCK` (=0x1) is used for huge leaves at
    /// L1/L2.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct PteFlags: u64 {
        const VALID  = 1 << 0;
        const TABLE  = 1 << 1;  // also "PAGE" at L3
        const ATTR0  = 1 << 2;  // MAIR index, low bit
        const ATTR1  = 1 << 3;  // MAIR index, mid bit
        const ATTR2  = 1 << 4;  // MAIR index, high bit
        const NS     = 1 << 5;
        const AP_RO  = 1 << 7;  // AP[2]: 0=RW, 1=RO
        const AP_EL0 = 1 << 6;  // AP[1]: 1=EL0 accessible
        const SH0    = 1 << 8;  // SH[0]
        const SH1    = 1 << 9;  // SH[1]: 11=Inner Shareable
        const AF     = 1 << 10; // Access Flag
        const NG     = 1 << 11; // Not Global (per-ASID)
        const PXN    = 1 << 53; // Privileged eXecute Never
        const UXN    = 1 << 54; // Unprivileged eXecute Never
    }
}

/// Mask covering the physical-frame field (bits 47:12).
pub const PTE_PHYS_MASK: u64 = 0x0000_ffff_ffff_f000;

impl PteArm64 {
    /// # C: O(1)
    pub const fn empty() -> Self { Self(0) }

    /// Build an L3 leaf (`VALID|TABLE` for 4 KiB pages per ARM ARM).
    /// # C: O(1)
    pub const fn new_leaf(pa: u64, flags: PteFlags) -> Self {
        Self((pa & PTE_PHYS_MASK) | flags.bits())
    }

    /// # C: O(1)
    pub const fn is_valid(self) -> bool {
        (self.0 & PteFlags::VALID.bits()) != 0
    }

    /// # C: O(1)
    pub const fn phys(self) -> u64 { self.0 & PTE_PHYS_MASK }

    /// # C: O(1)
    pub const fn flags(self) -> PteFlags {
        PteFlags::from_bits_truncate(self.0 & !PTE_PHYS_MASK)
    }

    /// Convert architecture-neutral `hal::PageFlags` → ARM PTE bits.
    /// VALID + AF are implicit. The W^X PTE encoding flips PXN+UXN
    /// when EXEC is absent. `READ` is implicit by VALID+AF.
    /// # C: O(1)
    pub fn flags_from_native(n: PageFlags) -> PteFlags {
        let mut f = PteFlags::VALID | PteFlags::AF | PteFlags::TABLE
                  | PteFlags::SH0 | PteFlags::SH1; // Inner Shareable
        if !n.contains(PageFlags::WRITE)  { f |= PteFlags::AP_RO; }
        if  n.contains(PageFlags::USER)   { f |= PteFlags::AP_EL0 | PteFlags::NG; }
        if !n.contains(PageFlags::EXEC) {
            f |= PteFlags::PXN | PteFlags::UXN;
        }
        // GLOBAL bit on ARM is the *absence* of NG; user mappings
        // get NG above. Kernel mappings keep NG clear → effectively
        // global.
        if !n.contains(PageFlags::GLOBAL) && !n.contains(PageFlags::USER) {
            // Default kernel: clear NG (already cleared above).
        }
        f
    }

    /// Reverse mapping. Drops MAIR / AF / SH bookkeeping.
    /// # C: O(1)
    pub fn flags_to_native(f: PteFlags) -> PageFlags {
        let mut n = PageFlags::READ;
        if !f.contains(PteFlags::AP_RO)  { n |= PageFlags::WRITE; }
        if  f.contains(PteFlags::AP_EL0) { n |= PageFlags::USER;  }
        if !f.contains(PteFlags::PXN) && !f.contains(PteFlags::UXN) {
            n |= PageFlags::EXEC;
        }
        if !f.contains(PteFlags::NG) { n |= PageFlags::GLOBAL; }
        n
    }

    /// Walk-depth for a given native page size.
    /// # C: O(1)
    pub const fn level_for(size: PageSize) -> u8 {
        match size {
            PageSize::P4K => 3, // L3 leaf
            PageSize::P2M => 2, // L2 block
            PageSize::P1G => 1, // L1 block
        }
    }
}

// ---------------------------------------------------------------------------
// TLB flush asm (`21§5` flush_va / flush_all_local)
// ---------------------------------------------------------------------------

/// Invalidate a single VA in the local TLB. `tlbi vae1is, x` plus
/// `dsb ish` + `isb` gives Inner Shareable broadcast — for true
/// per-CPU local-only flush use `vae1` (no IS suffix); spec uses IS
/// so cross-CPU TLB shootdown is implicit on EL1.
/// # SAFETY: privileged insn.
/// # C: O(1) local; O(N_cpus) shareable broadcast
pub unsafe fn flush_local_va(va: u64) {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `tlbi vae1is` invalidates EL1 stage-1 entries
        // matching the operand VA across the inner-shareable
        // domain. ARM ARM D5.7. Followed by `dsb ish` + `isb` to
        // ensure ordering before subsequent loads.
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

/// Flush all EL1 stage-1 TLB entries on this CPU. `tlbi vmalle1`.
/// # C: O(1)
pub fn flush_local_all() {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `tlbi vmalle1` invalidates *all* EL1 entries on
        // this PE; followed by `dsb ish` + `isb` for ordering. ARM
        // ARM D5.7.
        unsafe {
            core::arch::asm!(
                "tlbi vmalle1",
                "dsb ish",
                "isb",
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
        let va: u64 = (0x100u64 << L0_SHIFT)
                    | (0x080u64 << L1_SHIFT)
                    | (0x040u64 << L2_SHIFT)
                    | (0x020u64 << L3_SHIFT)
                    | 0x123;
        let i = va_to_indices(va);
        assert_eq!(i.l0,  0x100);
        assert_eq!(i.l1,  0x080);
        assert_eq!(i.l2,  0x040);
        assert_eq!(i.l3,  0x020);
        assert_eq!(i.off, 0x123);
    }

    #[test]
    fn pte_phys_mask_matches_arm_arm() {
        // VMSAv8 stage-1: bits 47:12 ⇒ `0x0000_ffff_ffff_f000`.
        assert_eq!(PTE_PHYS_MASK, 0x0000_ffff_ffff_f000);
    }

    #[test]
    fn pte_new_leaf_packs_pa_and_flags() {
        let pa: u64 = 0x1234_5000;
        let f = PteFlags::VALID | PteFlags::TABLE | PteFlags::AF;
        let pte = PteArm64::new_leaf(pa, f);
        assert!(pte.is_valid());
        assert_eq!(pte.phys(), pa);
        assert_eq!(pte.flags(), f);
    }

    #[test]
    fn pte_native_to_arch_round_trip_user_rwx() {
        let n = PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER;
        let f = PteArm64::flags_from_native(n);
        assert!(f.contains(PteFlags::VALID));
        assert!(f.contains(PteFlags::AF));
        assert!(f.contains(PteFlags::AP_EL0), "USER ⇒ AP[1]=1");
        assert!(!f.contains(PteFlags::AP_RO),  "WRITE ⇒ AP[2]=0");
        assert!(!f.contains(PteFlags::UXN),    "EXEC ⇒ UXN clear");
        assert!(f.contains(PteFlags::NG),      "USER ⇒ NG (per-ASID)");
        let back = PteArm64::flags_to_native(f);
        assert!(back.contains(PageFlags::WRITE));
        assert!(back.contains(PageFlags::USER));
        assert!(back.contains(PageFlags::EXEC));
    }

    #[test]
    fn pte_no_exec_native_sets_pxn_and_uxn() {
        let n = PageFlags::READ | PageFlags::WRITE;
        let f = PteArm64::flags_from_native(n);
        assert!(f.contains(PteFlags::PXN), "missing EXEC ⇒ PXN");
        assert!(f.contains(PteFlags::UXN), "missing EXEC ⇒ UXN");
    }

    #[test]
    fn level_for_page_size_matches_arm_walk_depth() {
        // L3 leaf for 4 KiB; L2 block for 2 MiB; L1 block for 1 GiB.
        assert_eq!(PteArm64::level_for(PageSize::P4K), 3);
        assert_eq!(PteArm64::level_for(PageSize::P2M), 2);
        assert_eq!(PteArm64::level_for(PageSize::P1G), 1);
    }

    #[test]
    fn flush_ops_compile_on_host() {
        // SAFETY: host fallback paths are no-ops; asm is cfg'd out.
        unsafe { flush_local_va(0x1000) };
        flush_local_all();
    }
}
