// Kernel page-table walker — install a Device-nGnRnE 4 KiB leaf in
// the live TTBR1_EL1 tree per `21§5`.
//
// Splices into Limine's existing tables; intermediate L1/L2/L3
// pages come from a caller-supplied frame allocator (PMM). Limine
// programs MAIR_EL1 = 0xff: byte 0 = Normal WB-cacheable, bytes
// 1..7 = Device-nGnRnE. We use AttrIdx = 1.

use core::ptr;

const ENTRIES_PER_TABLE: usize = 512;

const VALID:    u64 = 1 << 0;
const TABLE:    u64 = 1 << 1;       // also "PAGE" at L3
const ATTR1:    u64 = 1 << 3;       // AttrIdx[1]
const SH0:      u64 = 1 << 8;
const SH1:      u64 = 1 << 9;       // SH = 0b11 = Inner Shareable
const AF:       u64 = 1 << 10;
const PXN:      u64 = 1 << 53;
const UXN:      u64 = 1 << 54;
const PHYS_MASK: u64 = 0x0000_ffff_ffff_f000;

const L0_SHIFT: u32 = 39;
const L1_SHIFT: u32 = 30;
const L2_SHIFT: u32 = 21;
const L3_SHIFT: u32 = 12;
const TABLE_IDX:  u64 = 0x1ff;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MapErr {
    /// Frame allocator returned `None` mid-walk.
    AllocFailed,
    /// An intermediate entry is a BLOCK descriptor (huge page).
    HitBlockDescriptor,
    /// Leaf already present and points elsewhere.
    AlreadyMapped,
}

/// Read TTBR1_EL1 BADDR field (4 KiB-aligned).
/// # SAFETY: privileged read; EL1.
unsafe fn read_ttbr1_baddr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs x, ttbr1_el1` is privileged at EL1; no memory effect; result is the EL1 kernel-half page-table base.
        unsafe {
            core::arch::asm!(
                "mrs {}, ttbr1_el1",
                out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        return v & PHYS_MASK;
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Invalidate the local TLB entry for `va` and serialize.
/// # SAFETY: privileged at EL1.
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
    mut alloc_pa: F,
) -> Result<(), MapErr> {
    // SAFETY: privileged read; legal at EL1.
    let l0_pa = unsafe { read_ttbr1_baddr() };

    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX) as usize;

    // SAFETY: per fn contract — HHDM covers page-table pages, alloc_pa returns kernel-owned frames, walk runs single-CPU with IRQs off so no concurrent writers; leaf write happens after all intermediates exist.
    unsafe {
        let l1_pa = walk_or_alloc(l0_pa, i_l0, hhdm_offset, &mut alloc_pa)?;
        let l2_pa = walk_or_alloc(l1_pa, i_l1, hhdm_offset, &mut alloc_pa)?;
        let l3_pa = walk_or_alloc(l2_pa, i_l2, hhdm_offset, &mut alloc_pa)?;
        let l3_va = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
        let slot = l3_va.add(i_l3);
        let cur = ptr::read_volatile(slot);
        if (cur & VALID) != 0 && (cur & PHYS_MASK) != (pa & PHYS_MASK) {
            return Err(MapErr::AlreadyMapped);
        }
        // Device-nGnRnE leaf: VALID|PAGE, AttrIdx=1, Inner-Shareable, AF, PXN+UXN, RW.
        let leaf = (pa & PHYS_MASK) | VALID | TABLE | ATTR1 | SH0 | SH1 | AF | PXN | UXN;
        ptr::write_volatile(slot, leaf);
        flush_va(va);
    }
    Ok(())
}

unsafe fn walk_or_alloc<F: FnMut() -> Option<u64>>(
    parent_pa: u64,
    idx: usize,
    hhdm_offset: u64,
    alloc_pa: &mut F,
) -> Result<u64, MapErr> {
    // SAFETY: parent_pa points at a 4 KiB-aligned page-table page; HHDM maps it into kernel VA; single-CPU/IRQ-off per `map_device_4k`'s contract.
    unsafe {
        let parent_va = (hhdm_offset.wrapping_add(parent_pa)) as *mut u64;
        let slot = parent_va.add(idx);
        let entry = ptr::read_volatile(slot);
        if (entry & VALID) == 0 {
            let child_pa = alloc_pa().ok_or(MapErr::AllocFailed)?;
            // child_pa is a fresh kernel-owned frame; HHDM maps it; zero it
            // before linking so a missing leaf below acts like "not present".
            let child_va = (hhdm_offset.wrapping_add(child_pa)) as *mut u64;
            for k in 0..ENTRIES_PER_TABLE {
                ptr::write_volatile(child_va.add(k), 0);
            }
            ptr::write_volatile(slot, (child_pa & PHYS_MASK) | VALID | TABLE);
            return Ok(child_pa);
        }
        if (entry & TABLE) == 0 {
            return Err(MapErr::HitBlockDescriptor);
        }
        Ok(entry & PHYS_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_err_distinct() {
        assert_ne!(MapErr::AllocFailed, MapErr::HitBlockDescriptor);
        assert_ne!(MapErr::HitBlockDescriptor, MapErr::AlreadyMapped);
    }
}
