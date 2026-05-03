// Kernel page-table walker — install a Device-attr 4 KiB leaf for
// MMIO into the live PML4 (CR3) per `20§5`.
//
// We don't replace Limine's tables; we splice into them. New
// intermediate tables come from a caller-supplied frame allocator
// (PMM, or any source that returns a fresh page-aligned PA). The
// frame is zero-initialized through HHDM before any walker writes.
//
// PCD|PWT in the leaf maps to PAT slot 3 (Strong UC) by default,
// or PAT slot 1 (Write Through) if the kernel has reprogrammed PAT.
// Either is sound for MMIO.

use core::ptr;

const ENTRIES_PER_TABLE: usize = 512;

const P_BIT:  u64 = 1 << 0;
const RW_BIT: u64 = 1 << 1;
const PWT:    u64 = 1 << 3;
const PCD:    u64 = 1 << 4;
const PS_BIT: u64 = 1 << 7;
const NX_BIT: u64 = 1 << 63;
const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;

const PML4_SHIFT: u32 = 39;
const PDPT_SHIFT: u32 = 30;
const PD_SHIFT:   u32 = 21;
const PT_SHIFT:   u32 = 12;
const TABLE_IDX:  u64 = 0x1ff;

/// Errors `map_device_4k` can return.
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

/// Read CR3 (BADDR field, 4 KiB-aligned).
/// # SAFETY: privileged read; legal at CPL=0.
unsafe fn read_cr3() -> u64 {
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
        return v & PHYS_MASK;
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}

/// `invlpg [va]` — invalidate the local TLB entry for `va`.
/// # SAFETY: privileged; legal at CPL=0.
unsafe fn invlpg(va: u64) {
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
    mut alloc_pa: F,
) -> Result<(), MapErr> {
    // SAFETY: privileged read, legal at CPL=0.
    let pml4_pa = unsafe { read_cr3() };

    let i_pml4 = ((va >> PML4_SHIFT) & TABLE_IDX) as usize;
    let i_pdpt = ((va >> PDPT_SHIFT) & TABLE_IDX) as usize;
    let i_pd   = ((va >> PD_SHIFT)   & TABLE_IDX) as usize;
    let i_pt   = ((va >> PT_SHIFT)   & TABLE_IDX) as usize;

    // SAFETY: per fn contract — HHDM covers page-table memory, alloc_pa returns kernel-owned frames, single-CPU walk so no concurrent writers; the leaf write at the end runs after all intermediates are present.
    unsafe {
        let pdpt_pa = walk_or_alloc(pml4_pa, i_pml4, hhdm_offset, &mut alloc_pa)?;
        let pd_pa   = walk_or_alloc(pdpt_pa, i_pdpt, hhdm_offset, &mut alloc_pa)?;
        let pt_pa   = walk_or_alloc(pd_pa,   i_pd,   hhdm_offset, &mut alloc_pa)?;
        let pt_va = (hhdm_offset.wrapping_add(pt_pa)) as *mut u64;
        let slot = pt_va.add(i_pt);
        let cur = ptr::read_volatile(slot);
        if (cur & P_BIT) != 0 && (cur & PHYS_MASK) != (pa & PHYS_MASK) {
            return Err(MapErr::AlreadyMapped);
        }
        let leaf = (pa & PHYS_MASK) | P_BIT | RW_BIT | PCD | PWT | NX_BIT;
        ptr::write_volatile(slot, leaf);
        invlpg(va);
    }
    Ok(())
}

/// Read entry `[idx]` of the table at PA `parent_pa` (via HHDM).
/// If empty, allocate + install a child intermediate. Return child PA.
///
/// # SAFETY: see `map_device_4k`.
unsafe fn walk_or_alloc<F: FnMut() -> Option<u64>>(
    parent_pa: u64,
    idx: usize,
    hhdm_offset: u64,
    alloc_pa: &mut F,
) -> Result<u64, MapErr> {
    // SAFETY: parent_pa points at a 4 KiB-aligned page-table page; HHDM maps it into kernel VA; we own the parent slot per `map_device_4k`'s single-CPU/IRQ-off contract.
    unsafe {
        let parent_va = (hhdm_offset.wrapping_add(parent_pa)) as *mut u64;
        let slot = parent_va.add(idx);
        let entry = ptr::read_volatile(slot);
        if (entry & P_BIT) == 0 {
            let child_pa = alloc_pa().ok_or(MapErr::AllocFailed)?;
            // child_pa is a fresh kernel-owned frame from PMM; HHDM
            // maps it; zero out all 512 entries before linking.
            let child_va = (hhdm_offset.wrapping_add(child_pa)) as *mut u64;
            for k in 0..ENTRIES_PER_TABLE {
                ptr::write_volatile(child_va.add(k), 0);
            }
            ptr::write_volatile(slot, (child_pa & PHYS_MASK) | P_BIT | RW_BIT);
            return Ok(child_pa);
        }
        if (entry & PS_BIT) != 0 {
            return Err(MapErr::HitHugePage);
        }
        Ok(entry & PHYS_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_err_distinct() {
        assert_ne!(MapErr::AllocFailed, MapErr::HitHugePage);
        assert_ne!(MapErr::HitHugePage, MapErr::AlreadyMapped);
    }
}
