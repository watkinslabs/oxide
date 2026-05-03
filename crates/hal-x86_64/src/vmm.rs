// x86_64 page-table walker per `20§5`. Splices a Device-attr 4 KiB
// leaf into the live PML4 (CR3) tree.
//
// The walk loop is shared with aarch64 in `hal::pt_walker`; this
// file supplies the x86 bit semantics + privileged-register access
// via the `PtWalker` trait. Per `07§5` no-`dyn`-on-HAL: the
// `map_device_4k` shim is generic-only at the call site and
// monomorphizes to a single instance per arch.
//
// PCD|PWT in the leaf maps to PAT slot 3 (Strong UC) by default,
// or PAT slot 1 (Write Through) if the kernel has reprogrammed
// PAT. Either is sound for MMIO.

use hal::pt_walker::{self, PtWalker, WalkErr};

const P_BIT:  u64 = 1 << 0;
const RW_BIT: u64 = 1 << 1;
const PWT:    u64 = 1 << 3;
const PCD:    u64 = 1 << 4;
const PS_BIT: u64 = 1 << 7;
const NX_BIT: u64 = 1 << 63;
const PHYS_MASK_X86: u64 = 0x000f_ffff_ffff_f000;

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
    unsafe fn read_pt_base() -> u64 {
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
        (child_pa & Self::PHYS_MASK) | P_BIT | RW_BIT
    }

    fn pack_device_leaf(pa: u64) -> u64 {
        (pa & Self::PHYS_MASK) | P_BIT | RW_BIT | PCD | PWT | NX_BIT
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
mod tests {
    use super::*;

    #[test]
    fn map_err_distinct() {
        assert_ne!(MapErr::AllocFailed, MapErr::HitHugePage);
        assert_ne!(MapErr::HitHugePage, MapErr::AlreadyMapped);
    }

    #[test]
    fn host_walker_pack_unpack_roundtrip() {
        let pa = 0xdead_b000_u64;
        let leaf = PtWalkerX86::pack_device_leaf(pa);
        assert!(PtWalkerX86::is_valid(leaf));
        assert!(!PtWalkerX86::is_huge_or_block(leaf));
        assert_eq!(leaf & PtWalkerX86::PHYS_MASK, pa);
        let table = PtWalkerX86::pack_table(pa);
        assert!(PtWalkerX86::is_valid(table));
        assert!(!PtWalkerX86::is_huge_or_block(table));
        assert_eq!(table & PtWalkerX86::PHYS_MASK, pa);
    }
}
