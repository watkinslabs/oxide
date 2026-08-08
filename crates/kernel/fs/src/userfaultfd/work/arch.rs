// The per-arch names and the two leaf primitives the resolve paths share.
// Selected once here so no resolve path carries its own `#[cfg]` ladder.

#[cfg(target_arch = "aarch64")]
use hal::{MmuOps, Va};

#[cfg(target_arch = "x86_64")]
pub type Mmu = hal_x86_64::mmu_ops::X86Mmu;
#[cfg(target_arch = "x86_64")]
pub type Walker = hal_x86_64::vmm::PtWalkerX86;
#[cfg(target_arch = "aarch64")]
pub type Mmu = hal_aarch64::mmu_ops::ArmMmu;
#[cfg(target_arch = "aarch64")]
pub type Walker = hal_aarch64::vmm::PtWalkerArm;

/// The HHDM window every page-table and frame access goes through.
/// # C: O(1)
pub fn hhdm() -> u64 { pmm::user_as::hhdm_offset() }

/// Invalidate `va` on this CPU and on every peer running `mm`. A resolve that
/// flushed only locally would leave a peer CPU executing against the entry the
/// monitor just replaced.
/// # C: O(N_cpus)
pub fn flush(mm: &vmm::AddressSpace, va: u64) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: privileged local TLB invalidation of a user VA whose leaf this path just rewrote; legal at CPL=0.
    unsafe { hal_x86_64::flush_local_va(va); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: privileged local TLB invalidation of a user VA whose leaf this path just rewrote; legal at EL1.
    unsafe { <Mmu as MmuOps>::flush_va(Va(va)); }
    mm.uffd_shootdown_range(va, va + hal::PAGE_SIZE_BYTES);
}

/// Raw leaf for `va`, or `None` when no table covers it.
/// # C: O(walk depth)
pub fn leaf(mm: &vmm::AddressSpace, va: u64) -> Option<u64> {
    // SAFETY: the caller holds this address space's page-table lock for the duration of the resolve, so no table along the walk can be freed; HHDM covers page-table memory and the walk only reads.
    unsafe { hal::pt_walker::read_leaf_4k_at_root::<Walker>(mm.root_pa(), va, hhdm()) }
}

/// Replace the leaf for `va`, returning the previous value. `None` when no
/// table covers `va` — the caller must have established one.
/// # C: O(walk depth)
pub fn set_leaf(mm: &vmm::AddressSpace, va: u64, raw: u64) -> Option<u64> {
    // SAFETY: the caller holds this address space's page-table lock and owns the mapping it is rewriting; HHDM covers the table page holding the leaf.
    unsafe { hal::pt_walker::write_leaf_4k_at_root::<Walker>(mm.root_pa(), va, raw, hhdm()) }
}
