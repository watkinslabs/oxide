// UFFDIO_COPY / UFFDIO_ZEROPAGE page installation — Linux `mfill_atomic` +
// `mfill_atomic_install_pte` (`mm/userfaultfd.c`).
//
// Kernel-only: needs the PMM and the per-arch page-table walker. Every
// DECISION this file could make (range validation, dst-VMA acceptance, return
// protocol) lives in the ungated `policy.rs`; what is left here is the
// mechanical fill loop, so the gating costs no test coverage.

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use syscall::errno::Errno;

#[cfg(target_arch = "x86_64")]
use hal_x86_64::mmu_ops::X86Mmu as ArchMmu;
#[cfg(target_arch = "x86_64")]
use hal_x86_64::vmm::PtWalkerX86 as ArchWalker;
#[cfg(target_arch = "aarch64")]
use hal_aarch64::mmu_ops::ArmMmu as ArchMmu;
#[cfg(target_arch = "aarch64")]
use hal_aarch64::vmm::PtWalkerArm as ArchWalker;

/// 4 KiB granule of the fill loop (Linux installs one `PAGE_SIZE` folio per
/// `mfill_atomic_pte` iteration).
const PAGE: u64 = hal::PAGE_SIZE_BYTES;

/// True iff `va` already has a present leaf in the page tables rooted at
/// `root`. Linux's equivalent is `mfill_atomic_install_pte`'s
/// `ret = -EEXIST; if (!pte_none(dst_ptep) && !pte_is_uffd_marker(dst_ptep)) goto out_unlock;`
/// — the destination must be a hole, or a monitor could overwrite a page the
/// process is already using.
/// # C: O(walk depth)
fn leaf_present(root: u64, va: u64, hhdm: u64) -> bool {
    // SAFETY: `root` is a live user page-table root owned by the target AddressSpace and the HHDM window covers page-table memory; translate_4k_at_root only READS table entries.
    unsafe { hal::pt_walker::translate_4k_at_root::<ArchWalker>(root, va, hhdm).is_some() }
}

/// Flush the just-installed VA on this CPU so a faulter's retry walks the new
/// leaf. # C: O(1)
#[inline]
fn flush_local(va: u64) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: privileged local TLB invalidation of a freshly-mapped user VA; legal at CPL=0.
    unsafe { hal_x86_64::flush_local_va(va); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: tlbi of a freshly-mapped user VA so the faulter's retry walks the new PTE; privileged but legal at EL1.
    unsafe { <ArchMmu as MmuOps>::flush_va(Va(va)); }
}

/// Install `[dst0, dst0+len)` in the page tables rooted at `root`, filling each
/// page from monitor source `src0` (COPY) or with zeroes (`src0 == None`,
/// ZEROPAGE). Returns `(bytes_installed, first_error)` following Linux
/// `mfill_atomic`: the loop stops at the first per-page failure and the caller
/// reports `copied ? copied : err`.
///
/// `flags` come from the destination VMA's protection — never a synthesised
/// "user read-write" default. A COPY landing outside any VMA is refused before
/// this is called (`policy::check_dst_vma`).
/// # C: O(len/PAGE) walks + frame allocs
pub fn install_pages(mm: &vmm::AddressSpace, dst0: u64, src0: Option<u64>, len: u64, flags: PageFlags)
    -> (u64, Option<Errno>) {
    let root = mm.root_pa();
    let hhdm = pmm::user_as::hhdm_offset();
    let mut done = 0u64;
    while done < len {
        let dst = dst0 + done;
        if leaf_present(root, dst, hhdm) { return (done, Some(Errno::Eexist)); }
        let Some(pa) = pmm::setup::alloc_one_frame() else { return (done, Some(Errno::Enomem)) };
        // SAFETY: `pa` is a fresh PMM frame whose HHDM mirror at hhdm+pa is kernel-writable and PAGE bytes long; a COPY `src` is a user VA validated against the caller's address space (a not-present source page demand-faults normally through the active root).
        unsafe {
            let frame = (hhdm + pa) as *mut u8;
            match src0 {
                Some(s) => core::ptr::copy_nonoverlapping((s + done) as *const u8, frame, PAGE as usize),
                None    => core::ptr::write_bytes(frame, 0, PAGE as usize),
            }
        }
        // SAFETY: `pa` is the frame filled just above; `dst` is page-aligned and inside a VMA of the AS rooted at `root`; map_at installs the leaf, allocating intermediate tables from the PMM.
        let displaced = unsafe { <ArchMmu as MmuOps>::map_at(root, Va(dst), Pa(pa), flags, PageSize::P4K) };
        if let Some(old) = displaced {
            // Lost the race against a concurrent installer between the
            // `leaf_present` probe and this map: the leaf we tore down still
            // holds its mapping reference, so drop it rather than leak.
            // SAFETY: `old` was reachable only through the leaf map_at just replaced, so its mapping reference is ours to drop; rmap_aware_dec_and_maybe_free releases to the PMM only at refcount zero.
            unsafe { pmm::setup::rmap_aware_dec_and_maybe_free(old.0); }
        }
        flush_local(dst);
        // A monitor-filled page is as resident as a demand-faulted one; Linux
        // `mfill_atomic_install_pte` charges `mm_counter` here for exactly
        // that reason. A displaced leaf (the lost-race arm above) was already
        // counted, so its replacement is a net zero and must not double-count.
        if displaced.is_none() {
            if let Some(uva) = hal::UserVirtAddr::new(dst) { mm.account_pte_install_at(uva); }
        }
        done += PAGE;
    }
    (done, None)
}
