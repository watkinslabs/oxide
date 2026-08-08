// userfaultfd fault interception: the ONE place a fault is diverted to a
// monitor, and the one place a poisoned page becomes a memory-error signal.
//
// Every registration mode arrives here and leaves through the same
// `UffdContext::fault` call, so the modes differ only in what makes a fault
// interceptable:
//   MISSING — no page at the address at all.
//   MINOR   — no page-table entry, but the backing already holds the page.
//   WP      — a write to a present page carrying the per-page write-protect
//             marker.
// The marker lives in the page-table leaf, so "is this page write-protected"
// has exactly one answer: the one the CPU walks.

use vmm::{AddressSpace, UffdFaultKind, VmaFlags};
use hal::UserVirtAddr;

/// Page shift reported as `si_addr_lsb` on a memory-error signal: the fault is
/// precise to one 4 KiB page, not to the byte.
const PAGE_SHIFT: i16 = 12;

#[cfg(target_arch = "x86_64")]
type Walker = hal_x86_64::vmm::PtWalkerX86;
#[cfg(target_arch = "aarch64")]
type Walker = hal_aarch64::vmm::PtWalkerArm;

/// What the fault handler should do with a fault this module examined.
pub(super) enum Intercept {
    /// Handled — retry the faulting instruction.
    Retry,
    /// Unresolvable here; report the fault so the uaccess fixup or the signal
    /// path deals with it.
    Fail,
}

/// Raw leaf for `va` in `as_`'s tables, or `None` when no table covers it.
/// # C: O(walk depth)
fn leaf(as_: &AddressSpace, va: u64, hhdm: u64) -> Option<u64> {
    let _pt = as_.lock_page_table();
    // SAFETY: the page-table lock is held for the walk, so neither the root nor any intermediate table can be freed under it; HHDM covers every table page read and the walk only reads.
    unsafe { hal::pt_walker::read_leaf_4k_at_root::<Walker>(as_.root_pa(), va, hhdm) }
}

/// A poisoned page consumed by this access. Reported as a memory error, not as
/// an unmapped address: the mapping exists and the monitor deliberately marked
/// its contents unrecoverable, which is a different thing for a program to
/// catch.
///
/// A kernel-mode access takes `Fail` instead, so a uaccess of a poisoned page
/// returns EFAULT to its syscall rather than killing the thread.
/// # C: O(walk depth)
pub(super) fn poisoned(as_: &AddressSpace, va_page: u64, user_mode: bool, hhdm: u64)
    -> Option<Intercept> {
    if !leaf(as_, va_page, hhdm).is_some_and(<Walker as hal::pt_walker::PtWalker>::is_poison_marker) {
        return None;
    }
    if !user_mode { return Some(Intercept::Fail); }
    sched::live::force_sig_fault(sched::signum::Signum::Sigbus,
                                 hal::siginfo::code::BUS_MCEERR_AR, va_page, PAGE_SHIFT);
    Some(Intercept::Retry)
}

/// A not-present fault inside a registered range. MINOR wins over MISSING for
/// a backing page that is already resident — that IS the distinction between
/// the two modes, and a monitor registered for both must see the minor fault
/// rather than be told to supply a page it already supplied.
/// # C: O(log N) + O(walk depth)
pub(super) fn not_present(as_: &AddressSpace, uva: UserVirtAddr, write: bool, user_mode: bool,
                          hhdm: u64) -> Option<Intercept> {
    let va_page = uva.as_u64() & !(hal::PAGE_SIZE_BYTES - 1);
    if !as_.maybe_uffd() { return None; }
    let hit = as_.uffd_for(uva)?;
    if hit.modes.is_empty() { return None; }
    // A leaf that is already present (a racer, or a stale fault) is not a
    // missing page; let the normal resolve run.
    if leaf(as_, va_page, hhdm).is_some_and(<Walker as hal::pt_walker::PtWalker>::is_valid) {
        return None;
    }
    let resident = hit.modes.contains(VmaFlags::UFFD_MINOR) && backing_resident(as_, uva, va_page);
    let kind = vmm::uffd::not_present_kind(hit.modes, resident)?;
    Some(deliver(&*hit.ctx, va_page, kind, write, user_mode))
}

/// A write to a present page. Intercepted only when the leaf carries the
/// per-page write-protect marker AND the VMA is WP-registered: a marker left
/// behind by an unregistration must not divert a fault to a context that is no
/// longer listening.
/// # C: O(log N) + O(walk depth)
pub(super) fn write_protected(as_: &AddressSpace, uva: UserVirtAddr, user_mode: bool, hhdm: u64)
    -> Option<Intercept> {
    let va_page = uva.as_u64() & !(hal::PAGE_SIZE_BYTES - 1);
    if !as_.maybe_uffd() { return None; }
    if !leaf(as_, va_page, hhdm).is_some_and(<Walker as hal::pt_walker::PtWalker>::leaf_is_uffd_wp) {
        return None;
    }
    let hit = as_.uffd_for(uva)?;
    let kind = vmm::uffd::write_fault_kind(hit.modes, true)?;
    Some(deliver(&*hit.ctx, va_page, kind, true, user_mode))
}

/// Whether the VMA's backing already holds the page for `uva` resident — the
/// fact that makes a not-present fault a MINOR fault. The lookup must not
/// allocate or read the backing store, or asking the question would answer it.
/// # C: O(log N_pages)
fn backing_resident(as_: &AddressSpace, uva: UserVirtAddr, va_page: u64) -> bool {
    let Some(v) = as_.uffd_vma_at(uva) else { return false };
    if !v.shmem { return false; }
    let Some(off) = v.file_off(va_page) else { return false };
    let Some((backing, _)) = v.file.as_ref() else { return false };
    match backing.fault_around_frame(off) {
        Ok(Some(frame)) => {
            // The lookup took a prospective mapping reference for a PTE we are
            // NOT installing; release it or the page is pinned forever.
            if frame.map_ref_held {
                // SAFETY: `frame.pa` carries exactly the one prospective mapping reference this lookup acquired, and no PTE was installed from it; rmap_aware_dec_and_maybe_free releases to the PMM only at refcount zero.
                unsafe { crate::setup::rmap_aware_dec_and_maybe_free(frame.pa); }
            }
            true
        }
        _ => false,
    }
}

/// The single delivery call every mode goes through.
/// # C: O(1) + block
fn deliver(ctx: &dyn vmm::UffdContext, va_page: u64, kind: UffdFaultKind, write: bool,
           user_mode: bool) -> Intercept {
    if ctx.fault(va_page, kind, write, user_mode) { Intercept::Retry } else { Intercept::Fail }
}
