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
    /// Resolve the fault normally, but publish the page ALREADY carrying the
    /// write-protect state. The address held the protection with no page to
    /// carry it; materialising the page must not lose it, or the write this
    /// barrier exists to catch would go through unnoticed — and it must not
    /// lose it even briefly, or a peer thread writing the same page while the
    /// barrier is being put back escapes it once.
    ResolveProtected,
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
///
/// A leaf carrying the write-protect marker is judged FIRST, because it is the
/// only case in which an address with no page is already the monitor's: see
/// [`marker_fault`].
/// # C: O(log N) + O(walk depth)
pub(super) fn not_present(as_: &AddressSpace, uva: UserVirtAddr, write: bool, user_mode: bool,
                          hhdm: u64) -> Option<Intercept> {
    let va_page = uva.as_u64() & !(hal::PAGE_SIZE_BYTES - 1);
    if !as_.maybe_uffd() { return None; }
    let raw = leaf(as_, va_page, hhdm);
    // A leaf that is already present (a racer, or a stale fault) is not a
    // missing page; let the normal resolve run.
    if raw.is_some_and(<Walker as hal::pt_walker::PtWalker>::is_valid) { return None; }
    let marked = raw.is_some_and(<Walker as hal::pt_walker::PtWalker>::is_uffd_wp_marker);
    let hit = as_.uffd_for(uva)?;
    if marked { return marker_fault(as_, &hit, va_page, write, user_mode, hhdm); }
    if hit.modes.is_empty() { return None; }
    let resident = hit.modes.contains(VmaFlags::UFFD_MINOR) && backing_resident(as_, uva, va_page);
    let kind = vmm::uffd::not_present_kind(hit.modes, resident)?;
    Some(deliver(&*hit.ctx, va_page, kind, write, user_mode))
}

/// A fault on an address that holds the write-protect marker: the barrier was
/// armed while the address had no page, and this access is what it was armed to
/// catch. The choice between dropping it, reporting it and re-arming it after
/// the resolve is `vmm::uffd::wp_marker_action`.
/// # C: O(walk depth)
fn marker_fault(as_: &AddressSpace, hit: &vmm::address_space::uffd::UffdHit, va_page: u64,
                write: bool, user_mode: bool, hhdm: u64) -> Option<Intercept> {
    match vmm::uffd::wp_marker_action(hit.modes, hit.ctx.wp_async(), write) {
        vmm::uffd::WpAction::Resolve => { clear_marker(as_, va_page, hhdm); None }
        vmm::uffd::WpAction::ResolveProtected => Some(Intercept::ResolveProtected),
        vmm::uffd::WpAction::Report(kind) => Some(deliver(&*hit.ctx, va_page, kind, write, user_mode)),
        vmm::uffd::WpAction::NotOurs => None,
    }
}

/// Remove a write-protect marker, leaving the address an ordinary hole. Nothing
/// is released: a marker names no frame and no swap slot.
/// # C: O(walk depth)
fn clear_marker(as_: &AddressSpace, va_page: u64, hhdm: u64) {
    let _pt = as_.lock_page_table();
    let marker = <Walker as hal::pt_walker::PtWalker>::pack_uffd_wp_marker();
    // SAFETY: the page-table lock is held and HHDM covers this live root; the exchange writes the leaf only while it still holds exactly the marker, and a marker leaf is non-present, so nothing is unmapped and no mapping reference is dropped.
    unsafe {
        hal::pt_walker::swap_leaf_if_4k_at_root::<Walker>(as_.root_pa(), va_page, marker, 0, hhdm);
    }
}

/// Invalidate `va_page` on this CPU and on every peer running `as_`.
/// # C: O(N_cpus)
fn flush(as_: &AddressSpace, va_page: u64) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: privileged local TLB invalidation of a user VA whose leaf this path just rewrote; legal at CPL=0.
    unsafe { hal_x86_64::flush_local_va(va_page); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: privileged local TLB invalidation of a user VA whose leaf this path just rewrote; legal at EL1.
    unsafe { <hal_aarch64::mmu_ops::ArmMmu as hal::MmuOps>::flush_va(hal::Va(va_page)); }
    as_.uffd_shootdown_range(va_page, va_page + hal::PAGE_SIZE_BYTES);
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
    match vmm::uffd::write_fault_action(hit.modes, true, hit.ctx.wp_async()) {
        vmm::uffd::WpAction::Report(kind) => Some(deliver(&*hit.ctx, va_page, kind, true, user_mode)),
        // Told nothing: the protection is dropped where the write landed and
        // the write proceeds through the ordinary write-fault path, which is
        // where write permission is decided. The cleared state IS the record
        // that this page was written.
        vmm::uffd::WpAction::Resolve => { resolve_async(as_, va_page, hhdm); None }
        _ => None,
    }
}

/// Drop the write-protect state from a present leaf without granting write
/// permission: the fault continues into the ordinary write-fault resolve, which
/// decides copy-on-write, reuse or a shared page.
/// # C: O(walk depth) + O(N_cpus)
fn resolve_async(as_: &AddressSpace, va_page: u64, hhdm: u64) {
    {
        let _pt = as_.lock_page_table();
        // SAFETY: the page-table lock is held and HHDM covers this live root; clearing software state on a present leaf changes no mapping and drops no reference.
        unsafe {
            let Some(raw) = hal::pt_walker::read_leaf_4k_at_root::<Walker>(as_.root_pa(), va_page, hhdm)
                else { return };
            let cleared = <Walker as hal::pt_walker::PtWalker>::leaf_clear_uffd_wp(raw);
            if cleared == raw { return; }
            hal::pt_walker::write_leaf_4k_at_root::<Walker>(as_.root_pa(), va_page, cleared, hhdm);
        }
    }
    flush(as_, va_page);
}

/// Whether the VMA's backing already holds the page for `uva` — the fact that
/// makes a not-present fault a MINOR fault. The lookup must not allocate or
/// read the backing store, or asking the question would answer it.
///
/// "Holds" is OWNERSHIP of the page, not current residency: an evicted or
/// in-migration page is still a page the object has contents for, so a fault on
/// it is still minor. Deciding this from the narrower install-a-PTE-now lookup
/// reported an evicted page as absent, which downgraded the fault to MISSING
/// and asked the monitor to supply contents that already existed.
/// # C: O(log N_pages)
fn backing_resident(as_: &AddressSpace, uva: UserVirtAddr, va_page: u64) -> bool {
    let Some(v) = as_.uffd_vma_at(uva) else { return false };
    if !v.shmem { return false; }
    let Some(off) = v.file_off(va_page) else { return false };
    let Some((backing, _)) = v.file.as_ref() else { return false };
    backing.backing_holds_page(off)
}

/// The single delivery call every mode goes through.
/// # C: O(1) + block
fn deliver(ctx: &dyn vmm::UffdContext, va_page: u64, kind: UffdFaultKind, write: bool,
           user_mode: bool) -> Intercept {
    if ctx.fault(va_page, kind, write, user_mode) { Intercept::Retry } else { Intercept::Fail }
}
