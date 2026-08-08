// userfaultfd per-VMA hook per `27` — the per-VMA registration a fault
// consults — plus the `vm.unprivileged_userfaultfd` tunable that gates fd
// creation.
//
// A registered VMA carries an `Arc<dyn UffdContext>` (the fs `userfaultfd`
// inode state) together with its mode flags. The page-fault handler calls
// `fault` instead of resolving the fault itself: the context enqueues a
// PAGEFAULT event, wakes the monitor reading the fd, and BLOCKS the faulting
// thread until an ioctl resolves the address; it returns when the faulting
// instruction should retry.
//
// One trait method serves every mode. The mode decides WHICH fault is
// intercepted (absent page, write to a protected page, absent entry over a
// resident backing page) and which flag the message carries; the queueing,
// blocking and wake protocol are shared, so no mode gets a delivery path of
// its own to drift.
//
// Trait-object (dyn) so `mm-vmm` (no fs/sched deps) stays below the fs
// crate that implements it — the same layering as `FileBacking`.
//
// The tunable lives here rather than in the fs crate because the mm subsystem
// owns the `vm` sysctl it is registered under, and because procfs sits BELOW
// fs in the crate graph and so cannot reach an fs-owned variable.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

/// Why a fault is being handed to a monitor. Every registration mode delivers
/// through the SAME message queue and the same block/wake protocol; the kind
/// only selects the flag the message carries, so adding a mode never adds a
/// second delivery path.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UffdFaultKind {
    /// No page at the address and the range is MISSING-registered.
    Missing,
    /// A write to a page carrying the per-page write-protect marker in a
    /// WP-registered range.
    Wp,
    /// No page-table entry, but the backing already holds the page resident,
    /// in a MINOR-registered range.
    Minor,
}

/// An address-space change reported to a COOPERATIVE monitor — one tracking the
/// mappings it manages, not only their contents.
///
/// Each is delivered with the changing thread BLOCKED until the monitor has
/// read it. That block is the contract: without it a monitor acts on a mapping
/// that has already moved or gone, and its next resolve installs pages in the
/// wrong place.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UffdEvent {
    /// The address space was duplicated. The child carries its OWN context,
    /// which the monitor receives as a new descriptor when it reads the event.
    Fork,
    /// `[from, from+len)` now lives at `to`.
    Remap { from: u64, to: u64, len: u64 },
    /// The contents of `[start, end)` were discarded; the mapping stays.
    Remove { start: u64, end: u64 },
    /// `[start, end)` was unmapped.
    Unmap { start: u64, end: u64 },
}

/// The feature a monitor must have negotiated for an event to be reported.
/// Separate from [`UffdEvent`] so "does this monitor want it" can be asked
/// before the change's addresses exist.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UffdEventKind { Fork, Remap, Remove, Unmap }

impl UffdEvent {
    /// # C: O(1)
    pub fn kind(&self) -> UffdEventKind {
        match self {
            UffdEvent::Fork          => UffdEventKind::Fork,
            UffdEvent::Remap  { .. } => UffdEventKind::Remap,
            UffdEvent::Remove { .. } => UffdEventKind::Remove,
            UffdEvent::Unmap  { .. } => UffdEventKind::Unmap,
        }
    }
}

/// Per-VMA userfaultfd hook (Linux `vm_userfaultfd_ctx.ctx`). Impl'd by
/// the fs `userfaultfd` inode state; installed on VMAs via
/// [`crate::AddressSpace::set_uffd`].
///
/// Beyond fault delivery the trait carries the COOPERATIVE half: a change to
/// the address space is announced to the monitor, and every resolve issued
/// while such a change is in flight is refused, so no monitor can resolve
/// against a layout it has not been told about. The three-step shape — charge,
/// then either publish or abandon — is what makes that refusal exact: the
/// charge is taken before the change becomes visible and released only after
/// the monitor has consumed the announcement.
///
/// Every cooperative method defaults to doing nothing, because a context that
/// negotiated no event feature must behave exactly as it did before they
/// existed.
pub trait UffdContext: Send + Sync {
    /// Called on a fault at page-aligned `addr` inside a range registered for
    /// `kind`. Enqueues a PAGEFAULT message, wakes the fd's readers/pollers,
    /// and BLOCKS the calling (faulting) thread until the address is resolved
    /// or an explicit wake fires; returns when the faulting instruction should
    /// be retried. `write` = the fault was a write access.
    ///
    /// `user_mode` is false for a kernel-mode access to the user VA (uaccess,
    /// page pinning). A context created with `UFFD_USER_MODE_ONLY` refuses
    /// those, signalled by returning `false`; the fault is then reported
    /// unresolved rather than parking the kernel in a monitor's queue. `true`
    /// means "handled, retry the instruction".
    /// # C: O(1) enqueue + block
    fn fault(&self, addr: u64, kind: UffdFaultKind, write: bool, user_mode: bool) -> bool;

    /// Whether the monitor asked for write faults to be RESOLVED rather than
    /// reported: the protection is dropped where the write landed and the write
    /// proceeds, with no message and nothing to block on.
    ///
    /// This is what lets a monitor use the barrier as a RECORD of which pages
    /// were written without a thread reading the fd, so it has to be answered
    /// on the fault path — the only place that can choose between resolving the
    /// fault and reporting it.
    /// # C: O(1)
    fn wp_async(&self) -> bool { false }

    /// Whether the monitor asked the barrier to cover addresses with NO page.
    /// Without it, arming a range protects only pages that already exist, and
    /// the first write to an untouched address inside the range is never
    /// reported.
    /// # C: O(1)
    fn wp_unpopulated(&self) -> bool { false }

    /// Whether this monitor negotiated the feature that reports `kind`. A
    /// context that did not is skipped entirely — no charge, no announcement,
    /// and (for fork and remap) the registration is dropped rather than
    /// silently following a mapping the monitor cannot see move.
    /// # C: O(1)
    fn wants_event(&self, _kind: UffdEventKind) -> bool { false }

    /// Charge one in-flight address-space change against this context. Taken
    /// BEFORE the change becomes visible; every resolve is refused while the
    /// charge stands. Always paired with exactly one [`Self::change_complete`]
    /// or [`Self::change_abort`].
    /// # C: O(1)
    fn change_begin(&self) {}

    /// Publish `ev`, BLOCK until the monitor has read it, then release the
    /// charge [`Self::change_begin`] took.
    /// # C: O(1) enqueue + block
    fn change_complete(&self, _ev: UffdEvent) {}

    /// Release the charge without publishing anything — the change did not
    /// happen. Without this arm a failed operation would leave the context
    /// refusing every resolve forever.
    /// # C: O(1)
    fn change_abort(&self) {}

    /// Derive the context the CHILD address space carries across a fork, and
    /// charge the fork against this one. `None` = the monitor did not ask for
    /// fork events, so the child inherits no registration at all.
    ///
    /// The child gets its own context rather than sharing this one: the two
    /// address spaces resolve independently from that point, and a resolve
    /// aimed at one must never land in the other. The monitor is handed a
    /// descriptor for it when it reads the fork event.
    /// # C: O(1)
    fn fork_dup(&self, _child_mm: alloc::sync::Weak<crate::AddressSpace>)
        -> Option<Arc<dyn UffdContext>> { None }
}

/// Which fault a NOT-PRESENT access inside a registered range is, given the
/// modes armed there and whether the backing already holds the page.
///
/// MINOR wins over MISSING when the backing HAS the page: that is precisely
/// what separates the two, and a monitor registered for both must be told to
/// publish the page it already supplied rather than asked to supply it again.
/// `None` means the range is registered but not for anything this fault
/// matches, so the kernel resolves it normally.
/// # C: O(1)
pub fn not_present_kind(modes: crate::vma::VmaFlags, backing_resident: bool)
    -> Option<UffdFaultKind> {
    use crate::vma::VmaFlags;
    if modes.contains(VmaFlags::UFFD_MINOR) && backing_resident { return Some(UffdFaultKind::Minor); }
    if modes.contains(VmaFlags::UFFD_MISSING) { return Some(UffdFaultKind::Missing); }
    None
}

/// What a fault the write-protect barrier caught leads to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WpAction {
    /// Not this monitor's fault at all — resolve it the ordinary way.
    NotOurs,
    /// Drop the protection here and let the access proceed, telling nobody.
    Resolve,
    /// Hand it to the monitor as `kind`.
    Report(UffdFaultKind),
    /// Resolve the fault the ordinary way, but publish the page ALREADY
    /// protected — in the same store that makes it visible, so it is never
    /// briefly writable.
    ResolveProtected,
}

/// What a WRITE to a PRESENT page carrying the per-page write-protect marker
/// leads to.
///
/// BOTH facts are required before it is the monitor's: the page carries the
/// marker AND the VMA is still WP-registered. A marker left behind by an
/// unregistration must not divert a fault to a context that has stopped
/// listening — that would block the writer forever.
///
/// A monitor that asked for its write faults to be resolved is told nothing:
/// the protection is dropped where the write landed and the write proceeds
/// through the ordinary write-fault path. The cleared state is the record that
/// the page was written.
/// # C: O(1)
pub fn write_fault_action(modes: crate::vma::VmaFlags, leaf_is_uffd_wp: bool, wp_async: bool)
    -> WpAction {
    if !(leaf_is_uffd_wp && modes.contains(crate::vma::VmaFlags::UFFD_WP)) {
        return WpAction::NotOurs;
    }
    if wp_async { return WpAction::Resolve; }
    WpAction::Report(UffdFaultKind::Wp)
}

/// What a fault on an address whose leaf carries the write-protect MARKER leads
/// to — the barrier was armed while the address had no page, and this access is
/// what it was armed to catch.
///
/// - A marker left by an unregistration is dropped and the fault resolves
///   normally: a stale marker must never divert a fault to a context that has
///   stopped listening.
/// - A monitor that resolves its own write faults gets no message; the marker
///   goes and the access proceeds. That is the whole of that mode.
/// - A WRITE is the fault the barrier exists for — but if the range is ALSO
///   registered for missing pages, the missing page is reported FIRST: there is
///   nothing to write-protect until the monitor has supplied contents, and the
///   write-protect fault follows once it has.
/// - A READ has to be let through, and the page it materialises has to arrive
///   already protected, or the next write escapes the barrier entirely — and
///   arriving protected is not the same as being protected afterwards: a peer
///   thread writing in between escapes it exactly once.
/// # C: O(1)
pub fn wp_marker_action(modes: crate::vma::VmaFlags, wp_async: bool, write: bool) -> WpAction {
    use crate::vma::VmaFlags;
    if !modes.contains(VmaFlags::UFFD_WP) || wp_async { return WpAction::Resolve; }
    if !write { return WpAction::ResolveProtected; }
    if modes.contains(VmaFlags::UFFD_MISSING) { return WpAction::Report(UffdFaultKind::Missing); }
    WpAction::Report(UffdFaultKind::Wp)
}

/// Whether a page copied into a CHILD address space keeps the write-protect
/// barrier its parent page carries.
///
/// Both facts are required. The barrier belongs to a monitor, and a child
/// inherits a registration only when the monitor asked to be told about forks —
/// so a child of a monitor that did not gets an unregistered mapping, on which
/// a leftover barrier would block a writer on a context that will never hear
/// about it. Conversely, dropping the barrier for a monitor that DID ask hands
/// it a child whose first write goes unreported.
/// # C: O(1)
pub fn child_keeps_wp(modes: crate::vma::VmaFlags, ctx_tracks_fork: bool) -> bool {
    modes.contains(crate::vma::VmaFlags::UFFD_WP) && ctx_tracks_fork
}

/// Whether speculative installs around a fault must be suppressed on this
/// mapping. Mapping neighbours the fault never touched publishes ordinary
/// writable-path leaves over addresses a monitor is watching: a write-protect
/// barrier armed there is overwritten, and a minor-fault registration loses the
/// notification the monitor exists to receive.
/// # C: O(1)
pub fn fault_around_disabled(modes: crate::vma::VmaFlags) -> bool {
    modes.intersects(crate::vma::VmaFlags::UFFD_WP | crate::vma::VmaFlags::UFFD_MINOR)
}

/// Compare two optional uffd contexts by Arc identity — used by VMA
/// merge so abutting ranges bound to DIFFERENT uffd fds never coalesce.
/// # C: O(1)
pub fn uffd_ptr_eq(a: &Option<Arc<dyn UffdContext>>, b: &Option<Arc<dyn UffdContext>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        _ => false,
    }
}

/// `vm.unprivileged_userfaultfd` sysctl default: DENY (0), toggle range
/// `[0, 1]` enforced by its ctl_table bounds.
const UNPRIVILEGED_USERFAULTFD_DEFAULT: i64 = 0;
/// `.extra1`/`.extra2` of the `vm.unprivileged_userfaultfd` ctl_table entry.
pub const UNPRIVILEGED_USERFAULTFD_BOUNDS: (i64, i64) = (0, 1);

static UNPRIVILEGED_USERFAULTFD: AtomicI64 =
    AtomicI64::new(UNPRIVILEGED_USERFAULTFD_DEFAULT);

/// Live value of `vm.unprivileged_userfaultfd`, consulted by
/// `userfaultfd_syscall_allowed`. # C: O(1)
pub fn unprivileged_userfaultfd() -> i64 {
    UNPRIVILEGED_USERFAULTFD.load(Ordering::Relaxed)
}

/// `/proc/sys/vm/unprivileged_userfaultfd` write path. # C: O(1)
pub fn set_unprivileged_userfaultfd(v: i64) {
    UNPRIVILEGED_USERFAULTFD.store(v, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vma::VmaFlags;

    const MISSING: VmaFlags = VmaFlags::UFFD_MISSING;
    const MINOR: VmaFlags = VmaFlags::UFFD_MINOR;
    const WP: VmaFlags = VmaFlags::UFFD_WP;

    /// A minor fault is "the backing has it, the page table does not". Getting
    /// this precedence wrong tells a monitor registered for both modes to
    /// supply a page it already supplied, and the page it then writes silently
    /// replaces the one the backing holds.
    #[test]
    fn a_resident_backing_page_makes_it_a_minor_fault_not_a_missing_one() {
        assert_eq!(not_present_kind(MISSING | MINOR, true), Some(UffdFaultKind::Minor));
        assert_eq!(not_present_kind(MISSING | MINOR, false), Some(UffdFaultKind::Missing));
        assert_eq!(not_present_kind(MINOR, true), Some(UffdFaultKind::Minor));
        // Registered for minor faults only, with nothing in the backing: there
        // is no minor fault to report and no missing registration to fall back
        // on, so the kernel resolves it.
        assert_eq!(not_present_kind(MINOR, false), None);
        assert_eq!(not_present_kind(MISSING, true), Some(UffdFaultKind::Missing));
        assert_eq!(not_present_kind(VmaFlags::empty(), true), None);
        // A write-protect registration says nothing about absent pages.
        assert_eq!(not_present_kind(WP, false), None);
        assert_eq!(not_present_kind(WP, true), None);
    }

    /// An object that has EVICTED a page still holds that page's contents, so
    /// a fault on it is minor, not missing. The two residency queries differ
    /// exactly here, and deciding the fault kind from the narrower one told a
    /// monitor to supply contents the object already had — after which the
    /// monitor's page replaced them.
    #[test]
    fn an_evicted_backing_page_is_still_a_page_the_object_holds() {
        use crate::vma::{FileBacking, FileBackingError, SharedFrame};
        // A backing whose only page has been evicted: nothing to install a PTE
        // from right now, but the object still owns the contents.
        struct Evicted;
        impl FileBacking for Evicted {
            fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
            fn size_hint(&self) -> u64 { hal::PAGE_SIZE_BYTES }
            fn is_shmem(&self) -> bool { true }
            fn fault_around_frame(&self, _off: u64) -> Result<Option<SharedFrame>, FileBackingError> {
                Ok(None)
            }
            fn backing_holds_page(&self, _off: u64) -> bool { true }
        }
        // The narrower query cannot answer it: there is no frame to map.
        assert!(matches!(Evicted.fault_around_frame(0), Ok(None)));
        // The ownership query can, and that is the one the fault kind uses.
        assert!(Evicted.backing_holds_page(0));
        assert_eq!(not_present_kind(MISSING | MINOR, Evicted.backing_holds_page(0)),
                   Some(UffdFaultKind::Minor));
        // Reading the kind off the narrower query is the defect: it reports the
        // fault as MISSING and loses the page the object already holds.
        let narrow = Evicted.fault_around_frame(0).is_ok_and(|f| f.is_some());
        assert_eq!(not_present_kind(MISSING | MINOR, narrow), Some(UffdFaultKind::Missing));
    }

    /// A backing that owns no page at the offset reports nothing, so nothing
    /// can manufacture a minor fault over a hole.
    #[test]
    fn a_backing_that_holds_nothing_reports_no_page() {
        use crate::vma::{FileBacking, FileBackingError};
        struct Hole;
        impl FileBacking for Hole {
            fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
            fn size_hint(&self) -> u64 { 0 }
        }
        assert!(!Hole.backing_holds_page(0));
        assert_eq!(not_present_kind(MISSING | MINOR, Hole.backing_holds_page(0)),
                   Some(UffdFaultKind::Missing));
    }

    /// The marker and the registration must BOTH hold. A stale marker left by
    /// an unregistration would otherwise block the writer on a context that
    /// has stopped listening.
    #[test]
    fn a_write_is_the_monitors_only_with_both_the_marker_and_the_registration() {
        assert_eq!(write_fault_action(WP, true, false), WpAction::Report(UffdFaultKind::Wp));
        assert_eq!(write_fault_action(WP, false, false), WpAction::NotOurs);
        assert_eq!(write_fault_action(MISSING | MINOR, true, false), WpAction::NotOurs);
        assert_eq!(write_fault_action(VmaFlags::empty(), true, false), WpAction::NotOurs);
    }

    /// The barrier belongs to a monitor, so it crosses a fork only with one.
    /// A child that inherits no registration must inherit no barrier — a
    /// leftover one blocks its first write on a context that has no record of
    /// the process — and a child that DOES inherit the registration must inherit
    /// the barrier, or its first write goes unreported.
    #[test]
    fn a_barrier_crosses_a_fork_only_together_with_the_monitor_that_armed_it() {
        assert!(child_keeps_wp(WP, true));
        assert!(!child_keeps_wp(WP, false), "no monitor in the child, no barrier in the child");
        assert!(!child_keeps_wp(VmaFlags::empty(), true));
        assert!(!child_keeps_wp(MISSING | MINOR, true), "only the write-protect mode arms one");
    }

    /// Speculative neighbour installs publish ordinary leaves over addresses the
    /// fault never touched. On a watched range those addresses may carry a
    /// barrier, or be exactly the absences a minor-fault monitor exists to hear
    /// about — so the whole speculation is suppressed rather than filtered.
    #[test]
    fn faulting_around_is_suppressed_on_a_range_a_monitor_is_watching() {
        assert!(fault_around_disabled(WP));
        assert!(fault_around_disabled(MINOR));
        assert!(fault_around_disabled(WP | MISSING));
        // A missing-page registration is answered by the fault itself, so it
        // does not need the speculation turned off.
        assert!(!fault_around_disabled(MISSING));
        assert!(!fault_around_disabled(VmaFlags::empty()));
    }

    /// A monitor that asked for its write faults to be resolved is told
    /// nothing: the protection is dropped and the write proceeds. Reporting it
    /// instead would block a thread on a monitor that is not reading the fd —
    /// which is precisely the situation that mode exists for.
    #[test]
    fn an_asynchronous_monitor_has_its_write_faults_resolved_rather_than_reported() {
        assert_eq!(write_fault_action(WP, true, true), WpAction::Resolve);
        // The mode says nothing about a page this monitor never protected.
        assert_eq!(write_fault_action(WP, false, true), WpAction::NotOurs);
        assert_eq!(write_fault_action(MISSING, true, true), WpAction::NotOurs);
    }

    /// The barrier armed over an address with NO page. A write is the fault it
    /// exists for — unless the range also reports missing pages, in which case
    /// there is nothing to protect until the monitor has supplied contents, so
    /// the missing page is reported first. A read must be let through, and the
    /// protection must outlive the page it materialises, or the next write
    /// escapes the barrier entirely.
    #[test]
    fn a_fault_on_a_write_protected_hole_reports_the_missing_page_first_when_both_are_armed() {
        assert_eq!(wp_marker_action(WP, false, true), WpAction::Report(UffdFaultKind::Wp));
        assert_eq!(wp_marker_action(WP | MISSING, false, true),
                   WpAction::Report(UffdFaultKind::Missing));
        assert_eq!(wp_marker_action(WP, false, false), WpAction::ResolveProtected);
        assert_eq!(wp_marker_action(WP | MISSING, false, false), WpAction::ResolveProtected);
        // Resolved silently for a monitor that asked for that, whatever else is
        // armed — and dropped outright for a marker left behind by an
        // unregistration, which must never divert a fault to a context that
        // stopped listening.
        assert_eq!(wp_marker_action(WP, true, true), WpAction::Resolve);
        assert_eq!(wp_marker_action(MISSING, false, true), WpAction::Resolve);
        assert_eq!(wp_marker_action(VmaFlags::empty(), false, false), WpAction::Resolve);
    }
}
