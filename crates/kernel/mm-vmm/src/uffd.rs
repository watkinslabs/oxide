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

/// Per-VMA userfaultfd hook (Linux `vm_userfaultfd_ctx.ctx`). Impl'd by
/// the fs `userfaultfd` inode state; installed on VMAs via
/// [`crate::AddressSpace::set_uffd`].
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

/// Whether a WRITE to a present page is the monitor's to handle.
///
/// BOTH facts are required: the page carries the per-page marker AND the VMA
/// is still WP-registered. A marker left behind by an unregistration must not
/// divert a fault to a context that has stopped listening — that would block
/// the writer forever.
/// # C: O(1)
pub fn write_fault_kind(modes: crate::vma::VmaFlags, leaf_is_uffd_wp: bool)
    -> Option<UffdFaultKind> {
    if leaf_is_uffd_wp && modes.contains(crate::vma::VmaFlags::UFFD_WP) {
        return Some(UffdFaultKind::Wp);
    }
    None
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

    /// The marker and the registration must BOTH hold. A stale marker left by
    /// an unregistration would otherwise block the writer on a context that
    /// has stopped listening.
    #[test]
    fn a_write_is_the_monitors_only_with_both_the_marker_and_the_registration() {
        assert_eq!(write_fault_kind(WP, true), Some(UffdFaultKind::Wp));
        assert_eq!(write_fault_kind(WP, false), None);
        assert_eq!(write_fault_kind(MISSING | MINOR, true), None);
        assert_eq!(write_fault_kind(VmaFlags::empty(), true), None);
    }
}
