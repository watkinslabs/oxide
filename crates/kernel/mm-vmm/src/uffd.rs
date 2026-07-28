// userfaultfd per-VMA hook per `27` — Linux `vm_userfaultfd_ctx` — plus the
// `vm.unprivileged_userfaultfd` tunable that gates fd creation.
//
// A MISSING-registered VMA carries an `Arc<dyn UffdContext>` (the fs
// `userfaultfd` inode state). The page-fault handler calls
// `missing_fault` on a NotPresent fault inside such a VMA instead of
// zero-filling: the context enqueues a `uffd_msg` PAGEFAULT event,
// wakes the monitor reading the fd, and BLOCKS the faulting thread
// until `UFFDIO_COPY`/`UFFDIO_ZEROPAGE`/`UFFDIO_WAKE` resolves the
// address; it returns when the faulting instruction should retry.
//
// Trait-object (dyn) so `mm-vmm` (no fs/sched deps) stays below the fs
// crate that implements it — the same layering as `FileBacking`.
//
// The tunable lives here rather than in the fs crate because Linux registers
// it under `vm` from the mm subsystem (`mm/userfaultfd.c`
// `register_sysctl_init("vm", vm_userfaultfd_table)`), and because procfs sits
// BELOW fs in the crate graph and so cannot reach an fs-owned variable.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

/// Per-VMA userfaultfd hook (Linux `vm_userfaultfd_ctx.ctx`). Impl'd by
/// the fs `userfaultfd` inode state; installed on VMAs via
/// [`crate::AddressSpace::set_uffd_missing`].
pub trait UffdContext: Send + Sync {
    /// Called on a NotPresent fault at page-aligned `addr` inside a
    /// MISSING-registered range. Enqueues a PAGEFAULT message, wakes the
    /// fd's readers/pollers, and BLOCKS the calling (faulting) thread
    /// until the address is resolved or an explicit wake fires; returns
    /// when the faulting instruction should be retried. `write` = the
    /// fault was a write access (sets `UFFD_PAGEFAULT_FLAG_WRITE`).
    ///
    /// `user_mode` is Linux's `vmf->flags & FAULT_FLAG_USER`: false for a
    /// kernel-mode access to the user VA (uaccess, `get_user_pages`). A
    /// context created with `UFFD_USER_MODE_ONLY` refuses those — Linux
    /// `handle_userfault` returns `VM_FAULT_SIGBUS` — which is signalled by
    /// returning `false`. `true` means "handled, retry the instruction".
    /// # C: O(1) enqueue + block
    fn missing_fault(&self, addr: u64, write: bool, user_mode: bool) -> bool;
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

/// Linux `static int sysctl_unprivileged_userfaultfd __read_mostly;`
/// (`mm/userfaultfd.c`) — a zero-initialised `int`, i.e. DENY by default, with
/// a `proc_dointvec_minmax` window of `[SYSCTL_ZERO, SYSCTL_ONE]`.
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
