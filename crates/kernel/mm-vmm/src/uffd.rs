// userfaultfd per-VMA hook per `27` — Linux `vm_userfaultfd_ctx`.
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

use alloc::sync::Arc;

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
    /// # C: O(1) enqueue + block
    fn missing_fault(&self, addr: u64, write: bool);
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
