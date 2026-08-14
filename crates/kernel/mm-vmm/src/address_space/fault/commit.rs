use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use super::super::AddressSpace;

impl AddressSpace {
    /// Publish a demand-fault leaf only while its slot is still absent.
    ///
    /// File faults deliberately perform backing I/O before reaching this
    /// boundary.  A sibling in the same mm can install the same address while
    /// that I/O sleeps, so a lockless translate followed by `M::map` is not a
    /// valid recheck: `M::map` replaces a present leaf by design.  Linux holds
    /// the PTE lock for its final `pte_none` test and install; this is the
    /// per-mm equivalent.  Never call this while holding a VMA, filesystem, or
    /// backing lock.
    ///
    /// Returns `true` only when this call installed `pa`.  A `false` result
    /// leaves the winner's mapping untouched; the caller must release its
    /// speculative frame or mapping reference.
    ///
    /// # SAFETY
    /// `va` and `pa` obey `MmuOps::map` alignment/lifetime requirements.  The
    /// caller owns `pa` until this returns true.
    pub(super) unsafe fn map_if_absent<M: MmuOps>(
        &self,
        va: Va,
        pa: Pa,
        flags: PageFlags,
        size: PageSize,
    ) -> bool {
        let _pt = self.lock_page_table();
        if M::translate(va).is_some() {
            return false;
        }
        // SAFETY: the held per-mm lock serializes the empty-slot check and
        // install against every page-table writer for this address space.
        let replaced = unsafe { M::map(va, pa, flags, size) };
        debug_assert!(replaced.is_none(), "empty PTE install displaced a leaf");
        replaced.is_none()
    }
}
