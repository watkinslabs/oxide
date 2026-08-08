// The address_space a mapping of a hugetlbfs file faults on.
//
// Offsets here are HUGE-page aligned, not base-page aligned: the fault handler
// resolves a faulting address to the huge page that covers it before asking,
// so every offset this sees names one whole page of the file.

use core::sync::atomic::Ordering;

use vfs::{AddressSpaceOps, KResult};

use super::file::HugetlbfsFileData;

impl AddressSpaceOps for HugetlbfsFileData {
    /// The huge page backing `off`, allocating on first touch. The reference
    /// is left for the fault handler to take, so a page's mapping count is
    /// incremented by the code that installs the leaf and decremented by the
    /// code that clears it — one owner for both halves of the pair.
    /// # C: O(log N_pages)
    fn shared_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let pa = self.ensure_page(off / self.huge_bytes())?;
        Ok(Some(vfs::SharedFrame { pa, map_ref_held: false }))
    }

    /// No speculative neighbours: one leaf already covers a whole huge page,
    /// so there is no adjacent page a single fault could usefully install.
    /// # C: O(1)
    fn fault_around_frame(&self, _off: u64) -> KResult<Option<vfs::SharedFrame>> { Ok(None) }

    /// # C: O(log N_pages)
    fn backing_holds_page(&self, off: u64) -> bool {
        self.body.lock().pages.contains_key(&(off / self.huge_bytes()))
    }

    /// # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> { self.read_bytes(off, dst) }

    /// These pages are the file; there is nothing behind them to write to.
    /// # C: O(1)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// # C: O(log N_pages)
    fn mincore_page(&self, off: u64) -> bool {
        self.body.lock().pages.contains_key(&(off / self.huge_bytes()))
    }

    /// These frames are the file. # C: O(1)
    fn is_shmem(&self) -> bool { true }

    /// # C: O(1)
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
}
