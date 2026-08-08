use core::sync::atomic::Ordering;

use vfs::{AddressSpaceOps, KResult};

use super::file::{ensure_page, ShmemPage, TmpfsFileData};
use super::limits::PG;

/// The tmpfs inode's persistent, sparse shmem address_space. Every mapper of
/// one inode reaches these frames, so shared writes and fork retain one store.
impl AddressSpaceOps for TmpfsFileData {
    /// MAP_SHARED backing frame, allocating on first touch. # C: O(log N_pages)
    fn shared_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let idx = off / PG as u64;
        loop {
            let migrating = {
                let mut g = self.pages.lock();
                match g.get(&idx).copied() {
                    Some(ShmemPage::Migrating { token, .. }) => Some(token),
                    _ => {
                        let pa = ensure_page(&mut g, idx, &self.acct)?;
                        // SAFETY: index lock keeps this terminal resident
                        // state live until this map reference is recorded.
                        unsafe { pmm::setup::inc_ref(pa); }
                        return Ok(Some(vfs::SharedFrame { pa, map_ref_held: true }));
                    }
                }
            };
            super::migration::wait_and_restart(migrating.expect("migrating branch token"));
        }
    }

    /// Return only a stable resident page. Holes, swapped entries, and an
    /// in-flight migration are skipped without allocation or waiting.
    /// # C: O(log N_pages)
    fn fault_around_frame(&self, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let idx = off / PG as u64;
        let g = self.pages.lock();
        let Some(ShmemPage::Resident { pa, .. }) = g.get(&idx).copied() else {
            return Ok(None);
        };
        // SAFETY: the index lock keeps this resident page published until the
        // prospective PTE reference has been acquired.
        unsafe { pmm::setup::inc_ref(pa); }
        Ok(Some(vfs::SharedFrame { pa, map_ref_held: true }))
    }

    /// Every index the store owns, whatever state it is in. # C: O(log N_pages)
    fn backing_holds_page(&self, off: u64) -> bool {
        self.pages.lock().contains_key(&(off / PG as u64))
    }

    /// Read-fault / MAP_PRIVATE cache copy. # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> { self.read_bytes(off, dst) }

    /// shmem pages are the store. # C: O(1)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// Move requested inode indices through the shmem migration transaction.
    /// # C: O(pages in range)
    fn madvise_pageout(&self, off: u64, len: u64) -> Option<KResult<usize>> {
        let _transaction = self.pin_transaction()?;
        Some(super::reclaim::pageout_range(self, off, len))
    }

    /// Report only existing resident shmem frames. # C: O(log N_pages)
    fn mincore_page(&self, off: u64) -> bool {
        self.pages.lock().get(&(off / PG as u64)).is_some_and(|page| page.resident_pa().is_some())
    }

    /// Fold resident, migrating, and swapped indices into cache statistics.
    /// # C: O(entries in range)
    fn cachestat(&self, range: vfs::CachestatRange) -> vfs::CachestatCounts {
        let mut cs = vfs::CachestatCounts::default();
        if range.first > range.last { return cs; }
        let entries: alloc::vec::Vec<(u64, ShmemPage)> = {
            let g = self.pages.lock();
            g.range(range.first..=range.last).map(|(&idx, &page)| (idx, page)).collect()
        };
        let age = pmm::reclaim::nonresident_age();
        let size = pmm::reclaim::workingset::file_workingset_size();
        for (idx, page) in entries {
            let nr = range.covered(idx, 1);
            match page {
                ShmemPage::Resident { .. } | ShmemPage::Migrating { .. } =>
                    cs.account(vfs::PageState::Cache { dirty: false, writeback: false }, nr),
                ShmemPage::Swapped { shadow, .. } => {
                    let recent = pmm::reclaim::workingset::test_recent_sized(shadow, age, size);
                    cs.account(vfs::PageState::Evicted { recent }, nr);
                }
            }
        }
        cs
    }

    /// These frames are the file. # C: O(1)
    fn is_shmem(&self) -> bool { true }

    /// # C: O(1)
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
}
