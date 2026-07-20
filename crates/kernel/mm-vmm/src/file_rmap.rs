//! File/shmem reverse-map ownership (`address_space->i_mmap`).
//!
//! `FileRmap` belongs to one canonical file backing, not to a physical page.
//! Each file VMA contributes one interval edge.  A resident page stores this
//! owner plus its file-page index in PageMeta; reclaim then walks only the
//! mappings of that inode and PTE-verifies candidates before mutation.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{AnonVma as FileRmapClass, Spinlock};

use crate::{address_space::AddressSpace, Error, KResult};

/// One `address_space->i_mmap` interval. `file_page_start` is the backing
/// page index corresponding to `start`; it makes split VMAs and nonzero file
/// offsets exact without deriving ownership from a virtual address.
pub struct FileRmapTarget {
    mm:              Weak<AddressSpace>,
    start:           u64,
    end:             u64,
    file_page_start: u64,
}

/// Linux-shaped file reverse-map owner.  Its only truth is the VMA interval
/// set; PageMeta holds a strong reference while a resident shared page names
/// this mapping.  Weak mms avoid pinning a dead process through an inode.
pub struct FileRmap {
    targets: Spinlock<Vec<FileRmapTarget>, FileRmapClass>,
}

impl FileRmap {
    /// # C: O(1)
    pub fn new() -> Arc<Self> { Arc::new(Self { targets: Spinlock::new(Vec::new()) }) }

    /// Link one live MAP_SHARED file VMA. # C: amortised O(1)
    pub fn attach(&self, mm: Weak<AddressSpace>, start: u64, end: u64, file_page_start: u64) {
        self.targets.lock().push(FileRmapTarget { mm, start, end, file_page_start });
    }

    /// Unlink exactly one VMA interval after munmap, mprotect split, or AS
    /// teardown. # C: O(N_vmas_for_file)
    pub fn detach(&self, mm: &Weak<AddressSpace>, start: u64, end: u64, file_page_start: u64) {
        let mm_ptr = mm.as_ptr();
        let mut targets = self.targets.lock();
        if let Some(pos) = targets.iter().position(|target| {
            target.mm.as_ptr() == mm_ptr && target.start == start && target.end == end
                && target.file_page_start == file_page_start
        }) { targets.swap_remove(pos); }
    }

    /// Yield all live mappings for one file page.  The result is a candidate
    /// set only: caller must hold the target PTE lock and verify both the PA
    /// and VMA before replacing the leaf. # C: O(N_vmas_for_file)
    pub fn walk_page<F: FnMut(Arc<AddressSpace>, u64)>(&self, page_index: u64, mut f: F) -> KResult<()> {
        let mut visits = Vec::new();
        let targets = self.targets.lock();
        for target in targets.iter() {
            let pages = (target.end - target.start) / hal::PAGE_SIZE_BYTES;
            if page_index < target.file_page_start { continue; }
            let delta = page_index - target.file_page_start;
            if delta >= pages { continue; }
            if let Some(mm) = target.mm.upgrade() {
                visits.try_reserve(1).map_err(|_| Error::NoMem)?;
                visits.push((mm, target.start + delta * hal::PAGE_SIZE_BYTES));
            }
        }
        drop(targets);
        // Never call into an mm while the i_mmap interval lock is held: a
        // concurrent munmap/mprotect detaches under its VMA lock and must not
        // invert that order against pageout's PTE/VMA revalidation.
        for (mm, va) in visits { f(mm, va); }
        Ok(())
    }

    /// # C: O(N_vmas_for_file)
    pub fn live_target_count(&self) -> usize {
        self.targets.lock().iter().filter(|target| target.mm.upgrade().is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::FileRmap;
    use crate::AddressSpace;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    #[test]
    fn file_page_walk_honors_backing_offset_and_interval() {
        let rmap = FileRmap::new();
        let mm = AddressSpace::new(0x9000).unwrap();
        rmap.attach(Arc::downgrade(&mm), 0x4000, 0x6000, 7);
        let mut hits = Vec::new();
        rmap.walk_page(8, |target, va| hits.push((target.root_pa(), va))).unwrap();
        assert_eq!(hits, alloc::vec![(0x9000, 0x5000)]);
        assert_eq!(rmap.live_target_count(), 1);
    }
}
