//! File/shmem reverse-map ownership (`address_space->i_mmap`).
//!
//! `FileRmap` belongs to one canonical file backing, not to a physical page.
//! Each file VMA contributes one interval edge.  A resident page stores this
//! owner plus its file-page index in PageMeta; reclaim then walks only the
//! mappings of that inode and PTE-verifies candidates before mutation.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use sync::{AnonVma as FileRmapClass, Spinlock};

use crate::{address_space::AddressSpace, Error, KResult};

/// Machine-owned teardown half installed by PMM at user-address-space init.
/// FileRmap remains the one interval owner; PMM only mutates verified leaves.
pub type TruncateUnmapHook = fn(&FileRmap, u64, u64) -> usize;

static TRUNCATE_UNMAP: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the PMM leaf-teardown half. # C: O(1)
pub fn set_truncate_unmap_hook(hook: TruncateUnmapHook) {
    TRUNCATE_UNMAP.store(hook as *mut (), Ordering::Release);
}

/// Whether boot installed the machine half. # C: O(1)
pub fn truncate_unmap_hook_installed() -> bool {
    !TRUNCATE_UNMAP.load(Ordering::Acquire).is_null()
}

/// One `address_space->i_mmap` interval. `file_page_start` is the backing
/// page index corresponding to `start`; it makes split VMAs and nonzero file
/// offsets exact without deriving ownership from a virtual address.
pub struct FileRmapTarget {
    seq:             u64,
    mm:              Weak<AddressSpace>,
    start:           u64,
    end:             u64,
    file_page_start: u64,
    may_write:       bool,
}

struct FileRmapState {
    targets: Vec<FileRmapTarget>,
    next_seq: u64,
    pending_writable: usize,
    writable_denied: bool,
}

/// Linux-shaped file reverse-map owner plus `i_mmap_writable` state. PageMeta
/// holds a strong reference while a resident shared page names this mapping.
/// Weak mms avoid pinning a dead process through an inode.
pub struct FileRmap {
    state: Spinlock<FileRmapState, FileRmapClass>,
}

/// A writable shared mmap admitted before VMA placement. Its lifetime covers
/// address selection and destructive `MAP_FIXED` teardown, closing the race
/// with `F_SEAL_WRITE`. # C: O(1)
pub struct WritableMapReservation {
    owner: Arc<FileRmap>,
}

impl Drop for WritableMapReservation {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock();
        debug_assert!(state.pending_writable != 0);
        state.pending_writable -= 1;
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WriteSealError {
    Busy,
}

impl FileRmap {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Spinlock::new(FileRmapState {
                targets: Vec::new(),
                next_seq: 1,
                pending_writable: 0,
                writable_denied: false,
            }),
        })
    }

    /// Linux `mapping_map_writable`: reserve a future `VM_SHARED|VM_MAYWRITE`
    /// VMA unless `mapping_deny_writable` already won. # C: O(1)
    pub fn reserve_writable(self: &Arc<Self>) -> KResult<WritableMapReservation> {
        let mut state = self.state.lock();
        if state.writable_denied { return Err(Error::Perm); }
        state.pending_writable = state.pending_writable.checked_add(1).ok_or(Error::NoMem)?;
        Ok(WritableMapReservation { owner: Arc::clone(self) })
    }

    /// Link one live MAP_SHARED file VMA. # C: amortised O(1)
    pub fn attach(
        &self,
        mm: Weak<AddressSpace>,
        start: u64,
        end: u64,
        file_page_start: u64,
        may_write: bool,
    ) {
        let mut state = self.state.lock();
        let seq = state.next_seq;
        state.next_seq = state.next_seq.wrapping_add(1).max(1);
        state.targets.push(FileRmapTarget {
            seq, mm, start, end, file_page_start, may_write,
        });
    }

    /// Unlink every edge covered by one current VMA interval. Adjacent mmap
    /// insertions can merge in the VMA tree while retaining one rmap edge per
    /// insertion; removing the merged VMA must retire all of them.
    /// # C: O(N_vmas_for_file)
    pub fn detach(&self, mm: &Weak<AddressSpace>, start: u64, end: u64, _file_page_start: u64) {
        let mm_ptr = mm.as_ptr();
        let mut state = self.state.lock();
        state.targets.retain(|target| {
            target.mm.as_ptr() != mm_ptr || target.start < start || target.end > end
        });
    }

    /// Linux `mapping_deny_writable` plus seal publication. The mapping state
    /// remains locked across `publish`, so either a writable-map reservation
    /// wins and sealing reports EBUSY, or the seal wins and later reservations
    /// report EPERM. A failed CAS rolls the denial back. # C: O(N_vmas_for_file)
    pub fn commit_write_seal<F: FnOnce() -> bool>(
        &self,
        publish: F,
    ) -> Result<bool, WriteSealError> {
        let mut state = self.state.lock();
        state.targets.retain(|target| target.mm.strong_count() != 0);
        let was_denied = state.writable_denied;
        if !was_denied {
            if state.pending_writable != 0
                || state.targets.iter().any(|target| target.may_write)
            {
                return Err(WriteSealError::Busy);
            }
            state.writable_denied = true;
        }
        let published = publish();
        if !published && !was_denied { state.writable_denied = false; }
        Ok(published)
    }

    /// Yield all live mappings for one file page.  The result is a candidate
    /// set only: caller must hold the target PTE lock and verify both the PA
    /// and VMA before replacing the leaf. # C: O(N_vmas_for_file)
    pub fn walk_page<F: FnMut(Arc<AddressSpace>, u64)>(&self, page_index: u64, mut f: F) -> KResult<()> {
        self.walk_range(page_index, page_index.saturating_add(1), |mm, va, _, pages| {
            debug_assert_eq!(pages, 1);
            f(mm, va);
        })
    }

    /// Yield the live VMA spans intersecting file-page range `[first, end)`.
    /// One stable sequence cursor makes this allocation-free: truncate cannot
    /// abandon PTE revocation because heap allocation failed. The callback
    /// runs after the interval lock is dropped. # C: O(N_vmas² + visits)
    pub fn walk_range<F: FnMut(Arc<AddressSpace>, u64, u64, u64)>(
        &self, first: u64, end: u64, mut f: F,
    ) -> KResult<()> {
        if end <= first { return Ok(()); }
        let mut after = 0u64;
        loop {
            let visit = {
                let state = self.state.lock();
                state.targets.iter().filter(|target| target.seq > after).find_map(|target| {
                    let pages = (target.end - target.start) / hal::PAGE_SIZE_BYTES;
                    let target_end = target.file_page_start.saturating_add(pages);
                    let lo = first.max(target.file_page_start);
                    let hi = end.min(target_end);
                    if hi <= lo { return None; }
                    let mm = target.mm.upgrade()?;
                    let delta = lo - target.file_page_start;
                    Some((target.seq, mm, target.start + delta * hal::PAGE_SIZE_BYTES, lo, hi - lo))
                })
            };
            let Some((seq, mm, va, page, pages)) = visit else { break; };
            after = seq;
            // Never call into an mm while the i_mmap interval lock is held: a
            // concurrent munmap/mprotect detaches under its VMA lock and must
            // not invert that order against pageout's PTE/VMA revalidation.
            f(mm, va, page, pages);
        }
        Ok(())
    }

    /// Remove every private and shared PTE covering `[first, end)` before a
    /// truncate drops those file pages. PMM supplies TLB/refcount effects.
    /// # C: O(N_vmas + mapped pages)
    pub fn unmap_truncate_range(&self, first: u64, end: u64) -> usize {
        let raw = TRUNCATE_UNMAP.load(Ordering::Acquire);
        if raw.is_null() { return 0; }
        // SAFETY: the slot is written only by `set_truncate_unmap_hook` from
        // this exact function type; Release/Acquire publishes a static address.
        let unmap: TruncateUnmapHook = unsafe {
            core::mem::transmute::<*mut (), TruncateUnmapHook>(raw)
        };
        unmap(self, first, end)
    }

    /// # C: O(N_vmas_for_file)
    pub fn live_target_count(&self) -> usize {
        self.state.lock().targets.iter()
            .filter(|target| target.mm.upgrade().is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::FileRmap;
    use crate::{
        AddressSpace, FileBacking, FileBackingError, VmaBacking, VmaFlags, VmaProt,
    };
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use hal::UserVirtAddr;

    struct TestBacking {
        rmap: Arc<FileRmap>,
    }

    impl FileBacking for TestBacking {
        fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> {
            Ok(0)
        }

        fn size_hint(&self) -> u64 { hal::PAGE_SIZE_BYTES }

        fn file_rmap(&self) -> Option<Arc<FileRmap>> { Some(Arc::clone(&self.rmap)) }
    }

    fn uva(value: u64) -> UserVirtAddr {
        UserVirtAddr::new(value).unwrap()
    }

    #[test]
    fn file_page_walk_honors_backing_offset_and_interval() {
        let rmap = FileRmap::new();
        let mm = AddressSpace::new(0x9000).unwrap();
        rmap.attach(Arc::downgrade(&mm), 0x4000, 0x6000, 7, true);
        let mut hits = Vec::new();
        rmap.walk_page(8, |target, va| hits.push((target.root_pa(), va))).unwrap();
        assert_eq!(hits, alloc::vec![(0x9000, 0x5000)]);
        assert_eq!(rmap.live_target_count(), 1);
    }

    #[test]
    fn reservation_and_live_maywrite_mapping_exclude_a_write_seal() {
        let rmap = FileRmap::new();
        let pending = rmap.reserve_writable().unwrap();
        assert_eq!(rmap.commit_write_seal(|| true), Err(super::WriteSealError::Busy));
        drop(pending);

        let mm = AddressSpace::new(0xA000).unwrap();
        rmap.attach(Arc::downgrade(&mm), 0x4000, 0x5000, 0, true);
        assert_eq!(rmap.commit_write_seal(|| true), Err(super::WriteSealError::Busy));
        drop(mm);

        assert_eq!(rmap.commit_write_seal(|| true), Ok(true));
        assert!(matches!(rmap.reserve_writable(), Err(crate::Error::Perm)));
    }

    #[test]
    fn read_only_mapping_does_not_block_and_failed_publish_rolls_back() {
        let rmap = FileRmap::new();
        let mm = AddressSpace::new(0xB000).unwrap();
        rmap.attach(Arc::downgrade(&mm), 0x4000, 0x5000, 0, false);
        assert_eq!(rmap.commit_write_seal(|| false), Ok(false));
        assert!(rmap.reserve_writable().is_ok());
        assert_eq!(rmap.commit_write_seal(|| true), Ok(true));
    }

    #[test]
    fn address_space_lifecycle_tracks_maywrite_and_allows_read_only_after_seal() {
        let rmap = FileRmap::new();
        let backing: Arc<dyn FileBacking> =
            Arc::new(TestBacking { rmap: Arc::clone(&rmap) });
        let mm = AddressSpace::new(0xC000).unwrap();
        let file = VmaBacking::File { backing: Arc::clone(&backing), off: 0 };
        let rw = VmaProt::READ | VmaProt::WRITE;
        mm.mmap_with_may(
            Some(uva(0x4000)),
            hal::PAGE_SIZE_BYTES as usize,
            VmaProt::READ,
            rw,
            VmaFlags::SHARED,
            file,
            false,
        ).unwrap();
        assert_eq!(rmap.commit_write_seal(|| true), Err(super::WriteSealError::Busy));
        mm.munmap(uva(0x4000), hal::PAGE_SIZE_BYTES as usize).unwrap();
        assert_eq!(rmap.commit_write_seal(|| true), Ok(true));

        let read_only = VmaBacking::File { backing, off: 0 };
        mm.mmap_with_may(
            Some(uva(0x8000)),
            hal::PAGE_SIZE_BYTES as usize,
            VmaProt::READ,
            VmaProt::READ,
            VmaFlags::SHARED,
            read_only,
            false,
        ).unwrap();
        assert_eq!(
            mm.mprotect(
                uva(0x8000),
                hal::PAGE_SIZE_BYTES as usize,
                VmaProt::READ | VmaProt::WRITE,
            ),
            Err(crate::Error::Access),
        );
    }

    #[test]
    fn forked_shared_maywrite_mapping_remains_visible_after_parent_unmaps() {
        let rmap = FileRmap::new();
        let backing: Arc<dyn FileBacking> =
            Arc::new(TestBacking { rmap: Arc::clone(&rmap) });
        let parent = AddressSpace::new(0xD000).unwrap();
        parent.mmap_with_may(
            Some(uva(0x4000)),
            hal::PAGE_SIZE_BYTES as usize,
            VmaProt::READ,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::SHARED,
            VmaBacking::File { backing, off: 0 },
            false,
        ).unwrap();
        let child = parent.fork(0xE000).unwrap();
        parent.munmap(uva(0x4000), hal::PAGE_SIZE_BYTES as usize).unwrap();
        assert_eq!(rmap.commit_write_seal(|| true), Err(super::WriteSealError::Busy));
        child.munmap(uva(0x4000), hal::PAGE_SIZE_BYTES as usize).unwrap();
        assert_eq!(rmap.commit_write_seal(|| true), Ok(true));
    }

    #[test]
    fn unmapping_a_merged_vma_retires_each_original_rmap_edge() {
        let rmap = FileRmap::new();
        let backing: Arc<dyn FileBacking> =
            Arc::new(TestBacking { rmap: Arc::clone(&rmap) });
        let mm = AddressSpace::new(0xF000).unwrap();
        let rw = VmaProt::READ | VmaProt::WRITE;
        for (va, off) in [(0x4000, 0), (0x5000, hal::PAGE_SIZE_BYTES)] {
            mm.mmap_with_may(
                Some(uva(va)),
                hal::PAGE_SIZE_BYTES as usize,
                VmaProt::READ,
                rw,
                VmaFlags::SHARED,
                VmaBacking::File { backing: Arc::clone(&backing), off },
                false,
            ).unwrap();
        }
        assert_eq!(rmap.live_target_count(), 2);
        mm.munmap(uva(0x4000), 2 * hal::PAGE_SIZE_BYTES as usize).unwrap();
        assert_eq!(rmap.live_target_count(), 0);
        assert_eq!(rmap.commit_write_seal(|| true), Ok(true));
    }

    #[test]
    fn private_and_shared_vmas_share_the_canonical_file_interval_owner() {
        let rmap = FileRmap::new();
        let backing: Arc<dyn FileBacking> =
            Arc::new(TestBacking { rmap: Arc::clone(&rmap) });
        let mm = AddressSpace::new(0x11_000).unwrap();
        for (va, flags) in [(0x4000, VmaFlags::PRIVATE), (0x8000, VmaFlags::SHARED)] {
            mm.mmap_with_may(
                Some(uva(va)),
                2 * hal::PAGE_SIZE_BYTES as usize,
                VmaProt::READ,
                VmaProt::READ | VmaProt::WRITE,
                flags,
                VmaBacking::File { backing: Arc::clone(&backing), off: 7 * hal::PAGE_SIZE_BYTES },
                false,
            ).unwrap();
        }
        let mut hits = Vec::new();
        rmap.walk_range(8, 9, |target, va, page, pages| {
            hits.push((target.root_pa(), va, page, pages));
        }).unwrap();
        hits.sort_unstable();
        assert_eq!(hits, alloc::vec![(0x11_000, 0x5000, 8, 1), (0x11_000, 0x9000, 8, 1)]);
        let mut tears = 0;
        assert!(!mm.tear_file_page_if(uva(0x5000), &rmap, 7, || { tears += 1; true }));
        assert_eq!(tears, 0, "a stale page-index candidate cannot tear a leaf");
        mm.account_pte_install_at(uva(0x5000));
        assert!(mm.tear_file_page_if(uva(0x5000), &rmap, 8, || { tears += 1; true }));
        assert_eq!(tears, 1, "the live private file page reaches the machine half once");
    }
}
