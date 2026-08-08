// A hugetlbfs regular file: its huge-page store, its reservations, and the
// inode/file operations over them.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};

use core::sync::atomic::{AtomicU64, Ordering};

use pmm::hugetlb;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::superblock::SuperBlock;
use vfs::{AddressSpaceOps, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult,
          VfsError, mk_mode};

use super::accounting::HugetlbfsSb;
use super::inode::{fsid_of, iget_or_build, next_ino};

/// The file's page state, under one lock so a reservation and the page it
/// covers can never be updated apart.
pub(super) struct Body {
    /// `huge index -> physical base of the huge page`. Sparse: a hole reads
    /// as zero, exactly as a hole in any other file does.
    pub(super) pages: BTreeMap<u64, u64>,
    /// Huge indices a mapping has reserved but nothing has faulted yet. This
    /// is the file's `resv_map`: a shared mapping's promise lives on the
    /// INODE, so every mapper of one file shares one set of promises and two
    /// mappings of the same range are promised the same pages once.
    pub(super) resv: BTreeSet<u64>,
}

pub struct HugetlbfsFileData {
    pub(super) body: Spinlock<Body, TaskListClass>,
    /// Logical size (`i_size`); may exceed the populated pages.
    pub(super) len:  AtomicU64,
    /// Owning mount's enforced state.
    pub(super) sb:   Arc<HugetlbfsSb>,
}

impl HugetlbfsFileData {
    /// Byte size of the huge page this file is made of. # C: O(1)
    pub(super) fn huge_bytes(&self) -> u64 { self.sb.huge_size().bytes() }

    /// Take the huge page at `idx`, allocating it on first touch.
    ///
    /// A page a mapping already reserved consumes that reservation; a page
    /// nothing reserved is charged now and refused with `ENOSPC` when the
    /// mount is full. The page is zeroed before it becomes reachable, because
    /// a hole in a file reads as zero and a recycled pool page holds whatever
    /// its last owner wrote.
    /// # C: O(log N_pages) + O(huge page) on first touch
    pub(super) fn ensure_page(&self, idx: u64) -> KResult<u64> {
        let size = self.sb.huge_size();
        let mut g = self.body.lock();
        if let Some(&pa) = g.pages.get(&idx) { return Ok(pa); }
        let reserved = g.resv.remove(&idx);
        if !reserved { self.sb.charge_unreserved_page()?; }
        let Some(pa) = hugetlb::alloc_huge_frame(size, reserved) else {
            if reserved { g.resv.insert(idx); } else { self.sb.uncharge_page(); }
            return Err(VfsError::Enomem);
        };
        if let Some(dst) = pmm::setup::frame_ptr(pa) {
            hal::zerotrap::trap(dst as *const u8, size.bytes() as usize);
            // SAFETY: `pa` heads a huge page this file now owns exclusively and
            // no page table maps yet; the HHDM mirror covers the whole run.
            unsafe { core::ptr::write_bytes(dst, 0, size.bytes() as usize); }
        }
        g.pages.insert(idx, pa);
        Ok(pa)
    }

    /// Copy out of the file's pages, zero-filling holes and the tail past the
    /// logical size. # C: O(dst.len)
    pub(super) fn read_bytes(&self, off: u64, dst: &mut [u8]) -> KResult<usize> {
        let hb = self.huge_bytes();
        let len = self.len.load(Ordering::Acquire);
        if off >= len { return Ok(0); }
        let want = core::cmp::min(dst.len() as u64, len - off) as usize;
        let g = self.body.lock();
        let mut done = 0usize;
        while done < want {
            let cur = off + done as u64;
            let idx = cur / hb;
            let in_page = (cur % hb) as usize;
            let n = core::cmp::min(hb as usize - in_page, want - done);
            match g.pages.get(&idx).copied().and_then(pmm::setup::frame_ptr) {
                // SAFETY: `src` is the HHDM mirror of a huge page this file owns, and `n` stays inside it by construction.
                Some(src) => unsafe {
                    core::ptr::copy_nonoverlapping(src.add(in_page), dst[done..].as_mut_ptr(), n);
                },
                None => dst[done..done + n].fill(0),
            }
            done += n;
        }
        Ok(done)
    }

    /// A private copy of the huge page at `idx`, for a `MAP_PRIVATE` mapping.
    ///
    /// The source page is materialised first — a private mapping still reads
    /// the file's contents, and a copy of a page that does not exist yet is a
    /// page of zeroes, which is exactly what a hole reads as. The copy is
    /// charged to the mount like any other page it hands out, and carries
    /// exactly ONE reference, the caller's, so the mapping owns it outright and
    /// releasing it returns it to the pool.
    /// # C: O(huge page)
    pub(super) fn cow_page(&self, idx: u64) -> KResult<vfs::SharedFrame> {
        let size = self.sb.huge_size();
        let src = self.ensure_page(idx)?;
        self.sb.charge_unreserved_page()?;
        let Some(dst) = hugetlb::alloc_huge_frame(size, false) else {
            self.sb.uncharge_page();
            return Err(VfsError::Enomem);
        };
        if let (Some(sp), Some(dp)) = (pmm::setup::frame_ptr(src), pmm::setup::frame_ptr(dst)) {
            // SAFETY: `sp` and `dp` head two DISTINCT huge pages of `size` —
            // the destination is off the pool free list, so nothing else can
            // reach it — and the HHDM mirror covers both runs in full.
            unsafe { core::ptr::copy_nonoverlapping(sp, dp, size.bytes() as usize); }
        }
        Ok(vfs::SharedFrame { pa: dst, map_ref_held: true })
    }

    /// Release one reference to a huge page this file handed out, returning it
    /// to the pool when the last one goes.
    /// # C: O(log nr)
    pub(super) fn put_page(&self, pa: u64) {
        if hugetlb::huge_frame_dec_and_maybe_release(self.sb.huge_size(), pa) {
            self.sb.uncharge_page();
        }
    }

    /// Drop every page and every unconsumed reservation the file holds,
    /// returning the pages to the pool that owns them.
    /// # C: O(N_pages)
    pub(super) fn release_all(&self) {
        let size = self.sb.huge_size();
        let mut g = self.body.lock();
        let pages: alloc::vec::Vec<u64> = g.pages.values().copied().collect();
        let n_resv = g.resv.len() as u64;
        g.pages.clear();
        g.resv.clear();
        drop(g);
        for pa in pages {
            hugetlb::huge_frame_dec_and_maybe_release(size, pa);
            self.sb.uncharge_page();
        }
        self.sb.unreserve_pages(n_resv);
    }

    /// Reserve every huge index in `[off, off+len)` that is not already
    /// promised or resident, so a mapping of that range cannot later fail to
    /// find a page.
    /// # C: O(pages in range)
    pub(super) fn reserve_range(&self, off: u64, len: u64) -> KResult<()> {
        let hb = self.huge_bytes();
        if len == 0 { return Ok(()); }
        let first = off / hb;
        let last  = (off + len - 1) / hb;
        let mut want = alloc::vec::Vec::new();
        {
            let g = self.body.lock();
            for idx in first..=last {
                if !g.pages.contains_key(&idx) && !g.resv.contains(&idx) { want.push(idx); }
            }
        }
        if want.is_empty() { return Ok(()); }
        self.sb.reserve_pages(want.len() as u64)?;
        let mut g = self.body.lock();
        for idx in want { g.resv.insert(idx); }
        Ok(())
    }

    /// Set the logical size, dropping pages past the new end.
    /// # C: O(pages dropped)
    pub(super) fn truncate_to(&self, new_len: u64) -> KResult<()> {
        let hb = self.huge_bytes();
        // Linux refuses a hugetlbfs size that is not a whole number of huge
        // pages: a partial huge page is not a thing the file can hold.
        if new_len % hb != 0 { return Err(VfsError::Einval); }
        let size = self.sb.huge_size();
        let first_gone = new_len / hb;
        let mut g = self.body.lock();
        let dropped: alloc::vec::Vec<u64> = g.pages.range(first_gone..).map(|(_, &pa)| pa).collect();
        let keys: alloc::vec::Vec<u64> = g.pages.range(first_gone..).map(|(&k, _)| k).collect();
        for k in keys { g.pages.remove(&k); }
        let resv_gone: alloc::vec::Vec<u64> = g.resv.range(first_gone..).copied().collect();
        for k in &resv_gone { g.resv.remove(k); }
        drop(g);
        for pa in dropped {
            hugetlb::huge_frame_dec_and_maybe_release(size, pa);
            self.sb.uncharge_page();
        }
        self.sb.unreserve_pages(resv_gone.len() as u64);
        self.len.store(new_len, Ordering::Release);
        Ok(())
    }
}

impl Drop for HugetlbfsFileData {
    fn drop(&mut self) {
        self.release_all();
        self.sb.free_inode();
    }
}

/// Reserve the huge pages a mapping of `[off, off+len)` of `inode` will need.
///
/// This is where a hugetlbfs mapping's memory is committed — at `mmap`, not at
/// the fault — so a program that maps more than the mount or the pool can hold
/// is told so by `mmap` with `ENOMEM`, rather than by a fault it has no way to
/// handle. A non-hugetlbfs inode needs nothing and says so.
/// # C: O(pages in range)
pub fn reserve_mapping(inode: &Inode, off: u64, len: u64) -> KResult<()> {
    let Some(d) = inode.private::<HugetlbfsFileData>() else { return Ok(()) };
    let hb = d.huge_bytes();
    // A mapping whose offset is not a whole number of huge pages can never be
    // served by huge leaves, so it is refused rather than silently shifted.
    if off % hb != 0 { return Err(VfsError::Einval); }
    let end = off.checked_add(len).ok_or(VfsError::Einval)?;
    d.reserve_range(off, len)?;
    // A shared mapping past the end grows the file, exactly as it does in the
    // reference: the pages it reserved are part of the file now.
    if end > d.len.load(Ordering::Acquire) {
        d.len.store(end, Ordering::Release);
        inode.set_size(end);
    }
    Ok(())
}

/// Build a hugetlbfs regular-file inode on `sb_acct`'s mount.
/// # C: O(1)
pub(super) fn make_file_inode(perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>,
                              acct: Arc<HugetlbfsSb>) -> Option<InodeRef> {
    if !acct.charge_inode() { return None; }
    let ino = next_ino();
    let sb2 = sb.clone();
    Some(iget_or_build(&sb, ino, move || {
        let data = Arc::new(HugetlbfsFileData {
            body: Spinlock::new(Body { pages: BTreeMap::new(), resv: BTreeSet::new() }),
            len:  AtomicU64::new(0),
            sb:   acct,
        });
        let mapping: Arc<dyn AddressSpaceOps> = data.clone();
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Regular, perm),
            Arc::new(HugetlbfsFileInodeOps), Arc::new(HugetlbfsFileOps))
            .owner(uid, gid)
            .btime(crate::tmpfs::birth_time())
            .fsid(fsid_of(&sb2))
            .mapping(mapping)
            .xattrs(vfs::SimpleXattrs::new())
            .private(data);
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        b.build()
    }))
}

/// `i_op` for a hugetlbfs regular file.
pub(super) struct HugetlbfsFileInodeOps;
impl InodeOps for HugetlbfsFileInodeOps {
    /// `hugetlbfs_setattr`'s size leg: a size that is not a whole number of
    /// huge pages is `EINVAL`, because the file cannot hold a partial one.
    /// # C: O(pages dropped)
    fn truncate(&self, inode: &Inode, new_len: u64) -> KResult<()> {
        let d = inode.private::<HugetlbfsFileData>().ok_or(VfsError::Einval)?;
        d.truncate_to(new_len)?;
        inode.set_size(new_len);
        Ok(())
    }
}

/// `i_fop` for a hugetlbfs regular file.
pub(super) struct HugetlbfsFileOps;
impl FileOps for HugetlbfsFileOps {
    /// `hugetlbfs_read_iter`. # C: O(buf.len)
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<HugetlbfsFileData>().ok_or(VfsError::Einval)?;
        d.read_bytes(off, buf)
    }

    /// hugetlbfs has no `write_iter`: the only way to put bytes in one of
    /// these files is to map it, which is the whole point of the filesystem.
    /// # C: O(1)
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    /// `hstate_inode` — the granule this file's pages are. # C: O(1)
    fn huge_page_size(&self, inode: &Inode) -> u64 {
        inode.private::<HugetlbfsFileData>().map_or(0, |d| d.huge_bytes())
    }

    /// A private copy of the huge page at `off`, for a `MAP_PRIVATE` mapping
    /// whose writes must not reach the file.
    /// # C: O(huge page)
    fn huge_cow_frame(&self, inode: &Inode, off: u64) -> KResult<Option<vfs::SharedFrame>> {
        let d = inode.private::<HugetlbfsFileData>().ok_or(VfsError::Einval)?;
        d.cow_page(off / d.huge_bytes()).map(Some)
    }

    /// # C: O(log nr)
    fn huge_put_frame(&self, inode: &Inode, pa: u64) {
        if let Some(d) = inode.private::<HugetlbfsFileData>() { d.put_page(pa); }
    }

    /// These pages are never written back to anything (`noop_fsync`).
    /// # C: O(1)
    fn fsync(&self, _file: &vfs::File, _datasync: bool) -> KResult<()> { Ok(()) }

    /// A huge page is not a block-device transfer unit. # C: O(1)
    fn can_odirect(&self, _inode: &Inode) -> bool { false }
}
