use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{AddressSpaceOps, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};
use vfs::superblock::SuperBlock;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::accounting::TmpfsSb;
use super::flags::{F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SHRINK, F_SEAL_WRITE};
use super::inode::{fsid_of, iget_or_build};
use super::limits::PG;
use super::page::ensure_page;
use super::quota::{self, QuotaOwner};

/// One published shmem page.  The cgid is immutable page ownership: task
/// migration, inode sharing, and cgroup removal never retarget the charge.
/// One canonical shmem page-index entry.  A swap entry remains owned by this
/// inode at the same index, rather than becoming an anonymous PTE truth.
/// This is the essential `shmem_inode_info` distinction: a hole reads zero,
/// a resident entry names its frame, and a swapped entry names durable data.
#[derive(Clone, Copy)]
pub(super) enum ShmemPage {
    Resident { pa: u64, cgid: u64 },
    /// `shadow` is the nonresident-age stamp taken when the page left memory
    /// (Linux's workingset shadow, carried by the swap entry in the mapping
    /// xarray). `cachestat(2)` reads it to judge how recent the eviction was.
    Swapped { entry: hal::pt_walker::SwapEntry, cgid: u64, shadow: u64 },
    /// Canonical in-flight shmem pageout state.  The physical frame remains
    /// owned by this inode, but no new mapper may acquire it until the token
    /// resolves to Resident (rollback) or Swapped (commit).
    Migrating { pa: u64, cgid: u64, token: hal::pt_walker::MigrationEntry },
}

impl ShmemPage {
    /// Production charge/uncharge sites destructure `cgid` out of the variant
    /// they already matched; only `shmem_page_tests` needs the accessor.
    #[cfg(test)]
    pub(super) const fn cgid(self) -> u64 {
        match self {
            Self::Resident { cgid, .. } | Self::Swapped { cgid, .. }
            | Self::Migrating { cgid, .. } => cgid,
        }
    }
    pub(super) const fn resident_pa(self) -> Option<u64> {
        match self {
            Self::Resident { pa, .. } => Some(pa),
            Self::Swapped { .. } | Self::Migrating { .. } => None,
        }
    }
}

pub struct TmpfsFileData {
    /// Weak self-reference upgraded by long-running reclaim transactions so
    /// inode teardown cannot release a page index mid-migration.
    pub(super) self_ref: Spinlock<Weak<TmpfsFileData>, TaskListClass>,
    /// `page_idx -> frame pa`. Sparse: a hole reads as zero.
    pub(super) pages: Spinlock<BTreeMap<u64, ShmemPage>, TaskListClass>,
    /// Logical size (Linux `i_size`); may exceed the populated pages. Kept in
    /// sync with the owning inode's `i_size` by the file/inode ops.
    pub(super) len: AtomicU64,
    /// Owning mount's space accounting (block charge/uncharge). # D33
    pub(super) acct: Arc<TmpfsSb>,
    /// The owner this body's block charges are made against. Distinct from the
    /// inode's uid/gid only in WHEN it is read: a body outlives its inode (an
    /// unlinked file held open), and the pages it still holds must be returned
    /// to the owner that was charged for them. A chown moves both together.
    pub(super) owner: Spinlock<QuotaOwner, TaskListClass>,
    /// The inode this body backs, so a block charge can keep `i_blocks` equal
    /// to what the owner is charged for. Weak: the inode owns this body.
    pub(super) inode: Spinlock<Weak<Inode>, TaskListClass>,
    /// memfd `F_*_SEALS` word (Linux `shmem_inode_info.seals`). Lives HERE in the
    /// per-fs inode-info, reached via `vfs::SealCarrier`; the owning `Inode`
    /// exposes it through `fcntl_seals()` only when this data was attached as the
    /// inode's seal carrier (a sealable memfd). # D42
    pub(super) seals: AtomicU32,
}

/// memfd seal-store carrier (`16§2`, Linux `SHMEM_I(inode)->seals`): the tmpfs
/// inode-info owns the seal word, and the generic `Inode` reads it through this
/// trait. # C: O(1)
impl vfs::SealCarrier for TmpfsFileData {
    fn seal_word(&self) -> &AtomicU32 { &self.seals }
}

/// Build a regular tmpfs/memfd file inode. `sealable` enables the memfd seal
/// word (`Inode::fcntl_seals`); `perm` is the caller-supplied permission bits
/// (Linux honours the `open`/`creat` mode, masked by umask at the syscall
/// layer); `sb` owns the inode (`fsid` derives from `s_dev`). # C: O(1)
pub(super) fn make_tmpfs_file_inode(sealable: bool, perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>, acct: Arc<TmpfsSb>) -> InodeRef {
    let ino = acct.alloc_ino();
    let sb2 = sb.clone();
    let inode = iget_or_build(&sb, ino, move || {
        let data = Arc::new(TmpfsFileData {
            self_ref: Spinlock::new(Weak::new()),
            pages: Spinlock::new(BTreeMap::new()),
            len:   AtomicU64::new(0),
            acct,
            owner: Spinlock::new(QuotaOwner::new(uid, gid)),
            inode: Spinlock::new(Weak::new()),
            seals: AtomicU32::new(0),
        });
        *data.self_ref.lock() = Arc::downgrade(&data);
        super::reclaim::install();
        super::reclaim::register(&data);
        let mapping: Arc<dyn AddressSpaceOps> = data.clone();
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Regular, perm),
            Arc::new(TmpfsFileInodeOps), Arc::new(TmpfsFileOps))
            .owner(uid, gid)
            .btime(super::birth_time())
            .fsid(fsid_of(&sb2))
            .mapping(mapping)
            .xattrs(vfs::SimpleXattrs::new())
            .private(data.clone());
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        if sealable { b = b.seal_carrier(data); }
        b.build()
    });
    // The body reaches back to its inode so a block charge can keep `i_blocks`
    // equal to the charge, which is what a later chown moves.
    if let Some(d) = inode.private::<TmpfsFileData>() { *d.inode.lock() = Arc::downgrade(&inode); }
    inode
}

/// Anonymous tmpfs file body (memfd / coredump), no owning SuperBlock. # C: O(1)
pub fn tmpfs_anon_file() -> InodeRef { make_tmpfs_file_inode(false, 0o644, 0, 0, Weak::new(), TmpfsSb::unlimited()) }
/// A sealable memfd file (`memfd_create(MFD_ALLOW_SEALING)`). # C: O(1)
pub fn tmpfs_sealable_file() -> InodeRef { make_tmpfs_file_inode(true, 0o644, 0, 0, Weak::new(), TmpfsSb::unlimited()) }

impl TmpfsFileData {
    /// Charge one data page to the mount and to this body's owner, and record
    /// it in `i_blocks`. `ENOSPC` at the mount ceiling, `EDQUOT` at the
    /// owner's — both refused before the frame exists. # C: O(MAXQUOTAS log N)
    pub(super) fn acct_one_block(&self) -> KResult<()> {
        quota::acct_blocks(&self.acct, *self.owner.lock(), 1)?;
        self.note_blocks(1, true);
        Ok(())
    }
    /// Return one charged-but-unused data page. # C: O(MAXQUOTAS log N)
    pub(super) fn unacct_one_block(&self) { self.unacct_blocks(1); }
    /// Return `pages` data pages to the mount and to this body's owner.
    /// # C: O(MAXQUOTAS log N)
    pub(super) fn unacct_blocks(&self, pages: u64) {
        if pages == 0 { return; }
        quota::unacct_blocks(&self.acct, *self.owner.lock(), pages);
        self.note_blocks(pages, false);
    }
    /// Keep `i_blocks` equal to the charged page count, so `stat(2)` reports
    /// what the owner pays for and a chown transfers that same amount.
    /// # C: O(1)
    fn note_blocks(&self, pages: u64, add: bool) {
        let Some(inode) = self.inode.lock().upgrade() else { return; };
        let delta = quota::blocks_of(pages);
        let cur = inode.blocks();
        inode.set_blocks(if add { cur.saturating_add(delta) } else { cur.saturating_sub(delta) });
    }
    /// Re-point this body's charged owner after a transfer has moved the
    /// charge. The charge and the record of who holds it move together, so a
    /// later release cannot credit the previous owner. # C: O(1)
    pub(super) fn set_charged_owner(&self, owner: QuotaOwner) { *self.owner.lock() = owner; }
    /// Copy out cache bytes from `off` (sparse holes read as zero, tail past
    /// `len` short-reads). # C: O(buf.len)
    pub(super) fn read_bytes(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let len = self.len.load(Ordering::Acquire);
        if off >= len { return Ok(0); }
        let n = buf.len().min((len - off) as usize);
        let mut done = 0usize;
        while done < n {
            let cur   = off as usize + done;
            let idx   = (cur / PG) as u64;
            let pgoff = cur % PG;
            let chunk = (PG - pgoff).min(n - done);
            let migrating = {
                let mut g = self.pages.lock();
                match g.get(&idx).copied() {
                    Some(ShmemPage::Migrating { token, .. }) => Some(token),
                    Some(_) => {
                        let pa = ensure_page(&mut g, idx, self)?;
                    let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
                    // SAFETY: pa is an inode-owned frame; HHDM mirror readable;
                    // [pgoff..pgoff+chunk] is within the page granule.
                    unsafe {
                        let src = base.add(pgoff) as *const u8;
                        core::ptr::copy_nonoverlapping(src, buf[done..].as_mut_ptr(), chunk);
                    }
                        None
                    }
                    None => { buf[done..done + chunk].fill(0); None }
                }
            };
            if let Some(token) = migrating {
                super::migration::wait_and_restart(token);
                continue;
            }
            done += chunk;
        }
        Ok(n)
    }

    /// Write `src` at `off`, extending `len`. (Seal checks are done by the
    /// caller, which holds `&Inode`.) # C: O(src.len)
    fn write_bytes(&self, off: u64, src: &[u8]) -> KResult<usize> {
        let end = off + src.len() as u64;
        let mut done = 0usize;
        while done < src.len() {
            let cur   = off as usize + done;
            let idx   = (cur / PG) as u64;
            let pgoff = cur % PG;
            let chunk = (PG - pgoff).min(src.len() - done);
            let migrating = {
                let mut g = self.pages.lock();
                if let Some(ShmemPage::Migrating { token, .. }) = g.get(&idx).copied() {
                    Some(token)
                } else {
                    let pa = ensure_page(&mut g, idx, self)?;
                    let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
            // SAFETY: pa is an inode-owned frame; HHDM mirror writable;
            // [pgoff..pgoff+chunk] within the page granule; non-overlapping.
            unsafe {
                let dst = base.add(pgoff);
                core::ptr::copy_nonoverlapping(src[done..].as_ptr(), dst, chunk);
            }
                    None
                }
            };
            if let Some(token) = migrating {
                super::migration::wait_and_restart(token);
                continue;
            }
            done += chunk;
        }
        if end > self.len.load(Ordering::Acquire) { self.len.store(end, Ordering::Release); }
        Ok(src.len())
    }

    /// Set the logical length to `len`, freeing pages past it. # C: O(dropped)
    fn do_truncate(&self, len: u64) -> KResult<()> {
        let old = self.len.load(Ordering::Acquire);
        let mut g = self.pages.lock();
        if len < old {
            // Truncate must be all-or-retry with respect to a pageout token:
            // never remove earlier pages then discover that a later one is
            // frozen, because that would make retry observably partial.
            if let Some(token) = g.values().find_map(|page| match *page {
                ShmemPage::Migrating { token, .. } => Some(token), _ => None,
            }) {
                drop(g);
                super::migration::wait_and_restart(token);
                return self.do_truncate(len);
            }
            // Drop whole pages past the new end; zero the tail of a partial
            // last page so a later grow re-reads zeros (Linux truncate).
            let keep = (len as usize).div_ceil(PG) as u64;
            let stale: Vec<u64> = g.range(keep..).map(|(&k, _)| k).collect();
            let mut freed = 0u64;
            for idx in stale {
                if let Some(page) = g.remove(&idx) {
                    match page {
                        ShmemPage::Resident { pa, cgid } => {
                            // SAFETY: inode-owned frame past the truncation point; dec
                            // frees it when no mapper holds a reference.
                            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
                            vfs::memory_accounting::account_shmem_remove(1);
                        }
                        ShmemPage::Swapped { entry, .. } => { let _ = pmm::swap::free_page(entry); }
                        ShmemPage::Migrating { .. } => unreachable!("truncate preflight excludes migrating shmem pages"),
                    }
                    freed += 1;
                }
            }
            self.unacct_blocks(freed); // return reclaimed blocks to the mount and the owner
            let tail = len as usize % PG;
            if tail != 0 {
                let tail_idx = len / PG as u64;
                if g.contains_key(&tail_idx) {
                    let pa = ensure_page(&mut g, tail_idx, self)?;
                    let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
                    // SAFETY: inode-owned frame; zero [tail..PG] within the granule.
                    hal::zerotrap::trap(unsafe { base.add(tail) } as *const u8, PG - tail);
                    // SAFETY: base is page-aligned and tail..PG stays within the frame.
                    unsafe { core::ptr::write_bytes(base.add(tail), 0, PG - tail); }
                }
            }
        }
        self.len.store(len, Ordering::Release);
        Ok(())
    }

    /// Ensure backing for `[off, off+len)`, optionally zeroing + extending.
    /// (Seal checks are the caller's.) # C: O(len/PG)
    pub(super) fn do_fallocate(&self, off: u64, len: u64, keep_size: bool, zero_range: bool) -> KResult<()> {
        let end = off.checked_add(len).ok_or(VfsError::Einval)?;
        let old = self.len.load(Ordering::Acquire);
        let mut pos = off;
        while pos < end {
            let idx = pos / PG as u64;
            let pgoff = (pos as usize) % PG;
            let chunk = (PG - pgoff).min((end - pos) as usize);
            let migrating = {
                let mut g = self.pages.lock();
                if let Some(ShmemPage::Migrating { token, .. }) = g.get(&idx).copied() {
                    Some(token)
                } else {
                    let pa = ensure_page(&mut g, idx, self)?;
                    if zero_range {
                        let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
                // SAFETY: pa is an inode-owned frame; range lies within page.
                hal::zerotrap::trap(unsafe { base.add(pgoff) } as *const u8, chunk);
                // SAFETY: pgoff and chunk were computed to stay within this frame.
                        unsafe { core::ptr::write_bytes(base.add(pgoff), 0, chunk); }
                    }
                    None
                }
            };
            if let Some(token) = migrating {
                super::migration::wait_and_restart(token);
                continue;
            }
            pos += chunk as u64;
        }
        if !keep_size && end > old {
            self.len.store(end, Ordering::Release);
        }
        Ok(())
    }
}

impl Drop for TmpfsFileData {
    /// Release the inode's reference on every backing frame. No mapping can
    /// outlive the inode (a `MAP_SHARED` VMA pins it through the
    /// `FileBacking` Arc), so each frame is at refcount 1 here → freed.
    /// # C: O(N_pages)
    fn drop(&mut self) {
        let g = self.pages.lock();
        for (_idx, page) in g.iter() {
            match *page {
                ShmemPage::Resident { pa, cgid } => {
                    // SAFETY: this is the inode's own reference on `pa`, dropped
                    // exactly once here in `drop`; no mapping can outlive the
                    // inode, since a MAP_SHARED VMA pins it through the
                    // `FileBacking` Arc, so no stale PTE names the frame.
                    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                    cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
                }
                ShmemPage::Swapped { entry, .. } => { let _ = pmm::swap::free_page(entry); }
                ShmemPage::Migrating { token: _token, .. } => {
                    #[cfg(feature = "debug-zram-lifecycle")]
                    super::lifetime::trace_migration(b"drop-live", self, *_idx, _token);
                    unreachable!("tmpfs owner dropped during pageout transaction")
                }
            }
        }
        let resident = g.values().filter(|page| page.resident_pa().is_some()).count() as u64;
        vfs::memory_accounting::account_shmem_remove(resident);
        // The inode is already gone here, so the pages go back to the owner
        // this body recorded when they were charged, not to a live inode's.
        quota::unacct_blocks(&self.acct, *self.owner.lock(), g.len() as u64);
    }
}

/// `i_op` for a regular tmpfs file: truncate/fallocate consult the inode's
/// memfd seal word before mutating the body. # C: O(1)
struct TmpfsFileInodeOps;
impl InodeOps for TmpfsFileInodeOps {
    /// `shmem_fileattr_get` — the `chattr` word for this inode. # C: O(1)
    fn fileattr_get(&self, inode: &Inode) -> KResult<vfs::FileAttr> {
        super::fileattr::tmpfs_fileattr_get(inode)
    }
    /// `shmem_fileattr_set`. # C: O(1)
    fn fileattr_set(&self, inode: &Inode, fa: &vfs::FileAttr) -> KResult<()> {
        super::fileattr::tmpfs_fileattr_set(inode, fa)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = inode.private::<TmpfsFileData>().ok_or(VfsError::Einval)?;
        let s = inode.fcntl_seals().map_or(0, |a| a.load(Ordering::Acquire));
        let old = d.len.load(Ordering::Acquire);
        if len < old && s & F_SEAL_SHRINK != 0 { return Err(VfsError::Eperm); }
        if len > old && s & F_SEAL_GROW   != 0 { return Err(VfsError::Eperm); }
        d.do_truncate(len)?;
        inode.set_size(len);
        Ok(())
    }
    /// `shmem_fallocate` — body in `falloc.rs`. # C: O(len/PG)
    fn fallocate(&self, inode: &Inode, mode: u32, off: u64, len: u64) -> KResult<()> {
        super::falloc::shmem_fallocate(inode, mode, off, len)
    }
    /// `shmem_setattr`: the generic attribute apply, which transfers this
    /// inode's charged usage to the new owner when the owner changes, followed
    /// by re-pointing the body at the owner that now holds the charge. Without
    /// the second half the pages would be credited back to the previous owner
    /// when the body is finally released. # C: O(MAXQUOTAS log N)
    fn setattr(&self, inode: &Inode, idmap: &vfs::Idmap, ia: &vfs::Iattr) -> KResult<()> {
        vfs::simple_setattr(inode, idmap, ia)?;
        if let Some(d) = inode.private::<TmpfsFileData>() { d.set_charged_owner(QuotaOwner::of(inode)); }
        Ok(())
    }
}

/// `i_fop` for a regular tmpfs file. # C: O(1)
struct TmpfsFileOps;
impl FileOps for TmpfsFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<TmpfsFileData>().ok_or(VfsError::Einval)?;
        d.read_bytes(off, buf)
    }
    fn write(&self, inode: &Inode, off: u64, src: &[u8]) -> KResult<usize> {
        let d = inode.private::<TmpfsFileData>().ok_or(VfsError::Einval)?;
        let s = inode.fcntl_seals().map_or(0, |a| a.load(Ordering::Acquire));
        if s & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 { return Err(VfsError::Eperm); }
        let end = off + src.len() as u64;
        if end > d.len.load(Ordering::Acquire) && s & F_SEAL_GROW != 0 { return Err(VfsError::Eperm); }
        let n = d.write_bytes(off, src)?;
        inode.set_size(d.len.load(Ordering::Acquire));
        Ok(n)
    }

    /// tmpfs accepts `O_DIRECT` (sets `FMODE_CAN_ODIRECT`) because its pages
    /// ARE the store — there is no cache behind which data could be
    /// buffered, so "bypass the page cache" is already true. # C: O(1)
    fn can_odirect(&self, _inode: &Inode) -> bool { true }
}
