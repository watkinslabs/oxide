use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{AddressSpaceOps, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, mk_mode};
use vfs::superblock::SuperBlock;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::accounting::TmpfsSb;
use super::flags::{F_SEAL_FUTURE_WRITE, F_SEAL_GROW, F_SEAL_SHRINK, F_SEAL_WRITE};
use super::inode::{fsid_of, iget_or_build, next_ino};
use super::limits::PG;

/// Resolve the allocating task's memcg once, at the shmem page-allocation
/// boundary.  A pre-scheduler kernel context is charged to the root memcg,
/// matching Linux's root allocation context rather than inventing an owner
/// later during reclaim or teardown. # C: O(log n)
fn allocating_memcg() -> u64 {
    sched::current().map(|t| cgroup::cgroup_of(t.tid as u64)).unwrap_or_else(cgroup::kernel_context_memcg)
}

/// One published shmem page.  The cgid is immutable page ownership: task
/// migration, inode sharing, and cgroup removal never retarget the charge.
/// One canonical shmem page-index entry.  A swap entry remains owned by this
/// inode at the same index, rather than becoming an anonymous PTE truth.
/// This is the essential `shmem_inode_info` distinction: a hole reads zero,
/// a resident entry names its frame, and a swapped entry names durable data.
#[derive(Clone, Copy)]
pub(super) enum ShmemPage {
    Resident { pa: u64, cgid: u64 },
    Swapped { entry: hal::pt_walker::SwapEntry, cgid: u64 },
    /// Canonical in-flight shmem pageout state.  The physical frame remains
    /// owned by this inode, but no new mapper may acquire it until the token
    /// resolves to Resident (rollback) or Swapped (commit).
    Migrating { pa: u64, cgid: u64, token: hal::pt_walker::MigrationEntry },
}

impl ShmemPage {
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
    /// `page_idx -> frame pa`. Sparse: a hole reads as zero.
    pub(super) pages: Spinlock<BTreeMap<u64, ShmemPage>, TaskListClass>,
    /// Logical size (Linux `i_size`); may exceed the populated pages. Kept in
    /// sync with the owning inode's `i_size` by the file/inode ops.
    len:  AtomicU64,
    /// Owning mount's space accounting (block charge/uncharge). # D33
    acct: Arc<TmpfsSb>,
    /// memfd `F_*_SEALS` word (Linux `shmem_inode_info.seals`). Lives HERE in the
    /// per-fs inode-info, reached via `vfs::SealCarrier`; the owning `Inode`
    /// exposes it through `fcntl_seals()` only when this data was attached as the
    /// inode's seal carrier (a sealable memfd). # D42
    seals: AtomicU32,
}

/// memfd seal-store carrier (`16§2`, Linux `SHMEM_I(inode)->seals`): the tmpfs
/// inode-info owns the seal word, and the generic `Inode` reads it through this
/// trait. # C: O(1)
impl vfs::SealCarrier for TmpfsFileData {
    fn seal_word(&self) -> &AtomicU32 { &self.seals }
}

/// Frame for `idx`, allocating + zeroing on first touch and charging one block
/// against the mount's accounting (`ENOSPC` → `None` at the limit). The frame
/// holds the inode's single object reference (refcount 1, mapcount 0).
/// # C: O(log N_pages)
pub(super) fn ensure_page(g: &mut BTreeMap<u64, ShmemPage>, idx: u64, acct: &TmpfsSb) -> KResult<u64> {
    if let Some(page) = g.get(&idx).copied() {
        if let Some(pa) = page.resident_pa() { return Ok(pa); }
        let ShmemPage::Swapped { entry, cgid } = page else { return Err(VfsError::Eagain); };
        // A swapped shmem page retains its inode index and swap charge.  A
        // refault allocates a new object frame, restores bytes, and only then
        // consumes the old swap entry; failed reload leaves the index intact.
        if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64) {
            return Err(VfsError::Enomem);
        }
        let Some(pa) = pmm::setup::alloc_object_frame() else {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Enomem);
        };
        let Some(ptr) = pmm::setup::frame_ptr(pa) else {
            // SAFETY: this unpublished object frame has only its allocation ref.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Enomem);
        };
        // SAFETY: `ptr` spans the newly allocated page and no PTE can name it.
        let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, PG) };
        if pmm::swap::load_page(entry, bytes).is_err() {
            // SAFETY: failed I/O left the frame private to this construction.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Eio);
        }
        pmm::setup::classify_shmem_page(pa, cgid);
        if pmm::setup::admit_shmem_lru(pa).is_err() {
            // The old swap entry remains authoritative until this admission is
            // complete; don't publish a resident page outside reclaim state.
            // SAFETY: no PTE owns this failed refault frame.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            return Err(VfsError::Eio);
        }
        g.insert(idx, ShmemPage::Resident { pa, cgid });
        vfs::memory_accounting::account_shmem_publish(1);
        // Data is present in the new page-index entry before the swap slot is
        // released. `free_page` also removes the matching swap memcg charge.
        let _ = pmm::swap::free_page(entry);
        return Ok(pa);
    }
    if !acct.charge_block() { return Err(VfsError::Enospc); }
    let cgid = allocating_memcg();
    if !cgroup::try_charge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64) {
        acct.free_blocks(1);
        return Err(VfsError::Enomem);
    }
    let pa = match pmm::setup::alloc_object_frame() {
        Some(p) => p,
        None => {
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            acct.free_blocks(1);
            return Err(VfsError::Enomem);
        }
    };
    let ptr = match pmm::setup::frame_ptr(pa) {
        Some(p) => p,
        None => {
            // SAFETY: allocation published no page-index entry, so this is the
            // sole object reference and the failed construction rolls back fully.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
            cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
            acct.free_blocks(1);
            return Err(VfsError::Enomem);
        }
    };
    // SAFETY: pa is a freshly-allocated PMM frame; PG is the page granule.
    hal::zerotrap::trap((ptr) as *const u8, (PG) as usize);
    // SAFETY: ptr names the full freshly-allocated frame, and PG is its size.
    unsafe { core::ptr::write_bytes(ptr, 0, PG); }
    pmm::setup::classify_shmem_page(pa, cgid);
    pmm::kassert!(pmm::setup::admit_shmem_lru(pa).is_ok(), "shmem lru admission invariant");
    g.insert(idx, ShmemPage::Resident { pa, cgid });
    vfs::memory_accounting::account_shmem_publish(1);
    Ok(pa)
}

/// Build a regular tmpfs/memfd file inode. `sealable` enables the memfd seal
/// word (`Inode::fcntl_seals`); `perm` is the caller-supplied permission bits
/// (Linux honours the `open`/`creat` mode, masked by umask at the syscall
/// layer); `sb` owns the inode (`fsid` derives from `s_dev`). # C: O(1)
pub(super) fn make_tmpfs_file_inode(sealable: bool, perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>, acct: Arc<TmpfsSb>) -> InodeRef {
    let ino = next_ino();
    let sb2 = sb.clone();
    iget_or_build(&sb, ino, move || {
        let data = Arc::new(TmpfsFileData {
            pages: Spinlock::new(BTreeMap::new()),
            len:   AtomicU64::new(0),
            acct,
            seals: AtomicU32::new(0),
        });
        super::reclaim::install();
        super::reclaim::register(&data);
        let mapping: Arc<dyn AddressSpaceOps> = data.clone();
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Regular, perm),
            Arc::new(TmpfsFileInodeOps), Arc::new(TmpfsFileOps))
            .owner(uid, gid)
            .fsid(fsid_of(&sb2))
            .mapping(mapping)
            .xattrs(vfs::SimpleXattrs::new())
            .private(data.clone());
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        if sealable { b = b.seal_carrier(data); }
        b.build()
    })
}

/// Anonymous tmpfs file body (memfd / coredump), no owning SuperBlock. # C: O(1)
pub fn tmpfs_anon_file() -> InodeRef { make_tmpfs_file_inode(false, 0o644, 0, 0, Weak::new(), TmpfsSb::unlimited()) }
/// A sealable memfd file (`memfd_create(MFD_ALLOW_SEALING)`). # C: O(1)
pub fn tmpfs_sealable_file() -> InodeRef { make_tmpfs_file_inode(true, 0o644, 0, 0, Weak::new(), TmpfsSb::unlimited()) }

impl TmpfsFileData {
    /// Copy out cache bytes from `off` (sparse holes read as zero, tail past
    /// `len` short-reads). # C: O(buf.len)
    fn read_bytes(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
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
                        let pa = ensure_page(&mut g, idx, &self.acct)?;
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
                    let pa = ensure_page(&mut g, idx, &self.acct)?;
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
            self.acct.free_blocks(freed); // return reclaimed blocks to f_bfree
            let tail = len as usize % PG;
            if tail != 0 {
                let tail_idx = len / PG as u64;
                if g.contains_key(&tail_idx) {
                    let pa = ensure_page(&mut g, tail_idx, &self.acct)?;
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
    fn do_fallocate(&self, off: u64, len: u64, keep_size: bool, zero_range: bool) -> KResult<()> {
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
                    let pa = ensure_page(&mut g, idx, &self.acct)?;
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
                    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                    cgroup::uncharge_memory(cgid, cgroup::MemoryKind::Shmem, PG as u64);
                }
                ShmemPage::Swapped { entry, .. } => { let _ = pmm::swap::free_page(entry); }
                ShmemPage::Migrating { .. } => unreachable!("tmpfs owner dropped during pageout transaction"),
            }
        }
        let resident = g.values().filter(|page| page.resident_pa().is_some()).count() as u64;
        vfs::memory_accounting::account_shmem_remove(resident);
        self.acct.free_blocks(g.len() as u64); // return this inode's blocks to f_bfree
    }
}

/// `i_op` for a regular tmpfs file: truncate/fallocate consult the inode's
/// memfd seal word before mutating the body. # C: O(1)
struct TmpfsFileInodeOps;
impl InodeOps for TmpfsFileInodeOps {
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
    fn fallocate(&self, inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool, punch: bool) -> KResult<()> {
        let d = inode.private::<TmpfsFileData>().ok_or(VfsError::Einval)?;
        let s = inode.fcntl_seals().map_or(0, |a| a.load(Ordering::Acquire));
        let end = off.checked_add(len).ok_or(VfsError::Einval)?;
        let old = d.len.load(Ordering::Acquire);
        if !keep_size && end > old && s & F_SEAL_GROW != 0 { return Err(VfsError::Eperm); }
        if (zero_range || punch) && s & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 { return Err(VfsError::Eperm); }
        if punch {
            // PUNCH_HOLE on RAM-backed data: zero the range, size unchanged
            // (satisfies the read-as-zeros contract for the deallocated range).
            d.do_fallocate(off, len, /*keep_size*/ true, /*zero_range*/ true)?;
        } else {
            d.do_fallocate(off, len, keep_size, zero_range)?;
        }
        inode.set_size(d.len.load(Ordering::Acquire));
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
}

/// The tmpfs inode's `address_space` (Linux shmem mapping). Persistent,
/// frame-backed, per-inode, sparse (hole = zero) — every mapper of this
/// inode shares THESE frames, so `MAP_SHARED` writes propagate to
/// `read`/`write` and to all peers, and `fork` keeps the page shared
/// (no COW-split) because the backing object, not the PTE, owns the frame.
impl AddressSpaceOps for TmpfsFileData {
    /// MAP_SHARED backing: the inode's persistent frame for the page at file
    /// offset `off` (page-aligned), allocating on first touch. # C: O(log N_pages)
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

    /// Read-fault / MAP_PRIVATE fill: copy cache bytes (sparse holes read as
    /// zero, tail past `i_size` short-reads). # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> KResult<usize> { self.read_bytes(off, dst) }

    /// shmem pages ARE the store — nothing to flush. # C: O(1)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// MAP_SHARED MADV_PAGEOUT moves only the requested inode indices through
    /// the canonical shmem migration transaction. # C: O(pages in range)
    fn madvise_pageout(&self, off: u64, len: u64) -> Option<KResult<usize>> {
        Some(super::reclaim::pageout_range(self, off, len))
    }

    /// `mincore(2)` must not fault in tmpfs holes; only existing shmem frames
    /// are resident. # C: O(log N_pages)
    fn mincore_page(&self, off: u64) -> bool {
        self.pages.lock().get(&(off / PG as u64)).is_some_and(|page| page.resident_pa().is_some())
    }

    /// # C: O(1)
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
}

#[cfg(test)]
mod shmem_page_tests {
    use super::{ShmemPage, TmpfsFileData};
    use alloc::collections::BTreeMap;
    use core::sync::atomic::{AtomicU32, AtomicU64};
    use sync::{Spinlock, TaskList};

    #[test]
    fn swapped_index_keeps_immutable_memcg_but_has_no_resident_frame() {
        let cgid = 0x61;
        let resident = ShmemPage::Resident { pa: 0x9000, cgid };
        let entry = hal::pt_walker::SwapEntry::new(1, 7).expect("representable swap entry");
        let swapped = ShmemPage::Swapped { entry, cgid };
        assert_eq!(resident.resident_pa(), Some(0x9000));
        assert_eq!(swapped.resident_pa(), None);
        assert_eq!(resident.cgid(), swapped.cgid());
    }

    fn migrating_fixture(pa: u64, cgid: u64) -> (TmpfsFileData, hal::pt_walker::MigrationEntry) {
        let token = vmm::migration_begin(pa).expect("test migration token");
        let mut pages = BTreeMap::new();
        pages.insert(7, ShmemPage::Migrating { pa, cgid, token });
        (TmpfsFileData {
            pages: Spinlock::<BTreeMap<u64, ShmemPage>, TaskList>::new(pages),
            len: AtomicU64::new(0), acct: super::super::accounting::TmpfsSb::unlimited(),
            seals: AtomicU32::new(0),
        }, token)
    }

    fn assert_failed_mapped_pageout_restores_resident(force: fn(), invoke_failure: impl FnOnce(hal::pt_walker::MigrationEntry) -> bool) {
        let (data, token) = migrating_fixture(0x70_000, 0x29);
        force();
        assert!(!invoke_failure(token), "test hook must force this transaction failure");
        super::super::reclaim::rollback_mapped_for_test(&data, 7, 0x70_000, 0x29, token);
        assert!(matches!(data.pages.lock().get(&7), Some(ShmemPage::Resident { pa: 0x70_000, cgid: 0x29 })));
        assert!(!vmm::migration_pending_then(token, || {}), "rollback must retire the migration token");
        // Synthetic state owns neither a PMM frame nor a published shmem count.
        core::mem::forget(data);
    }

    #[test]
    fn forced_marker_and_store_failure_restore_the_same_resident_index_and_token() {
        assert_failed_mapped_pageout_restores_resident(
            super::super::reclaim::fail_next_marker_for_test,
            super::super::reclaim::attach_marker_for_test,
        );
        assert_failed_mapped_pageout_restores_resident(
            super::super::reclaim::fail_next_store_for_test,
            |token| super::super::reclaim::store_page_for_test(&[0; 1], token.token()).is_some(),
        );
    }
}
