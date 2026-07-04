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

pub struct TmpfsFileData {
    /// `page_idx -> frame pa`. Sparse: a hole reads as zero.
    pages: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
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
fn ensure_page(g: &mut BTreeMap<u64, u64>, idx: u64, acct: &TmpfsSb) -> Option<u64> {
    if let Some(&pa) = g.get(&idx) { return Some(pa); }
    if !acct.charge_block() { return None; } // f_bfree exhausted → ENOSPC
    let pa = match pmm::setup::alloc_object_frame() { Some(p) => p, None => { acct.free_blocks(1); return None; } };
    let ptr = match pmm::setup::frame_ptr(pa) { Some(p) => p, None => { acct.free_blocks(1); return None; } };
    // SAFETY: pa is a freshly-allocated PMM frame; PG is the page granule.
    hal::zerotrap::trap((ptr) as *const u8, (PG) as usize);
    // SAFETY: ptr names the full freshly-allocated frame, and PG is its size.
    unsafe { core::ptr::write_bytes(ptr, 0, PG); }
    g.insert(idx, pa);
    Some(pa)
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
        let g = self.pages.lock();
        let mut done = 0usize;
        while done < n {
            let cur   = off as usize + done;
            let idx   = (cur / PG) as u64;
            let pgoff = cur % PG;
            let chunk = (PG - pgoff).min(n - done);
            match g.get(&idx) {
                Some(&pa) => {
                    let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
                    // SAFETY: pa is an inode-owned frame; HHDM mirror readable;
                    // [pgoff..pgoff+chunk] is within the page granule.
                    unsafe {
                        let src = base.add(pgoff) as *const u8;
                        core::ptr::copy_nonoverlapping(src, buf[done..].as_mut_ptr(), chunk);
                    }
                }
                None => { buf[done..done + chunk].fill(0); } // sparse hole
            }
            done += chunk;
        }
        Ok(n)
    }

    /// Write `src` at `off`, extending `len`. (Seal checks are done by the
    /// caller, which holds `&Inode`.) # C: O(src.len)
    fn write_bytes(&self, off: u64, src: &[u8]) -> KResult<usize> {
        let end = off + src.len() as u64;
        let mut g = self.pages.lock();
        let mut done = 0usize;
        while done < src.len() {
            let cur   = off as usize + done;
            let idx   = (cur / PG) as u64;
            let pgoff = cur % PG;
            let chunk = (PG - pgoff).min(src.len() - done);
            let pa = ensure_page(&mut g, idx, &self.acct).ok_or(VfsError::Enospc)?;
            let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
            // SAFETY: pa is an inode-owned frame; HHDM mirror writable;
            // [pgoff..pgoff+chunk] within the page granule; non-overlapping.
            unsafe {
                let dst = base.add(pgoff);
                core::ptr::copy_nonoverlapping(src[done..].as_ptr(), dst, chunk);
            }
            done += chunk;
        }
        drop(g);
        if end > self.len.load(Ordering::Acquire) { self.len.store(end, Ordering::Release); }
        Ok(src.len())
    }

    /// Set the logical length to `len`, freeing pages past it. # C: O(dropped)
    fn do_truncate(&self, len: u64) -> KResult<()> {
        let old = self.len.load(Ordering::Acquire);
        let mut g = self.pages.lock();
        if len < old {
            // Drop whole pages past the new end; zero the tail of a partial
            // last page so a later grow re-reads zeros (Linux truncate).
            let keep = (len as usize).div_ceil(PG) as u64;
            let stale: Vec<u64> = g.range(keep..).map(|(&k, _)| k).collect();
            let mut freed = 0u64;
            for idx in stale {
                if let Some(pa) = g.remove(&idx) {
                    // SAFETY: inode-owned frame past the truncation point; dec
                    // frees it when no mapper holds a reference.
                    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                    freed += 1;
                }
            }
            self.acct.free_blocks(freed); // return reclaimed blocks to f_bfree
            let tail = len as usize % PG;
            if tail != 0 {
                if let Some(&pa) = g.get(&((len / PG as u64))) {
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
        let mut g = self.pages.lock();
        let mut pos = off;
        while pos < end {
            let idx = pos / PG as u64;
            let pgoff = (pos as usize) % PG;
            let chunk = (PG - pgoff).min((end - pos) as usize);
            let pa = ensure_page(&mut g, idx, &self.acct).ok_or(VfsError::Enospc)?;
            if zero_range {
                let base = pmm::setup::frame_ptr(pa).ok_or(VfsError::Eio)?;
                // SAFETY: pa is an inode-owned frame; range lies within page.
                hal::zerotrap::trap(unsafe { base.add(pgoff) } as *const u8, chunk);
                // SAFETY: pgoff and chunk were computed to stay within this frame.
                unsafe { core::ptr::write_bytes(base.add(pgoff), 0, chunk); }
            }
            pos += chunk as u64;
        }
        drop(g);
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
        for (_idx, &pa) in g.iter() {
            // SAFETY: pa was alloc_object_frame'd for this inode (object ref
            // held since); the OBJECT dec releases refcount WITHOUT touching
            // mapcount — this drop is not a PTE teardown (the plain
            // dec_and_maybe_free_frame here underflowed mapcount 0→-1 on
            // every tmpfs inode drop, tripping [COW-LEAK] free-while-mapped).
            // SAFETY: this frame still belongs to the inode's object reference.
            unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
        }
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
    fn fallocate(&self, inode: &Inode, off: u64, len: u64, keep_size: bool, zero_range: bool) -> KResult<()> {
        let d = inode.private::<TmpfsFileData>().ok_or(VfsError::Einval)?;
        let s = inode.fcntl_seals().map_or(0, |a| a.load(Ordering::Acquire));
        let end = off.checked_add(len).ok_or(VfsError::Einval)?;
        let old = d.len.load(Ordering::Acquire);
        if !keep_size && end > old && s & F_SEAL_GROW != 0 { return Err(VfsError::Eperm); }
        if zero_range && s & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 { return Err(VfsError::Eperm); }
        d.do_fallocate(off, len, keep_size, zero_range)?;
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
    fn shared_frame(&self, off: u64) -> Option<u64> {
        let mut g = self.pages.lock();
        ensure_page(&mut g, off / PG as u64, &self.acct)
    }

    /// Read-fault / MAP_PRIVATE fill: copy cache bytes (sparse holes read as
    /// zero, tail past `i_size` short-reads). # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        self.read_bytes(off, dst).map_err(|_| ())
    }

    /// shmem pages ARE the store — nothing to flush. # C: O(1)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// # C: O(1)
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
}
