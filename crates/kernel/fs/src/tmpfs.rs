// Minimal in-memory filesystem per docs/16. v1 stand-in for a
// real tmpfs:
//   - flat path → TmpfsFileInode map (no directory structure)
//   - each inode wraps a `Spinlock<Vec<u8>>` body
//   - read/write extend the body; truncate on first write per
//     O_TRUNC behaviour (O_TRUNC handling rides VFS open-flag
//     work)
//   - `open(path, O_CREAT)` lazily registers an empty file
//
// `/tmp/*` paths fall through to this when not found in devfs/
// procfs. v1 uses a global registry; per-mount-tree isolation
// rides the multi-mount work in docs/16.





use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;

use sync::{Spinlock, Inode as InodeClass, TaskList as TaskListClass};
use vfs::{AddressSpaceOps, Devt, FileType, Ino, Inode, InodeOps, InodeRef, KResult, VfsError};
use vfs::{DirContext, FileOps, InodeBuilder, default_inode_ops, make_device_node_inode, mk_mode, CreateCtx};
use vfs::superblock::SuperBlock;

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x4000_0000);

/// memfd file-seal bits (`fcntl.h`).
pub const F_SEAL_SEAL:   u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW:   u32 = 0x0004;
pub const F_SEAL_WRITE:  u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;

const PG: usize = 4096;
/// TMPFS_MAGIC (linux/magic.h) — statfs `f_type`.
const TMPFS_MAGIC: u64 = 0x0102_1994;
/// Fallback `fsid` for an anonymous inode (memfd / coredump) with no owning
/// SuperBlock; tree inodes derive `fsid` from `i_sb().s_dev`.
const TMPFS_FSID: u64 = 0x0102_1994;
/// Root-inode number of every instance (distinct `s_dev` keeps `(dev,ino)`
/// unique across mounts).
const ROOT_INO: Ino = 2;

const S_IFMT:  u16 = 0xF000;
const S_IFCHR: u16 = 0x2000;
const S_IFBLK: u16 = 0x6000;
const S_IFIFO: u16 = 0x1000;
const S_IFSOCK: u16 = 0xC000;

/// `fsid` from an inode's owning SB, else the tmpfs fallback. # C: O(1)
fn fsid_of(sb: &Weak<SuperBlock>) -> u64 {
    sb.upgrade().map(|s| s.s_dev).unwrap_or(TMPFS_FSID)
}

/// Per-instance tmpfs space accounting (Linux `shmem_sb_info`): block + inode
/// limits and live usage, so `statfs(2)`/`df` report real `f_blocks`/`f_bfree`/
/// `f_files`/`f_ffree` and `create`/`write`/`mkdir` fail `ENOSPC` at the limit
/// (D33). Blocks are counted in `PG` (4 KiB) units, matching `f_bsize`. Shared
/// by every node of one mount (cloned `Arc`); anonymous memfd/coredump files
/// use [`TmpfsSb::unlimited`] so they neither hit a limit nor skew any mount.
pub struct TmpfsSb {
    max_blocks:  u64,
    max_inodes:  u64,
    used_blocks: AtomicU64,
    used_inodes: AtomicU64,
}

impl TmpfsSb {
    /// A bounded instance (`max_blocks` pages, `max_inodes` inodes). # C: O(1)
    fn new(max_blocks: u64, max_inodes: u64) -> Arc<Self> {
        Arc::new(Self { max_blocks, max_inodes,
            used_blocks: AtomicU64::new(0), used_inodes: AtomicU64::new(0) })
    }
    /// Effectively-unbounded accounting (memfd/anon/coredump, hosted tests).
    /// # C: O(1)
    pub fn unlimited() -> Arc<Self> { Self::new(u64::MAX, u64::MAX) }
    /// Linux tmpfs default: half of physical RAM for blocks, and one inode per
    /// page of half-RAM, falling back to a large bound when the PMM is absent
    /// (hosted tests). # C: O(1)
    fn default_limits() -> Arc<Self> {
        let total_pages = pmm::setup::pmm_static()
            .map(|p| p.free_pages() + p.allocated_pages())
            .filter(|&t| t != 0)
            .unwrap_or(1 << 30);
        let half = total_pages / 2;
        Self::new(half, half)
    }
    /// Reserve one block; `false` (caller → `ENOSPC`) at the limit. # C: O(1)
    fn charge_block(&self) -> bool {
        let mut cur = self.used_blocks.load(Ordering::Relaxed);
        loop {
            if cur >= self.max_blocks { return false; }
            match self.used_blocks.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }
    /// Release `n` blocks. # C: O(1)
    fn free_blocks(&self, n: u64) { if n != 0 { self.used_blocks.fetch_sub(n, Ordering::Relaxed); } }
    /// Reserve one inode; `false` (caller → `ENOSPC`) at the limit. # C: O(1)
    fn charge_inode(&self) -> bool {
        let mut cur = self.used_inodes.load(Ordering::Relaxed);
        loop {
            if cur >= self.max_inodes { return false; }
            match self.used_inodes.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }
    /// Release one inode. # C: O(1)
    fn free_inode(&self) { self.used_inodes.fetch_sub(1, Ordering::Relaxed); }
    /// `statfs(2)` block/inode accounting subset (Linux `shmem_statfs`).
    /// # C: O(1)
    fn statfs(&self) -> vfs::SbStatFs {
        let ub = self.used_blocks.load(Ordering::Relaxed);
        let ui = self.used_inodes.load(Ordering::Relaxed);
        let bfree = self.max_blocks.saturating_sub(ub);
        let ffree = self.max_inodes.saturating_sub(ui);
        vfs::SbStatFs {
            f_type:   TMPFS_MAGIC,
            f_bsize:  PG as u32,
            f_blocks: self.max_blocks,
            f_bfree:  bfree,
            f_bavail: bfree,
            f_files:  self.max_inodes,
            f_ffree:  ffree,
            ..Default::default()
        }
    }
}

/// In-memory file body, Linux-shmem style: data lives in PMM page FRAMES
/// (sparse `page_idx -> pa`), NOT a `Vec<u8>`. This is load-bearing for
/// `MAP_SHARED`: a shared mmap aliases the SAME frames the file's
/// `read`/`write` use, so writes propagate both ways (the prior `Vec<u8>`
/// body forced `read_at` to COPY into a fresh per-fault frame, silently
/// turning every `MAP_SHARED` — e.g. journald's sealed-memfd journals —
/// into a private snapshot). Each frame carries the inode's own refcount
/// reference (alloc=1); shared mappers `inc_ref` on fault and the AS
/// teardown `dec`s, so a frame outlives every mapping until the inode drops.
/// In-memory regular-file body (Linux `i_private`). The `pages` frame set is
/// also the inode's `address_space` (TmpfsFileData impls `AddressSpaceOps`),
/// so a `MAP_SHARED` mmap aliases the SAME frames `read`/`write` use. The memfd
/// seal word lives on the OWNING inode (`Inode::fcntl_seals`), so the ops that
/// hold `&Inode` consult it before mutating.
pub struct TmpfsFileData {
    /// `page_idx -> frame pa`. Sparse: a hole reads as zero.
    pages: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
    /// Logical size (Linux `i_size`); may exceed the populated pages. Kept in
    /// sync with the owning inode's `i_size` by the file/inode ops.
    len:  AtomicU64,
    /// Owning mount's space accounting (block charge/uncharge). # D33
    acct: Arc<TmpfsSb>,
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
    unsafe { core::ptr::write_bytes(ptr, 0, PG); }
    g.insert(idx, pa);
    Some(pa)
}

/// Build a regular tmpfs/memfd file inode. `sealable` enables the memfd seal
/// word (`Inode::fcntl_seals`); `perm` is the caller-supplied permission bits
/// (Linux honours the `open`/`creat` mode, masked by umask at the syscall
/// layer); `sb` owns the inode (`fsid` derives from `s_dev`). # C: O(1)
fn make_tmpfs_file_inode(sealable: bool, perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>, acct: Arc<TmpfsSb>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(TmpfsFileData {
        pages: Spinlock::new(BTreeMap::new()),
        len:   AtomicU64::new(0),
        acct,
    });
    let mapping: Arc<dyn AddressSpaceOps> = data.clone();
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Regular, perm),
        Arc::new(TmpfsFileInodeOps), Arc::new(TmpfsFileOps))
        .owner(uid, gid)
        .fsid(fsid_of(&sb))
        .mapping(mapping)
        .private(data);
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    if sealable { b = b.seals(0); }
    b.build()
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
            // SAFETY: pa was alloc_one_frame'd for this inode (refcount ref
            // held since); dec returns it to the buddy when the count hits 0.
            unsafe { pmm::setup::dec_and_maybe_free_frame(pa); }
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

/// Symlink-type tmpfs inode body (Linux `i_private`) — the target text;
/// `readlink` returns it. Created by `i_op->symlink` (e.g. systemd's `/run`
/// symlinks). The path-walk follows it like any symlink.
pub struct TmpfsSymlinkData { target: Vec<u8> }

/// `i_op` for a tmpfs symlink: `readlink` returns the stored target. # C: O(1)
struct TmpfsSymlinkOps;
impl InodeOps for TmpfsSymlinkOps {
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = inode.private::<TmpfsSymlinkData>().ok_or(VfsError::Einval)?;
        Ok(d.target.clone())
    }
}

/// Build a tmpfs symlink inode pointing at `target`, owned by `sb`. # C: O(1)
fn make_tmpfs_symlink_inode(target: &[u8], uid: u32, gid: u32, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777),
        Arc::new(TmpfsSymlinkOps), vfs::default_file_ops())
        .owner(uid, gid)
        .size(target.len() as u64)
        .fsid(fsid_of(&sb))
        .private(Arc::new(TmpfsSymlinkData { target: target.to_vec() }));
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    b.build()
}

/// `i_fop` whose read/write both error `EIO` (tmpfs socket / special node).
struct TmpfsErrFileOps;
impl FileOps for TmpfsErrFileOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _inode: &Inode, _off: u64, _src: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// F152: socket-type tmpfs inode. bind(AF_UNIX, path) materialises one of
/// these at `path` so stat() returns S_IFSOCK + chmod() flows through normal
/// VFS. All I/O errors — datagram queueing lives in `net`. # C: O(1)
fn make_tmpfs_sock_inode(uid: u32, gid: u32, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Socket, 0o755),
        default_inode_ops(), Arc::new(TmpfsErrFileOps))
        .owner(uid, gid)
        .fsid(fsid_of(&sb));
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    b.build()
}

/// Special tmpfs inode created by mknod(2), mainly FIFO nodes under /run. The
/// mode (`ft` + `perm`) + device number are stamped into the inode — discarding
/// them made systemd's fifo_address_create reject the dm-event FIFO. # C: O(1)
fn make_tmpfs_special_inode(ft: FileType, perm: u16, rdev: u32, uid: u32, gid: u32, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mut b = InodeBuilder::new(ino, mk_mode(ft, perm),
        default_inode_ops(), Arc::new(TmpfsErrFileOps))
        .owner(uid, gid)
        .rdev(rdev)
        .fsid(fsid_of(&sb));
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    b.build()
}

/// Downcast an `InodeRef` to `&TmpfsDirData` (every tmpfs dir carries one).
/// # C: O(1)
fn as_dir(i: &InodeRef) -> Option<&TmpfsDirData> {
    i.private::<TmpfsDirData>()
}

/// Per-instance tmpfs directory state (Linux `i_private`). Its `kids` map IS
/// the directory — resolution is per-component `i_op->lookup`, no whole-path
/// key, no global registry. Every child it creates inherits this dir's `sb`
/// weak, so `fsid` derives from the mount's `s_dev`.
pub struct TmpfsDirData {
    sb:   Spinlock<Weak<SuperBlock>, InodeClass>,
    kids: Spinlock<BTreeMap<String, InodeRef>, InodeClass>,
    /// Owning mount's space accounting (inode charge/uncharge + block
    /// propagation to children). Shared `Arc` across the whole instance. # D33
    acct: Arc<TmpfsSb>,
}

impl TmpfsDirData {
    /// This dir's owning-SB weak (handed to every child). # C: O(1)
    fn sb_weak(&self) -> Weak<SuperBlock> { self.sb.lock().clone() }
    /// Stamp the owning SB (`TmpfsFs::set_sb` at `fill_super`). # C: O(1)
    fn set_sb(&self, sb: Weak<SuperBlock>) { *self.sb.lock() = sb; }
    /// Raw insert of an existing inode (rename / hardlink). # C: O(log N)
    fn insert(&self, name: &str, inode: InodeRef) { self.kids.lock().insert(name.into(), inode); }
    /// Raw remove (rename). # C: O(log N)
    fn remove(&self, name: &str) -> Option<InodeRef> { self.kids.lock().remove(name) }
}

/// Build a fresh tmpfs directory inode (`ino`, `perm` permission bits, owned by
/// `sb`). `i_nlink` defaults to 2 (`.` + the parent's link), per Linux
/// `simple_fs`. # C: O(1)
fn make_tmpfs_dir_inode(ino: Ino, perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>, acct: Arc<TmpfsSb>) -> InodeRef {
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Directory, perm),
        Arc::new(TmpfsDirOps), Arc::new(TmpfsDirFileOps))
        .owner(uid, gid)
        .fsid(fsid_of(&sb))
        .private(Arc::new(TmpfsDirData {
            sb:   Spinlock::new(sb.clone()),
            kids: Spinlock::new(BTreeMap::new()),
            acct,
        }));
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    b.build()
}

/// Resolve a tree-relative path per-component from `root`. # C: O(components·log N)
fn dir_resolve(root: &InodeRef, rel: &str) -> Option<InodeRef> {
    let mut cur: InodeRef = root.clone();
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        cur = cur.lookup(comp).ok()?;
    }
    Some(cur)
}

/// Resolve the PARENT dir of `rel` to `(parent_inode, leaf_name)`.
/// # C: O(components·log N)
fn dir_parent_of<'a>(root: &InodeRef, rel: &'a str) -> Option<(InodeRef, &'a str)> {
    let mut parts = rel.split('/').filter(|c| !c.is_empty()).peekable();
    let mut cur: InodeRef = root.clone();
    let mut name = "";
    while let Some(c) = parts.next() {
        if parts.peek().is_none() { name = c; break; }
        cur = cur.lookup(c).ok()?;
    }
    if name.is_empty() { return None; }
    Some((cur, name))
}

/// `i_fop` for a tmpfs directory (readdir). # C: O(1)
struct TmpfsDirFileOps;
impl FileOps for TmpfsDirFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let g = d.kids.lock();
        let off = ctx.pos as usize;
        let mut idx = off;
        for (name, child) in g.iter().skip(off) {
            let next = idx as u64 + 1;
            if !ctx.emit(name, child.ino(), child.file_type(), next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

/// `i_op` for a tmpfs directory (lookup + namespace mutators). # C: O(log N)
struct TmpfsDirOps;
impl InodeOps for TmpfsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        d.kids.lock().get(name).cloned().ok_or(VfsError::Enoent)
    }

    /// `mkdir` — a fresh child `TmpfsDir` in this instance's tree. Honours the
    /// caller-supplied `mode` (perm bits; umask is applied at the syscall
    /// layer). The new dir starts at `i_nlink == 2` (`.` + this parent's link
    /// down) and the PARENT gains a link (the child's `..`), matching Linux
    /// `simple_mkdir`/`inc_nlink(dir)`. # C: O(log N)
    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        // Owner = caller fsuid/fsgid mapped down through the mount idmap; perm =
        // requested mode with umask cleared (Linux `shmem_mkdir` → `shmem_get_inode`
        // → `inode_init_owner`). Closes fsimpls D35 (was always uid/gid=0).
        let perm = (ctx.apply_umask(mode) & 0o7777) as u16;
        let d = make_tmpfs_dir_inode(ino, perm, ctx.fsuid(), ctx.fsgid(), dd.sb_weak(), dd.acct.clone());
        g.insert(name.into(), d.clone());
        inode.inc_nlink(); // child's ".." adds a link to this parent dir
        Ok(d)
    }

    /// `rmdir` — ENOTEMPTY when the child dir still has entries. Removing the
    /// child drops this parent's `i_nlink` (the gone `..`), mirroring Linux
    /// `simple_rmdir`/`drop_nlink(dir)`. # C: O(log N)
    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        match g.get(name) {
            None => return Err(VfsError::Enoent),
            Some(i) if i.file_type() != FileType::Directory => return Err(VfsError::Enotdir),
            Some(i) => {
                if let Some(d) = as_dir(i) {
                    if !d.kids.lock().is_empty() { return Err(VfsError::Enotempty); }
                }
            }
        }
        if let Some(victim) = g.remove(name) {
            victim.set_nlink(0);   // emptied dir: drop "." + parent's link down
            inode.drop_nlink();    // the child's ".." no longer points at us
            dd.acct.free_inode();  // reclaim the dir inode (f_ffree)
        }
        Ok(())
    }

    /// `create` — a fresh regular file honouring the caller-supplied `mode`
    /// (perm bits; umask is applied at the syscall layer). # C: O(log N)
    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        // Owner from caller cred (idmap-mapped), perm with umask cleared. # D35
        let perm = (ctx.apply_umask(mode) & 0o7777) as u16;
        let child = make_tmpfs_file_inode(false, perm, ctx.fsuid(), ctx.fsgid(), dd.sb_weak(), dd.acct.clone());
        g.insert(name.into(), child.clone());
        Ok(child)
    }

    /// `unlink` — remove a non-directory child. A directory victim is rejected
    /// with `EISDIR` (Linux `unlink(2)`; directories go through `rmdir`).
    /// Dropping the name decrements the victim's `i_nlink` (Linux
    /// `drop_nlink`); the inode's storage is freed once the count and all open
    /// fds reach zero. # C: O(log N)
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        match g.get(name) {
            None => Err(VfsError::Enoent),
            Some(i) if i.file_type() == FileType::Directory => Err(VfsError::Eisdir),
            Some(_) => {
                let victim = g.remove(name).expect("present");
                victim.drop_nlink();
                // Reclaim the inode only when the last name is gone (a hardlink
                // target with nlink>0 keeps its single charged inode). # D33
                if victim.nlink() == 0 { dd.acct.free_inode(); }
                Ok(())
            }
        }
    }

    /// `symlink(2)` — a followable tmpfs symlink child. # C: O(log N)
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &CreateCtx) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        // Symlinks carry no umask (always 0777) but DO take the caller owner. # D35
        g.insert(name.into(), make_tmpfs_symlink_inode(target, ctx.fsuid(), ctx.fsgid(), dd.sb_weak()));
        Ok(())
    }

    /// `mknod(2)` — FIFO/socket stay tmpfs special inodes; CHR/BLK become a
    /// device-node inode that dispatches I/O to the driver registered by
    /// `(major,minor)` (so `mknod /dev/zero c 1 5` then read returns zeros).
    /// # C: O(log N)
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &CreateCtx) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        let sb = dd.sb_weak();
        let perm = (ctx.apply_umask(mode as u32) & 0o7777) as u16;
        let (uid, gid) = (ctx.fsuid(), ctx.fsgid());
        let child: InodeRef = match mode & S_IFMT {
            S_IFIFO  => make_tmpfs_special_inode(FileType::Fifo, perm, rdev, uid, gid, sb),
            S_IFSOCK => make_tmpfs_sock_inode(uid, gid, sb),
            S_IFCHR  => make_device_node_inode(
                NEXT_INO.fetch_add(1, Ordering::Relaxed), FileType::CharDev,
                Devt::from_raw(rdev), perm, sb),
            S_IFBLK  => make_device_node_inode(
                NEXT_INO.fetch_add(1, Ordering::Relaxed), FileType::BlockDev,
                Devt::from_raw(rdev), perm, sb),
            _ => { dd.acct.free_inode(); return Err(VfsError::Einval); }
        };
        g.insert(name.into(), child);
        Ok(())
    }
}

/// Boot-time hook (kept for the boot sequence). The per-instance trees are
/// now built by the boot `register_bind` calls (each `TmpfsFs::new` owns its
/// own root `TmpfsDir`), so there is nothing to seed into a global registry.
/// # C: O(1)
pub fn init() {}

/// Boot-time round-trip smoke for the tmpfs body: build a fresh instance,
/// create a file in its tree, write/read-back/partial-overwrite.
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
pub fn smoke_test() {
    use hal::kassert;
    let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
    let inode = root.create_child(".smoke", 0o644, &CreateCtx::root()).expect("tmpfs.create");
    let n = inode.write(0, b"shell-test").expect("tmpfs.write");
    kassert!(n == 10, "tmpfs write len");
    let mut buf = [0u8; 16];
    let n = inode.read(0, &mut buf).expect("tmpfs.read");
    kassert!(n == 10, "tmpfs read len");
    kassert!(&buf[..10] == b"shell-test", "tmpfs round-trip body");
    // Re-write at offset 5 to validate partial overwrite.
    let _ = inode.write(5, b"WORK").expect("tmpfs.write part");
    let n = inode.read(0, &mut buf).expect("tmpfs.read 2");
    kassert!(&buf[..n] == b"shellWORKt", "tmpfs partial overwrite");
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  tmpfs-smoke: ok\n");
    }
}

/// One mounted tmpfs instance. Owns its OWN inode tree (`root: TmpfsDir`)
/// under its SuperBlock — there is no shared global registry. `mount_path`
/// is the prefix stripped from the whole-path `FileSystem` write ops
/// (`create`/`unlink`/`rename`/`link`) to address the tree; the per-component
/// ops (`mknod_child`/`unlink_child` via the resolved parent inode) need no
/// path at all. Built fresh per mount by [`TmpfsFs::new`].
pub struct TmpfsFs {
    mount_path: String,
    root:       InodeRef,
    sb:         Spinlock<Weak<SuperBlock>, InodeClass>,
    /// Per-instance space accounting (block/inode limits + usage). # D33
    acct:       Arc<TmpfsSb>,
}

impl TmpfsFs {
    /// A fresh empty tmpfs instance mounted at `mount_path` with Linux-default
    /// limits (half of RAM). `set_sb` stamps `s_dev` at `fill_super`, after
    /// which children derive `fsid` from it. # C: O(1)
    pub fn new(mount_path: String) -> Arc<Self> {
        Self::with_limits(mount_path, TmpfsSb::default_limits())
    }
    /// As [`TmpfsFs::new`] but with explicit accounting (the hook a future
    /// `mount -o size=,nr_inodes=` parser fills — the syscall layer that parses
    /// the option string is the only remaining piece, cross-lane). # C: O(1)
    pub fn with_limits(mount_path: String, acct: Arc<TmpfsSb>) -> Arc<Self> {
        acct.charge_inode(); // the root inode itself counts (Linux shmem)
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), acct.clone());
        Arc::new(Self { mount_path, root, sb: Spinlock::new(Weak::new()), acct })
    }
    /// This instance's root inode (`sb->s_root->d_inode`), handed to
    /// `register_bind` so the path walk crosses into the tree. # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
    /// Strip the mount-point prefix → tree-relative path. # C: O(len)
    fn rel<'a>(&self, abs: &'a str) -> &'a str {
        let mp = self.mount_path.trim_end_matches('/');
        if !mp.is_empty() {
            if let Some(r) = abs.strip_prefix(mp) {
                if r.is_empty() || r.starts_with('/') { return r.trim_start_matches('/'); }
            }
        }
        abs.trim_start_matches('/')
    }
}

impl vfs::fs::FileSystem for TmpfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "tmpfs" }
    /// TMPFS_MAGIC (linux/magic.h). # C: O(1)
    fn magic(&self) -> u64 { TMPFS_MAGIC }
    /// tmpfs block size = page size (statfs `f_bsize`). # C: O(1)
    fn block_size(&self) -> u32 { PG as u32 }
    /// This instance's root inode (mount table per-mount root). # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    /// Install live tmpfs space accounting as this SB's `s_op` so `statfs(2)`/
    /// `df` report real `f_blocks`/`f_bfree`/`f_files`/`f_ffree` (D33/D6). # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn vfs::SuperOps>> {
        Some(Arc::new(TmpfsSuperOps { acct: self.acct.clone() }))
    }

    /// `fill_super` back-stamp: record the SB so the root + every child
    /// derives `fsid` from `s_dev` (per-instance, not a constant). # C: O(1)
    fn set_sb(&self, sb: Weak<SuperBlock>) {
        *self.sb.lock() = sb.clone();
        if let Some(d) = as_dir(&self.root) { d.set_sb(sb); }
    }

    /// `open(O_CREAT)`: return the existing inode or create a regular file in
    /// the tree (lookup-or-create). `path` is mount-absolute. # C: O(components)
    fn create(&self, path: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        let rel = self.rel(path);
        if let Some(i) = dir_resolve(&self.root, rel) { return Ok(i); }
        let (p, name) = dir_parent_of(&self.root, rel).ok_or(VfsError::Enoent)?;
        p.create_child(name, mode, &CreateCtx::root())
    }

    /// `O_TMPFILE`: a fresh in-memory inode with no directory entry — reclaimed
    /// when its last fd closes (Linux shmem anonymous inode). It carries this
    /// instance's SB so `fsid` is the mount's `s_dev`. # C: O(1)
    fn create_anonymous(&self, _dir: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        // Blocks the anon inode writes count against this mount (freed on the
        // file's Drop); it has no directory entry so it is not inode-charged.
        Ok(make_tmpfs_file_inode(false, (mode & 0o7777) as u16, 0, 0, self.sb.lock().clone(), self.acct.clone()))
    }

    /// `unlink(2)` by whole path (atomic-rename idiom). # C: O(components)
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> {
        let (p, name) = dir_parent_of(&self.root, self.rel(path)).ok_or(VfsError::Enoent)?;
        p.unlink_child(name)
    }

    /// Hardlink: add another name in the tree for `target`'s inode. # C: O(components)
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        let inode = dir_resolve(&self.root, self.rel(target)).ok_or(VfsError::Enoent)?;
        self.link_inode(inode, link)
    }

    /// Materialize `inode` at `link` (linkat AT_EMPTY_PATH). # C: O(components)
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        let (p, name) = dir_parent_of(&self.root, self.rel(link)).ok_or(VfsError::Enoent)?;
        let dir = as_dir(&p).ok_or(VfsError::Enotdir)?;
        if dir.kids.lock().contains_key(name) { return Err(VfsError::Eexist); }
        inode.inc_nlink(); // a new name for the same inode (Linux inc_nlink)
        dir.insert(name, inode);
        Ok(())
    }

    /// `rename(from, to)` — the editor/package-manager atomic-write idiom:
    /// detach the source from its parent dir, attach it under the dest name.
    /// # C: O(components)
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        let (sp, sname) = dir_parent_of(&self.root, self.rel(from)).ok_or(VfsError::Enoent)?;
        let (dp, dname) = dir_parent_of(&self.root, self.rel(to)).ok_or(VfsError::Enoent)?;
        let sdir = as_dir(&sp).ok_or(VfsError::Enotdir)?;
        let ddir = as_dir(&dp).ok_or(VfsError::Enotdir)?;
        let inode = sdir.remove(sname).ok_or(VfsError::Enoent)?;
        ddir.insert(dname, inode);
        Ok(())
    }
}

/// `super_operations` for a tmpfs mount: `statfs` reports live per-instance
/// block/inode accounting (Linux `shmem_statfs`), replacing the generic
/// `FsBackedSuperOps` that reported only `f_type`/`f_bsize` (D33/D6). # C: O(1)
pub struct TmpfsSuperOps { acct: Arc<TmpfsSb> }
impl vfs::SuperOps for TmpfsSuperOps {
    /// # C: O(1)
    fn statfs(&self) -> KResult<vfs::SbStatFs> { Ok(self.acct.statfs()) }
}

#[cfg(test)]
mod statfs_tests {
    use super::*;
    use vfs::fs::FileSystem;

    // D33/D6: the accounting arithmetic statfs reports — block charge/free hits
    // the limit (the ENOSPC source) and f_bfree/f_ffree track usage. Exercised
    // directly so it needs no initialised PMM (frame alloc) in hosted tests.
    #[test]
    fn sb_block_inode_accounting_arithmetic() {
        let sb = TmpfsSb::new(4, 4);
        let s0 = sb.statfs();
        assert_eq!((s0.f_type, s0.f_bsize as usize), (TMPFS_MAGIC, PG));
        assert_eq!((s0.f_blocks, s0.f_bfree, s0.f_files, s0.f_ffree), (4, 4, 4, 4));
        // Charge 4 blocks → 5th is refused (ENOSPC).
        for _ in 0..4 { assert!(sb.charge_block()); }
        assert!(!sb.charge_block());
        assert_eq!(sb.statfs().f_bfree, 0);
        sb.free_blocks(2);
        assert_eq!(sb.statfs().f_bfree, 2);
        // Inodes behave the same.
        for _ in 0..4 { assert!(sb.charge_inode()); }
        assert!(!sb.charge_inode());
        assert_eq!(sb.statfs().f_ffree, 0);
        sb.free_inode();
        assert_eq!(sb.statfs().f_ffree, 1);
    }

    // D33: per-instance inode accounting through the directory ops — the root
    // counts, create/mkdir charge, unlink/rmdir reclaim, and an inode-limit hit
    // returns ENOSPC. (No data writes → no PMM dependency.)
    #[test]
    fn instance_inode_accounting_and_enospc() {
        // 3 inodes: root takes one, leaving room for two entries.
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 3));
        let root = fs.root_inode();
        let sops = fs.super_ops().expect("tmpfs super_ops");
        assert_eq!(sops.statfs().unwrap().f_ffree, 2); // root charged

        root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(sops.statfs().unwrap().f_ffree, 0);
        // Inode limit reached → next create is ENOSPC.
        assert!(matches!(root.create_child("g", 0o644, &CreateCtx::root()), Err(VfsError::Enospc)));

        // Reclaim both entries.
        root.unlink_child("f").expect("unlink f");
        root.rmdir("d").expect("rmdir d");
        assert_eq!(sops.statfs().unwrap().f_ffree, 2);
    }
}

#[cfg(test)]
mod symlink_tests {
    use super::*;
    // tmpfs symlink inode round-trips its target (the systemd /run case).
    #[test]
    fn symlink_inode_readlink_roundtrips() {
        let s = make_tmpfs_symlink_inode(b"/usr/share/zoneinfo/UTC", 0, 0, Weak::new());
        assert_eq!(s.file_type(), FileType::Symlink);
        assert_eq!(s.size(), 23);
        assert_eq!(s.readlink().unwrap(), b"/usr/share/zoneinfo/UTC".to_vec());
    }
    // symlink_child creates a followable symlink resolved per-component from
    // the dir's own kids map (no global registry).
    #[test]
    fn dir_symlink_child_creates_followable_link() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        root.symlink_child("tz", b"/etc/localtime", &CreateCtx::root()).expect("create symlink");
        let resolved = root.lookup("tz").expect("symlink in tree");
        assert_eq!(resolved.file_type(), FileType::Symlink);
        assert_eq!(resolved.readlink().unwrap(), b"/etc/localtime".to_vec());
        // Eexist on a second create.
        assert!(matches!(root.symlink_child("tz", b"/x", &CreateCtx::root()), Err(VfsError::Eexist)));
    }
}

#[cfg(test)]
mod nlink_mode_tests {
    use super::*;
    use vfs::fs::FileSystem;

    // D32: a fresh file starts at nlink=1; a hardlink raises it; unlink lowers
    // it (Linux tmpfs/simple_fs link accounting).
    #[test]
    fn hardlink_raises_and_unlink_lowers_nlink() {
        let fs = TmpfsFs::new(String::from("/"));
        let root = fs.root_inode();
        let f = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
        assert_eq!(f.nlink(), 1);
        fs.link_inode(f.clone(), "/b").expect("hardlink b");
        assert_eq!(f.nlink(), 2);
        fs.unlink("/b").expect("unlink b");
        assert_eq!(f.nlink(), 1);
        fs.unlink("/a").expect("unlink a");
        assert_eq!(f.nlink(), 0);
    }

    // D32: mkdir starts the child at nlink=2 (".", parent's link down) and
    // raises the PARENT's nlink (the child's ".."); rmdir reverses both.
    #[test]
    fn mkdir_rmdir_maintains_dir_nlink() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        assert_eq!(root.nlink(), 2);
        let sub = root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(sub.nlink(), 2);
        assert_eq!(root.nlink(), 3); // gained child's ".."
        root.rmdir("d").expect("rmdir d");
        assert_eq!(root.nlink(), 2);
    }

    // D35: mkdir/create honour the caller-supplied permission bits instead of
    // a hardcoded 0o755/0o644.
    #[test]
    fn create_and_mkdir_honour_mode() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let f = root.create_child("f", 0o600, &CreateCtx::root()).expect("create f");
        assert_eq!(f.perm(), Some(0o600));
        let d = root.mkdir("d", 0o2750, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(d.perm(), Some(0o2750));
    }

    // D35 (idmap lane): a new tmpfs inode takes its owner from the caller cred
    // (fsuid/fsgid) mapped DOWN through the mount idmap, and clears the umask
    // from its perm bits — closing the "tmpfs dirs land uid/gid=0" defect.
    #[test]
    fn create_mkdir_set_owner_from_cred_and_honour_umask() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let mut cred = vfs::Cred::root();
        cred.uid = 1000; cred.gid = 2000;
        // Non-idmapped (identity) mount: stored fs ids == caller ids; umask
        // clears the group/other write bits (Linux `inode_init_owner`).
        let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o022 };
        let f = root.create_child("f", 0o666, &ctx).expect("create f");
        assert_eq!((f.uid(), f.gid()), (Some(1000), Some(2000)));
        assert_eq!(f.perm(), Some(0o644)); // 0o666 & ~0o022
        let d = root.mkdir("d", 0o777, &ctx).expect("mkdir d");
        assert_eq!((d.uid(), d.gid()), (Some(1000), Some(2000)));
        assert_eq!(d.perm(), Some(0o755)); // 0o777 & ~0o022

        // Idmapped mount: caller vfs ids are mapped DOWN to the fs ids stored in
        // i_uid/i_gid (uniform extent fs=vfs+10000) — the mnt_idmap path.
        let idmap = vfs::Idmap::uniform(/*fs_lo*/10000, /*vfs_lo*/0, /*count*/65536);
        let ctx2 = CreateCtx { idmap: &idmap, cred: &cred, umask: 0 };
        let g = root.create_child("g", 0o600, &ctx2).expect("create g");
        assert_eq!((g.uid(), g.gid()), (Some(11000), Some(12000)));
    }

    // D28: unlink of a directory returns EISDIR (Linux unlink(2); rmdir is the
    // directory removal path).
    #[test]
    fn unlink_directory_is_eisdir() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert!(matches!(root.unlink_child("d"), Err(VfsError::Eisdir)));
        // A regular file still unlinks fine.
        root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        assert!(root.unlink_child("f").is_ok());
    }
}
