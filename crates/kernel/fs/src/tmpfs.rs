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
use vfs::{FileOps, InodeBuilder, default_inode_ops, make_device_node_inode, mk_mode};
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
}

/// Frame for `idx`, allocating + zeroing on first touch. The frame holds
/// the inode's single object reference (refcount 1, mapcount 0).
/// # C: O(log N_pages)
fn ensure_page(g: &mut BTreeMap<u64, u64>, idx: u64) -> Option<u64> {
    if let Some(&pa) = g.get(&idx) { return Some(pa); }
    let pa = pmm::setup::alloc_object_frame()?;
    let ptr = pmm::setup::frame_ptr(pa)?;
    // SAFETY: pa is a freshly-allocated PMM frame; PG is the page granule.
    unsafe { core::ptr::write_bytes(ptr, 0, PG); }
    g.insert(idx, pa);
    Some(pa)
}

/// Build a regular tmpfs/memfd file inode. `sealable` enables the memfd seal
/// word (`Inode::fcntl_seals`); `sb` owns the inode (`fsid` derives from
/// `s_dev`). # C: O(1)
fn make_tmpfs_file_inode(sealable: bool, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(TmpfsFileData {
        pages: Spinlock::new(BTreeMap::new()),
        len:   AtomicU64::new(0),
    });
    let mapping: Arc<dyn AddressSpaceOps> = data.clone();
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
        Arc::new(TmpfsFileInodeOps), Arc::new(TmpfsFileOps))
        .fsid(fsid_of(&sb))
        .mapping(mapping)
        .private(data);
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    if sealable { b = b.seals(0); }
    b.build()
}

/// Anonymous tmpfs file body (memfd / coredump), no owning SuperBlock. # C: O(1)
pub fn tmpfs_anon_file() -> InodeRef { make_tmpfs_file_inode(false, Weak::new()) }
/// A sealable memfd file (`memfd_create(MFD_ALLOW_SEALING)`). # C: O(1)
pub fn tmpfs_sealable_file() -> InodeRef { make_tmpfs_file_inode(true, Weak::new()) }

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
            let pa = ensure_page(&mut g, idx).ok_or(VfsError::Enospc)?;
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
            for idx in stale {
                if let Some(pa) = g.remove(&idx) {
                    // SAFETY: inode-owned frame past the truncation point; dec
                    // frees it when no mapper holds a reference.
                    unsafe { pmm::setup::dec_object_ref_and_maybe_free_frame(pa); }
                }
            }
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
            let pa = ensure_page(&mut g, idx).ok_or(VfsError::Enospc)?;
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
        ensure_page(&mut g, off / PG as u64)
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
fn make_tmpfs_symlink_inode(target: &[u8], sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777),
        Arc::new(TmpfsSymlinkOps), vfs::default_file_ops())
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
fn make_tmpfs_sock_inode(sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Socket, 0o755),
        default_inode_ops(), Arc::new(TmpfsErrFileOps))
        .fsid(fsid_of(&sb));
    if let Some(s) = sb.upgrade() { b = b.sb(Arc::downgrade(&s)); }
    b.build()
}

/// Special tmpfs inode created by mknod(2), mainly FIFO nodes under /run. The
/// mode (`ft` + `perm`) + device number are stamped into the inode — discarding
/// them made systemd's fifo_address_create reject the dm-event FIFO. # C: O(1)
fn make_tmpfs_special_inode(ft: FileType, perm: u16, rdev: u32, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
    let mut b = InodeBuilder::new(ino, mk_mode(ft, perm),
        default_inode_ops(), Arc::new(TmpfsErrFileOps))
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

/// Build a fresh tmpfs directory inode (`ino`, owned by `sb`). # C: O(1)
fn make_tmpfs_dir_inode(ino: Ino, sb: Weak<SuperBlock>) -> InodeRef {
    let mut b = InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
        Arc::new(TmpfsDirOps), Arc::new(TmpfsDirFileOps))
        .fsid(fsid_of(&sb))
        .private(Arc::new(TmpfsDirData {
            sb:   Spinlock::new(sb.clone()),
            kids: Spinlock::new(BTreeMap::new()),
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
    fn iterate(&self, inode: &Inode, off: u64,
               f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let d = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let g = d.kids.lock();
        let mut idx = off as usize;
        for (name, inode) in g.iter().skip(off as usize) {
            let next = idx as u64 + 1;
            if !f(inode.ino(), next, name, inode.file_type()) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `i_op` for a tmpfs directory (lookup + namespace mutators). # C: O(log N)
struct TmpfsDirOps;
impl InodeOps for TmpfsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        d.kids.lock().get(name).cloned().ok_or(VfsError::Enoent)
    }

    /// `mkdir` — a fresh child `TmpfsDir` in this instance's tree. # C: O(log N)
    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        let d = make_tmpfs_dir_inode(ino, dd.sb_weak());
        g.insert(name.into(), d.clone());
        Ok(d)
    }

    /// `rmdir` — ENOTEMPTY when the child dir still has entries. # C: O(log N)
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
        g.remove(name);
        Ok(())
    }

    /// # C: O(log N)
    fn create(&self, inode: &Inode, name: &str, _mode: u32) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let child = make_tmpfs_file_inode(false, dd.sb_weak());
        g.insert(name.into(), child.clone());
        Ok(child)
    }

    /// # C: O(log N)
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        if dd.kids.lock().remove(name).is_some() { Ok(()) } else { Err(VfsError::Enoent) }
    }

    /// `symlink(2)` — a followable tmpfs symlink child. # C: O(log N)
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8]) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        g.insert(name.into(), make_tmpfs_symlink_inode(target, dd.sb_weak()));
        Ok(())
    }

    /// `mknod(2)` — FIFO/socket stay tmpfs special inodes; CHR/BLK become a
    /// device-node inode that dispatches I/O to the driver registered by
    /// `(major,minor)` (so `mknod /dev/zero c 1 5` then read returns zeros).
    /// # C: O(log N)
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let sb = dd.sb_weak();
        let perm = mode & 0o7777;
        let child: InodeRef = match mode & S_IFMT {
            S_IFIFO  => make_tmpfs_special_inode(FileType::Fifo, perm, rdev, sb),
            S_IFSOCK => make_tmpfs_sock_inode(sb),
            S_IFCHR  => make_device_node_inode(
                NEXT_INO.fetch_add(1, Ordering::Relaxed), FileType::CharDev,
                Devt::from_raw(rdev), perm, sb),
            S_IFBLK  => make_device_node_inode(
                NEXT_INO.fetch_add(1, Ordering::Relaxed), FileType::BlockDev,
                Devt::from_raw(rdev), perm, sb),
            _ => return Err(VfsError::Einval),
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
    let root = make_tmpfs_dir_inode(ROOT_INO, Weak::new());
    let inode = root.create_child(".smoke", 0o644).expect("tmpfs.create");
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
}

impl TmpfsFs {
    /// A fresh empty tmpfs instance mounted at `mount_path`. `set_sb` stamps
    /// `s_dev` at `fill_super`, after which children derive `fsid` from it.
    /// # C: O(1)
    pub fn new(mount_path: String) -> Arc<Self> {
        let root = make_tmpfs_dir_inode(ROOT_INO, Weak::new());
        Arc::new(Self { mount_path, root, sb: Spinlock::new(Weak::new()) })
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
    /// This instance's root inode (mount table per-mount root). # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }

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
        p.create_child(name, mode)
    }

    /// `O_TMPFILE`: a fresh in-memory inode with no directory entry — reclaimed
    /// when its last fd closes (Linux shmem anonymous inode). It carries this
    /// instance's SB so `fsid` is the mount's `s_dev`. # C: O(1)
    fn create_anonymous(&self, _dir: &str, _mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        Ok(make_tmpfs_file_inode(false, self.sb.lock().clone()))
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

#[cfg(test)]
mod symlink_tests {
    use super::*;
    // tmpfs symlink inode round-trips its target (the systemd /run case).
    #[test]
    fn symlink_inode_readlink_roundtrips() {
        let s = make_tmpfs_symlink_inode(b"/usr/share/zoneinfo/UTC", Weak::new());
        assert_eq!(s.file_type(), FileType::Symlink);
        assert_eq!(s.size(), 23);
        assert_eq!(s.readlink().unwrap(), b"/usr/share/zoneinfo/UTC".to_vec());
    }
    // symlink_child creates a followable symlink resolved per-component from
    // the dir's own kids map (no global registry).
    #[test]
    fn dir_symlink_child_creates_followable_link() {
        let root = make_tmpfs_dir_inode(ROOT_INO, Weak::new());
        root.symlink_child("tz", b"/etc/localtime").expect("create symlink");
        let resolved = root.lookup("tz").expect("symlink in tree");
        assert_eq!(resolved.file_type(), FileType::Symlink);
        assert_eq!(resolved.readlink().unwrap(), b"/etc/localtime".to_vec());
        // Eexist on a second create.
        assert!(matches!(root.symlink_child("tz", b"/x"), Err(VfsError::Eexist)));
    }
}
