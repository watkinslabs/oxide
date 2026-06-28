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
use vfs::{DeviceNodeInode, Devt, FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::superblock::SuperBlock;

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x4000_0000);

/// memfd file-seal bits (`fcntl.h`).
pub const F_SEAL_SEAL:   u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW:   u32 = 0x0004;
pub const F_SEAL_WRITE:  u32 = 0x0008;

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
pub struct TmpfsFileInode {
    /// `page_idx -> frame pa`. Sparse: a hole reads as zero.
    pages: Spinlock<BTreeMap<u64, u64>, TaskListClass>,
    /// Logical size (Linux `i_size`); may exceed the populated pages.
    len:  AtomicU64,
    ino:  Ino,
    /// memfd seals (0 = none). `sealable` gates `fcntl_seals`: only a
    /// memfd created with `MFD_ALLOW_SEALING` exposes them.
    seals:    core::sync::atomic::AtomicU32,
    sealable: bool,
    /// `i_sb` — owning SuperBlock (empty for an anonymous memfd/coredump body).
    sb:       Weak<SuperBlock>,
}

/// Frame for `idx`, allocating + zeroing on first touch. The frame holds
/// the inode's single reference (alloc_one_frame = refcount 1).
/// # C: O(log N_pages)
fn ensure_page(g: &mut BTreeMap<u64, u64>, idx: u64) -> Option<u64> {
    if let Some(&pa) = g.get(&idx) { return Some(pa); }
    let pa = pmm::setup::alloc_one_frame()?;
    let hhdm = pmm::user_as::hhdm_offset();
    // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror at hhdm+pa is
    // kernel-writable (Limine-installed); PG is the page granule.
    unsafe { core::ptr::write_bytes((hhdm + pa) as *mut u8, 0, PG); }
    g.insert(idx, pa);
    Some(pa)
}

impl TmpfsFileInode {
    /// Anonymous body (memfd / coredump), no owning SuperBlock. # C: O(1)
    pub fn new() -> Arc<Self> { Self::make(false, Weak::new()) }
    /// A sealable memfd file (`memfd_create(MFD_ALLOW_SEALING)`).
    /// # C: O(1)
    pub fn new_sealable() -> Arc<Self> { Self::make(true, Weak::new()) }
    /// A tree file owned by `sb` (`fsid` derives from `sb.s_dev`). # C: O(1)
    pub fn new_in_sb(sb: Weak<SuperBlock>) -> Arc<Self> { Self::make(false, sb) }

    /// # C: O(1)
    fn make(sealable: bool, sb: Weak<SuperBlock>) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            pages: Spinlock::new(BTreeMap::new()),
            len:   AtomicU64::new(0),
            ino,
            seals: core::sync::atomic::AtomicU32::new(0),
            sealable,
            sb,
        })
    }
}

impl Drop for TmpfsFileInode {
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

impl Inode for TmpfsFileInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn fsid(&self) -> u64 { fsid_of(&self.sb) }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }

    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let len = self.len.load(Ordering::Acquire);
        if off >= len { return Ok(0); }
        let n = buf.len().min((len - off) as usize);
        let g = self.pages.lock();
        let hhdm = pmm::user_as::hhdm_offset();
        let mut done = 0usize;
        while done < n {
            let cur   = off as usize + done;
            let idx   = (cur / PG) as u64;
            let pgoff = cur % PG;
            let chunk = (PG - pgoff).min(n - done);
            match g.get(&idx) {
                Some(&pa) => {
                    // SAFETY: pa is an inode-owned frame; HHDM mirror readable;
                    // [pgoff..pgoff+chunk] is within the page granule.
                    unsafe {
                        let src = (hhdm + pa + pgoff as u64) as *const u8;
                        core::ptr::copy_nonoverlapping(src, buf[done..].as_mut_ptr(), chunk);
                    }
                }
                None => { buf[done..done + chunk].fill(0); } // sparse hole
            }
            done += chunk;
        }
        Ok(n)
    }

    fn write(&self, off: u64, src: &[u8]) -> KResult<usize> {
        let s = self.seals.load(Ordering::Acquire);
        if s & F_SEAL_WRITE != 0 { return Err(VfsError::Eperm); }
        let end = off + src.len() as u64;
        if end > self.len.load(Ordering::Acquire) && s & F_SEAL_GROW != 0 {
            return Err(VfsError::Eperm);
        }
        let mut g = self.pages.lock();
        let hhdm = pmm::user_as::hhdm_offset();
        let mut done = 0usize;
        while done < src.len() {
            let cur   = off as usize + done;
            let idx   = (cur / PG) as u64;
            let pgoff = cur % PG;
            let chunk = (PG - pgoff).min(src.len() - done);
            let pa = ensure_page(&mut g, idx).ok_or(VfsError::Enospc)?;
            // SAFETY: pa is an inode-owned frame; HHDM mirror writable;
            // [pgoff..pgoff+chunk] within the page granule; non-overlapping.
            unsafe {
                let dst = (hhdm + pa + pgoff as u64) as *mut u8;
                core::ptr::copy_nonoverlapping(src[done..].as_ptr(), dst, chunk);
            }
            done += chunk;
        }
        drop(g);
        if end > self.len.load(Ordering::Acquire) { self.len.store(end, Ordering::Release); }
        Ok(src.len())
    }

    fn truncate(&self, len: u64) -> KResult<()> {
        let s = self.seals.load(Ordering::Acquire);
        let old = self.len.load(Ordering::Acquire);
        if len < old && s & F_SEAL_SHRINK != 0 { return Err(VfsError::Eperm); }
        if len > old && s & F_SEAL_GROW   != 0 { return Err(VfsError::Eperm); }
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
                    unsafe { pmm::setup::dec_and_maybe_free_frame(pa); }
                }
            }
            let tail = len as usize % PG;
            if tail != 0 {
                if let Some(&pa) = g.get(&((len / PG as u64))) {
                    let hhdm = pmm::user_as::hhdm_offset();
                    // SAFETY: inode-owned frame; zero [tail..PG] within the granule.
                    unsafe { core::ptr::write_bytes((hhdm + pa + tail as u64) as *mut u8, 0, PG - tail); }
                }
            }
        }
        self.len.store(len, Ordering::Release);
        Ok(())
    }

    /// MAP_SHARED backing: hand back the inode's persistent frame for the
    /// page at file offset `off` (page-aligned), allocating on first touch.
    /// A shared mapping installs THIS pa (refcount-bumped), so user writes
    /// land in the file's storage and are visible to read/write + peers.
    /// # C: O(log N_pages)
    fn mmap_shared_frame(&self, off: u64) -> Option<u64> {
        let mut g = self.pages.lock();
        ensure_page(&mut g, off / PG as u64)
    }

    fn fcntl_seals(&self) -> Option<&core::sync::atomic::AtomicU32> {
        if self.sealable { Some(&self.seals) } else { None }
    }
}

/// Symlink-type tmpfs inode — stores the target text; `readlink` returns
/// it. Created by `TmpfsRootInode::symlink_child` (e.g. systemd's `/run`
/// symlinks). The path-walk follows it like any symlink.
pub struct TmpfsSymlinkInode {
    target: Vec<u8>,
    ino:    Ino,
    sb:     Weak<SuperBlock>,
}

impl TmpfsSymlinkInode {
    /// # C: O(1)
    pub fn new(target: &[u8]) -> Arc<Self> { Self::new_in_sb(target, Weak::new()) }
    /// Tree symlink owned by `sb`. # C: O(1)
    pub fn new_in_sb(target: &[u8], sb: Weak<SuperBlock>) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { target: target.to_vec(), ino, sb })
    }
}

impl Inode for TmpfsSymlinkInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn fsid(&self) -> u64 { fsid_of(&self.sb) }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.target.clone()) }
}

/// F152: socket-type tmpfs inode. bind(AF_UNIX, path) materialises
/// one of these at `path` so stat() returns S_IFSOCK + chmod()
/// flows through normal VFS (no per-call UNIX_REGISTRY override).
/// All I/O on this inode errors — actual datagram queueing lives
/// in `net::UnixDgramQueue` / SockKind::UnixDgram.
pub struct TmpfsSockInode {
    ino: Ino,
    sb:  Weak<SuperBlock>,
}

impl TmpfsSockInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> { Self::new_in_sb(Weak::new()) }
    /// Tree socket node owned by `sb`. # C: O(1)
    pub fn new_in_sb(sb: Weak<SuperBlock>) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { ino, sb })
    }
}

impl Inode for TmpfsSockInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn fsid(&self) -> u64 { fsid_of(&self.sb) }
    fn file_type(&self) -> FileType { FileType::Socket }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _off: u64, _src: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Special tmpfs inode created by mknod(2), mainly FIFO nodes under /run.
pub struct TmpfsSpecialInode {
    ino:  Ino,
    ft:   FileType,
    perm: u16,
    rdev: u32,
    sb:   Weak<SuperBlock>,
}

impl TmpfsSpecialInode {
    /// # C: O(1)
    pub fn new(ft: FileType, perm: u16, rdev: u32) -> Arc<Self> {
        Self::new_in_sb(ft, perm, rdev, Weak::new())
    }
    /// Tree special node (FIFO) owned by `sb`. # C: O(1)
    pub fn new_in_sb(ft: FileType, perm: u16, rdev: u32, sb: Weak<SuperBlock>) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { ino, ft, perm, rdev, sb })
    }
}

impl Inode for TmpfsSpecialInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn fsid(&self) -> u64 { fsid_of(&self.sb) }
    fn file_type(&self) -> FileType { self.ft }
    // mknod(2) gave this node its permission bits + device number; report
    // them. Discarding the mode made systemd's fifo_address_create reject
    // the dm-event FIFO ((st_mode & 0007)!=0 against the 0o755 fallback),
    // failing dm-event.socket -> lvm2-monitor dependency.
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn rdev(&self) -> u32 { self.rdev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _off: u64, _src: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}

/// Downcast an `InodeRef` to `&TmpfsDir` (every tmpfs dir is one). # C: O(1)
fn as_dir(i: &InodeRef) -> Option<&TmpfsDir> {
    i.as_any()?.downcast_ref::<TmpfsDir>()
}

/// Per-instance tmpfs directory inode (Linux `shmem` dir). Its `kids` map IS
/// the directory — resolution is per-component `i_op->lookup`, no whole-path
/// key, no global registry. Every child it creates inherits this dir's `sb`
/// weak, so `fsid` derives from the mount's `s_dev`.
pub struct TmpfsDir {
    ino:  Ino,
    sb:   Spinlock<Weak<SuperBlock>, InodeClass>,
    kids: Spinlock<BTreeMap<String, InodeRef>, InodeClass>,
}

impl TmpfsDir {
    /// # C: O(1)
    pub fn new(ino: Ino, sb: Weak<SuperBlock>) -> Arc<Self> {
        Arc::new(Self { ino, sb: Spinlock::new(sb), kids: Spinlock::new(BTreeMap::new()) })
    }
    /// This dir's owning-SB weak (handed to every child). # C: O(1)
    fn sb_weak(&self) -> Weak<SuperBlock> { self.sb.lock().clone() }
    /// Stamp the owning SB (`TmpfsFs::set_sb` at `fill_super`). # C: O(1)
    pub fn set_sb(&self, sb: Weak<SuperBlock>) { *self.sb.lock() = sb; }
    /// Raw insert of an existing inode (rename / hardlink). # C: O(log N)
    fn insert(&self, name: &str, inode: InodeRef) { self.kids.lock().insert(name.into(), inode); }
    /// Raw remove (rename). # C: O(log N)
    fn remove(&self, name: &str) -> Option<InodeRef> { self.kids.lock().remove(name) }
    /// Resolve a tree-relative path per-component. # C: O(components·log N)
    fn resolve(self: &Arc<Self>, rel: &str) -> Option<InodeRef> {
        let mut cur: InodeRef = self.clone();
        for comp in rel.split('/').filter(|c| !c.is_empty()) {
            cur = cur.lookup(comp).ok()?;
        }
        Some(cur)
    }
    /// Resolve the PARENT dir of `rel` to `(parent_inode, leaf_name)`.
    /// # C: O(components·log N)
    fn parent_of<'a>(self: &Arc<Self>, rel: &'a str) -> Option<(InodeRef, &'a str)> {
        let mut parts = rel.split('/').filter(|c| !c.is_empty()).peekable();
        let mut cur: InodeRef = self.clone();
        let mut name = "";
        while let Some(c) = parts.next() {
            if parts.peek().is_none() { name = c; break; }
            cur = cur.lookup(c).ok()?;
        }
        if name.is_empty() { return None; }
        Some((cur, name))
    }
}

impl Inode for TmpfsDir {
    fn ino(&self) -> Ino { self.ino }
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.lock().upgrade() }
    fn fsid(&self) -> u64 { fsid_of(&self.sb.lock()) }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        self.kids.lock().get(name).cloned().ok_or(VfsError::Enoent)
    }

    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let g = self.kids.lock();
        let mut idx = off as usize;
        for (name, inode) in g.iter().skip(off as usize) {
            let next = idx as u64 + 1;
            if !f(next, name, inode.file_type()) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }

    /// `mkdir` — a fresh child `TmpfsDir` in this instance's tree. # C: O(log N)
    fn mkdir(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        let mut g = self.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        let d = TmpfsDir::new(ino, self.sb_weak()) as InodeRef;
        g.insert(name.into(), d.clone());
        Ok(d)
    }

    /// `rmdir` — ENOTEMPTY when the child dir still has entries. # C: O(log N)
    fn rmdir(&self, name: &str) -> KResult<()> {
        let mut g = self.kids.lock();
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
    fn create_child(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        let mut g = self.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let inode = TmpfsFileInode::new_in_sb(self.sb_weak()) as InodeRef;
        g.insert(name.into(), inode.clone());
        Ok(inode)
    }

    /// # C: O(log N)
    fn unlink_child(&self, name: &str) -> KResult<()> {
        if self.kids.lock().remove(name).is_some() { Ok(()) } else { Err(VfsError::Enoent) }
    }

    /// `symlink(2)` — a followable `TmpfsSymlinkInode` child. # C: O(log N)
    fn symlink_child(&self, name: &str, target: &[u8]) -> KResult<()> {
        let mut g = self.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        g.insert(name.into(), TmpfsSymlinkInode::new_in_sb(target, self.sb_weak()) as InodeRef);
        Ok(())
    }

    /// `mknod(2)` — FIFO/socket stay tmpfs special inodes; CHR/BLK become a
    /// `vfs::DeviceNodeInode` that dispatches I/O to the driver registered by
    /// `(major,minor)` (so `mknod /dev/zero c 1 5` then read returns zeros).
    /// # C: O(log N)
    fn mknod_child(&self, name: &str, mode: u16, rdev: u32) -> KResult<()> {
        let mut g = self.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let sb = self.sb_weak();
        let perm = mode & 0o7777;
        let inode: InodeRef = match mode & S_IFMT {
            S_IFIFO  => TmpfsSpecialInode::new_in_sb(FileType::Fifo, perm, rdev, sb) as InodeRef,
            S_IFSOCK => TmpfsSockInode::new_in_sb(sb) as InodeRef,
            S_IFCHR  => DeviceNodeInode::new(
                NEXT_INO.fetch_add(1, Ordering::Relaxed), FileType::CharDev,
                Devt::from_raw(rdev), perm, sb) as InodeRef,
            S_IFBLK  => DeviceNodeInode::new(
                NEXT_INO.fetch_add(1, Ordering::Relaxed), FileType::BlockDev,
                Devt::from_raw(rdev), perm, sb) as InodeRef,
            _ => return Err(VfsError::Einval),
        };
        g.insert(name.into(), inode);
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
    let root = TmpfsDir::new(ROOT_INO, Weak::new());
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
    root:       Arc<TmpfsDir>,
    sb:         Spinlock<Weak<SuperBlock>, InodeClass>,
}

impl TmpfsFs {
    /// A fresh empty tmpfs instance mounted at `mount_path`. `set_sb` stamps
    /// `s_dev` at `fill_super`, after which children derive `fsid` from it.
    /// # C: O(1)
    pub fn new(mount_path: String) -> Arc<Self> {
        let root = TmpfsDir::new(ROOT_INO, Weak::new());
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
        self.root.set_sb(sb);
    }

    /// `open(O_CREAT)`: return the existing inode or create a regular file in
    /// the tree (lookup-or-create). `path` is mount-absolute. # C: O(components)
    fn create(&self, path: &str, mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        let rel = self.rel(path);
        if let Some(i) = self.root.resolve(rel) { return Ok(i); }
        let (p, name) = self.root.parent_of(rel).ok_or(VfsError::Enoent)?;
        p.create_child(name, mode)
    }

    /// `O_TMPFILE`: a fresh in-memory inode with no directory entry — reclaimed
    /// when its last fd closes (Linux shmem anonymous inode). It carries this
    /// instance's SB so `fsid` is the mount's `s_dev`. # C: O(1)
    fn create_anonymous(&self, _dir: &str, _mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        Ok(TmpfsFileInode::new_in_sb(self.sb.lock().clone()) as vfs::InodeRef)
    }

    /// `unlink(2)` by whole path (atomic-rename idiom). # C: O(components)
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> {
        let (p, name) = self.root.parent_of(self.rel(path)).ok_or(VfsError::Enoent)?;
        p.unlink_child(name)
    }

    /// Hardlink: add another name in the tree for `target`'s inode. # C: O(components)
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        let inode = self.root.resolve(self.rel(target)).ok_or(VfsError::Enoent)?;
        self.link_inode(inode, link)
    }

    /// Materialize `inode` at `link` (linkat AT_EMPTY_PATH). # C: O(components)
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        let (p, name) = self.root.parent_of(self.rel(link)).ok_or(VfsError::Enoent)?;
        let dir = as_dir(&p).ok_or(VfsError::Enotdir)?;
        if dir.kids.lock().contains_key(name) { return Err(VfsError::Eexist); }
        dir.insert(name, inode);
        Ok(())
    }

    /// `rename(from, to)` — the editor/package-manager atomic-write idiom:
    /// detach the source from its parent dir, attach it under the dest name.
    /// # C: O(components)
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        let (sp, sname) = self.root.parent_of(self.rel(from)).ok_or(VfsError::Enoent)?;
        let (dp, dname) = self.root.parent_of(self.rel(to)).ok_or(VfsError::Enoent)?;
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
        let s = TmpfsSymlinkInode::new(b"/usr/share/zoneinfo/UTC");
        assert_eq!(s.file_type(), FileType::Symlink);
        assert_eq!(s.size(), 23);
        assert_eq!(s.readlink().unwrap(), b"/usr/share/zoneinfo/UTC".to_vec());
    }
    // symlink_child creates a followable symlink resolved per-component from
    // the dir's own kids map (no global registry).
    #[test]
    fn dir_symlink_child_creates_followable_link() {
        let root = TmpfsDir::new(ROOT_INO, Weak::new());
        root.symlink_child("tz", b"/etc/localtime").expect("create symlink");
        let resolved = root.lookup("tz").expect("symlink in tree");
        assert_eq!(resolved.file_type(), FileType::Symlink);
        assert_eq!(resolved.readlink().unwrap(), b"/etc/localtime".to_vec());
        // Eexist on a second create.
        assert!(matches!(root.symlink_child("tz", b"/x"), Err(VfsError::Eexist)));
    }
}
