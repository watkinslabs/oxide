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





use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x4000_0000);

/// memfd file-seal bits (`fcntl.h`).
pub const F_SEAL_SEAL:   u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW:   u32 = 0x0004;
pub const F_SEAL_WRITE:  u32 = 0x0008;

const PG: usize = 4096;
const TMPFS_FSID: u64 = 0x0102_1994;

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
    /// # C: O(1)
    pub fn new() -> Arc<Self> { Self::make(false) }
    /// A sealable memfd file (`memfd_create(MFD_ALLOW_SEALING)`).
    /// # C: O(1)
    pub fn new_sealable() -> Arc<Self> { Self::make(true) }

    /// # C: O(1)
    fn make(sealable: bool) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            pages: Spinlock::new(BTreeMap::new()),
            len:   AtomicU64::new(0),
            ino,
            seals: core::sync::atomic::AtomicU32::new(0),
            sealable,
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
    fn fsid(&self) -> u64 { TMPFS_FSID }
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
}

impl TmpfsSymlinkInode {
    /// # C: O(1)
    pub fn new(target: &[u8]) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { target: target.to_vec(), ino })
    }
}

impl Inode for TmpfsSymlinkInode {
    fn ino(&self) -> Ino { self.ino }
    fn fsid(&self) -> u64 { TMPFS_FSID }
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
}

impl TmpfsSockInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { ino })
    }
}

impl Inode for TmpfsSockInode {
    fn ino(&self) -> Ino { self.ino }
    fn fsid(&self) -> u64 { TMPFS_FSID }
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
}

impl TmpfsSpecialInode {
    /// # C: O(1)
    pub fn new(ft: FileType, perm: u16, rdev: u32) -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { ino, ft, perm, rdev })
    }
}

impl Inode for TmpfsSpecialInode {
    fn ino(&self) -> Ino { self.ino }
    fn fsid(&self) -> u64 { TMPFS_FSID }
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

/// Path → tmpfs inode registry. Same `&str → InodeRef` shape as
/// devfs but mutable (callers can register new files on demand).
static REGISTRY: Spinlock<Vec<(String, InodeRef)>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Register a path (idempotent). Boot path uses this to seed
/// well-known files; `lookup_or_create` for runtime O_CREAT.
/// # SAFETY: caller is the boot path; single-CPU pre-init or holds
/// the registry's own spinlock for runtime use.
/// # C: O(N)
pub fn register(path: String, inode: InodeRef) {
    let mut g = REGISTRY.lock();
    if let Some(slot) = g.iter_mut().find(|(p, _)| *p == path) {
        slot.1 = inode;
    } else {
        g.push((path, inode));
    }
}

/// Look up a path; returns `Some(inode)` on hit.
/// # C: O(N)
pub fn lookup(path: &str) -> Option<InodeRef> {
    let g = REGISTRY.lock();
    g.iter().find(|(p, _)| p == path).map(|(_, i)| Arc::clone(i))
}

/// Look up `path`; if missing, create an empty `TmpfsFileInode`,
/// register, and return. Used by `sys_open(O_CREAT)`.
/// # C: O(N) lookup + O(1) insert
pub fn lookup_or_create(path: &str) -> InodeRef {
    if let Some(i) = lookup(path) { return i; }
    let inode = TmpfsFileInode::new() as InodeRef;
    register(path.into(), Arc::clone(&inode));
    inode
}

/// Tmpfs directory inode rooted at `mount_path` (e.g. "/tmp" for the
/// default boot mount, or "/var/lock" for a runtime-mounted instance).
/// readdir filters the flat registry by path-prefix; lookup composes
/// `<mount_path>/<name>`. F110 made this parameterised so `mount(2)`
/// can spawn multiple tmpfs instances at different mount points.
pub struct TmpfsRootInode {
    pub mount_path: String,
}

impl TmpfsRootInode {
    /// # C: O(1)
    pub fn new(mount_path: String) -> Self { Self { mount_path } }
    /// Construct the canonical root for the boot-time `/tmp`.
    /// # C: O(1)
    pub fn at_tmp() -> Self { Self::new(String::from("/tmp")) }
    /// Compose `<mount_path>/<name>` — the flat-registry key for a child.
    /// # C: O(len)
    fn child_path(&self, name: &str) -> String {
        let mut p = String::with_capacity(self.mount_path.len() + 1 + name.len());
        p.push_str(&self.mount_path);
        p.push('/');
        p.push_str(name);
        p
    }
}

impl Inode for TmpfsRootInode {
    fn ino(&self) -> Ino { 0x4000_0000 }
    fn fsid(&self) -> u64 { TMPFS_FSID }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let mut p = String::with_capacity(self.mount_path.len() + 1 + name.len());
        p.push_str(&self.mount_path);
        p.push('/');
        p.push_str(name);
        lookup(&p).ok_or(VfsError::Enoent)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let g = REGISTRY.lock();
        let mut idx = off as usize;
        while idx < g.len() {
            let (path, inode) = &g[idx];
            if let Some(name) = procfs::paths::child_under(&self.mount_path, path) {
                let next = idx as u64 + 1;
                if !f(next, name, inode.file_type()) {
                    return Ok(next);
                }
            }
            idx += 1;
        }
        Ok(idx as u64)
    }

    /// `mkdir` — register a nested `TmpfsRootInode` at `<mp>/<name>`.
    /// The namei walker dispatches here after resolving the parent.
    /// # C: O(N_tmpfs_entries)
    fn mkdir(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        let path = self.child_path(name);
        if lookup(&path).is_some() { return Err(VfsError::Eexist); }
        let inode = Arc::new(TmpfsRootInode::new(path.clone())) as InodeRef;
        register(path, Arc::clone(&inode));
        Ok(inode)
    }

    /// # C: O(N_tmpfs_entries)
    fn rmdir(&self, name: &str) -> KResult<()> {
        let path = self.child_path(name);
        let mut g = REGISTRY.lock();
        let len = g.len();
        g.retain(|(p, _)| *p != path);
        if g.len() == len { Err(VfsError::Enoent) } else { Ok(()) }
    }

    /// # C: O(N_tmpfs_entries)
    fn create_child(&self, name: &str, _mode: u32) -> KResult<InodeRef> {
        let path = self.child_path(name);
        if lookup(&path).is_some() { return Err(VfsError::Eexist); }
        let inode = TmpfsFileInode::new() as InodeRef;
        register(path, Arc::clone(&inode));
        Ok(inode)
    }

    /// # C: O(N_tmpfs_entries)
    fn unlink_child(&self, name: &str) -> KResult<()> {
        let path = self.child_path(name);
        let mut g = REGISTRY.lock();
        let len = g.len();
        g.retain(|(p, _)| *p != path);
        if g.len() == len { Err(VfsError::Enoent) } else { Ok(()) }
    }

    /// `symlink(2)` into tmpfs — registers a `TmpfsSymlinkInode` holding
    /// `target` (e.g. systemd's `/run` symlinks). The path-walk follows it.
    /// # C: O(N_tmpfs_entries)
    fn symlink_child(&self, name: &str, target: &[u8]) -> KResult<()> {
        let path = self.child_path(name);
        if lookup(&path).is_some() { return Err(VfsError::Eexist); }
        register(path, TmpfsSymlinkInode::new(target) as InodeRef);
        Ok(())
    }

    /// `mknod(2)` into tmpfs. systemd creates FIFOs under /run during early boot.
    /// # C: O(N_tmpfs_entries)
    fn mknod_child(&self, name: &str, mode: u16, _rdev: u32) -> KResult<()> {
        const S_IFMT:  u16 = 0xF000;
        const S_IFCHR: u16 = 0x2000;
        const S_IFBLK: u16 = 0x6000;
        const S_IFIFO: u16 = 0x1000;
        const S_IFSOCK: u16 = 0xC000;
        let ft = match mode & S_IFMT {
            S_IFIFO => FileType::Fifo,
            S_IFSOCK => FileType::Socket,
            S_IFCHR => FileType::CharDev,
            S_IFBLK => FileType::BlockDev,
            _ => return Err(VfsError::Einval),
        };
        let path = self.child_path(name);
        if lookup(&path).is_some() { return Err(VfsError::Eexist); }
        register(path, TmpfsSpecialInode::new(ft, mode & 0o7777, _rdev) as InodeRef);
        Ok(())
    }
}

/// Boot-time registry seeding. Registers the `/tmp` directory inode
/// so `open("/tmp", O_DIRECTORY)` + `getdents64` enumerate.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    register("/tmp".into(), Arc::new(TmpfsRootInode::at_tmp()) as InodeRef);
    // F111: POSIX shared memory backing — POSIX `shm_open(name, ...)`
    // resolves to `/dev/shm/<name>` per `shm_open(3)` linker contract.
    // Pre-mount tmpfs there so glibc/musl shm_open works without an
    // explicit mount(2) call from userspace at boot.
    register("/dev/shm".into(), Arc::new(TmpfsRootInode::new(String::from("/dev/shm"))) as InodeRef);
    // /run is the modern systemd-class tmpfs root (replaces /var/run).
    // Pre-mount so init scripts that write /run/<service>.pid don't
    // fail before the userspace mount sequence runs.
    register("/run".into(), Arc::new(TmpfsRootInode::new(String::from("/run"))) as InodeRef);
}

/// Boot-time round-trip smoke for the tmpfs path. Creates an
/// inode, writes "shell-test", reads back, verifies, drops.
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
pub fn smoke_test() {
    use hal::kassert;
    let inode = lookup_or_create("/tmp/.smoke");
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


/// FileSystem trait impl per `vfs::fs::FileSystem`.
pub struct TmpfsFs;

impl vfs::fs::FileSystem for TmpfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "tmpfs" }
    /// TMPFS_MAGIC (linux/magic.h).
    /// # C: O(1)
    fn magic(&self) -> u64 { 0x0102_1994 }
    /// # C: O(N_tmpfs_entries) — auto-creates regular files.
    fn create(&self, path: &str, _mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        Ok(lookup_or_create(path))
    }

    /// `O_TMPFILE`: a fresh in-memory inode with no registry (directory)
    /// entry — reclaimed when its last fd closes, like Linux shmem's
    /// anonymous inodes. `dir` is irrelevant for an in-memory FS. This is
    /// what makes `O_TMPFILE` on /run, /tmp, /dev/shm work (those are
    /// tmpfs); previously every `O_TMPFILE` was wrongly routed to ext4 and
    /// returned ENOSPC, which made journald abort.
    /// # C: O(1)
    fn create_anonymous(&self, _dir: &str, _mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        Ok(TmpfsFileInode::new() as vfs::InodeRef)
    }

    /// Drop the registry entry for `path`. Returns ENOENT if absent.
    /// F225: GNU patch's atomic-rename pattern needs unlink (sometimes
    /// it removes the dest before renaming the .tmp file in).
    /// # C: O(N_tmpfs_entries)
    fn unlink(&self, path: &str) -> vfs::fs::KResult<()> {
        let mut g = REGISTRY.lock();
        let len = g.len();
        g.retain(|(p, _)| p != path);
        if g.len() == len { Err(vfs::VfsError::Enoent) } else { Ok(()) }
    }

    /// Hardlink within tmpfs: register another name for the same inode.
    /// # C: O(N_tmpfs_entries)
    fn link(&self, target: &str, link: &str) -> vfs::fs::KResult<()> {
        let inode = lookup(target).ok_or(vfs::VfsError::Enoent)?;
        self.link_inode(inode, link)
    }

    /// Materialize an unnamed tmpfs inode at `link`.
    /// # C: O(N_tmpfs_entries)
    fn link_inode(&self, inode: vfs::InodeRef, link: &str) -> vfs::fs::KResult<()> {
        if inode.fsid() != TMPFS_FSID { return Err(vfs::VfsError::Exdev); }
        if lookup(link).is_some() { return Err(vfs::VfsError::Eexist); }
        register(link.into(), inode);
        Ok(())
    }

    /// rename(from, to) — atomic-write idiom used by every editor +
    /// package manager + GNU patch. Replaces the destination entry
    /// (if any) with the source inode, then drops the source entry.
    /// F225: required for GNU patch's `patch foo.txt < diff` flow,
    /// which writes patched content to `foo.txt.<temp>` then renames
    /// it over the original.
    /// # C: O(N_tmpfs_entries)
    fn rename(&self, from: &str, to: &str) -> vfs::fs::KResult<()> {
        let mut g = REGISTRY.lock();
        // Find source.
        let src_idx = match g.iter().position(|(p, _)| p == from) {
            Some(i) => i, None => return Err(vfs::VfsError::Enoent),
        };
        let src_inode = Arc::clone(&g[src_idx].1);
        // Replace dest (if it exists) or push a new entry, then drop source.
        if let Some(dst_idx) = g.iter().position(|(p, _)| p == to) {
            g[dst_idx].1 = src_inode;
        } else {
            g.push((to.into(), src_inode));
        }
        g.swap_remove(src_idx);
        Ok(())
    }
}

/// Singleton accessor.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &TmpfsFs }

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
    // symlink_child registers a followable symlink at <mount>/<name>.
    #[test]
    fn root_symlink_child_creates_followable_link() {
        let root = TmpfsRootInode::new(String::from("/run-test-xyz"));
        root.symlink_child("tz", b"/etc/localtime").expect("create symlink");
        let resolved = lookup("/run-test-xyz/tz").expect("symlink registered");
        assert_eq!(resolved.file_type(), FileType::Symlink);
        assert_eq!(resolved.readlink().unwrap(), b"/etc/localtime".to_vec());
        // Eexist on a second create.
        assert!(matches!(root.symlink_child("tz", b"/x"), Err(VfsError::Eexist)));
    }
}
