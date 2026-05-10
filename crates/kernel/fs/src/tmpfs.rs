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

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x4000_0000);

/// In-memory file body.
pub struct TmpfsFileInode {
    body: Spinlock<Vec<u8>, TaskListClass>,
    ino:  Ino,
}

impl TmpfsFileInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { body: Spinlock::new(Vec::new()), ino })
    }
}

impl Inode for TmpfsFileInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.body.lock().len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }

    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let g = self.body.lock();
        let off = off as usize;
        if off >= g.len() { return Ok(0); }
        let avail = &g[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }

    fn write(&self, off: u64, src: &[u8]) -> KResult<usize> {
        let mut g = self.body.lock();
        let off = off as usize;
        if off + src.len() > g.len() {
            g.resize(off + src.len(), 0);
        }
        g[off..off + src.len()].copy_from_slice(src);
        Ok(src.len())
    }
    fn truncate(&self, len: u64) -> KResult<()> {
        let mut g = self.body.lock();
        let len = len as usize;
        if len < g.len() {
            g.truncate(len);
        } else if len > g.len() {
            g.resize(len, 0);
        }
        Ok(())
    }
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
}

impl Inode for TmpfsRootInode {
    fn ino(&self) -> Ino { 0x4000_0000 }
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
    /// # C: O(N_tmpfs_entries)
    fn lookup(&self, path: &str) -> Option<vfs::InodeRef> { lookup(path) }
    /// # C: O(N_tmpfs_entries) — auto-creates regular files.
    fn create(&self, path: &str, _mode: u32) -> vfs::fs::KResult<vfs::InodeRef> {
        Ok(lookup_or_create(path))
    }
}

/// Singleton accessor.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &TmpfsFs }
