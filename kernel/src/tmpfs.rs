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

#![cfg(target_os = "oxide-kernel")]

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

/// `/tmp` directory inode. v1: synthetic — reads the flat registry
/// and emits each `/tmp/<name>` entry. lookup(name) reverses that.
pub struct TmpfsRootInode;

impl Inode for TmpfsRootInode {
    fn ino(&self) -> Ino { 0x4000_0000 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let mut p = String::with_capacity(5 + name.len());
        p.push_str("/tmp/");
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
            if let Some(name) = procfs::paths::child_under("/tmp", path) {
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
    register("/tmp".into(), Arc::new(TmpfsRootInode) as InodeRef);
}

/// Boot-time round-trip smoke for the tmpfs path. Creates an
/// inode, writes "shell-test", reads back, verifies, drops.
/// # SAFETY: caller is the boot path; PMM up; pre-userspace.
/// # C: O(1)
pub fn smoke_test() {
    use vfs::Inode;
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
    debug_boot! { klog::write_raw(b"[INFO]  tmpfs-smoke: ok\n"); }
}
