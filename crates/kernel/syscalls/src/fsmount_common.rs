// fsmount_common — shared types/helpers for the new mount API
// (fsopen/fsconfig/fsmount/move_mount/open_tree/fspick/mount_setattr).
// One syscall, one file (docs/53 §0). Moved verbatim from fsmount.rs.

// New mount API (`docs/16`, systemd 254+): fsopen/fsconfig/fsmount/
// move_mount. An `fs_context` is an fd-backed builder — fsopen creates
// one tagged with the fstype, fsconfig accumulates options (source, …),
// fsmount materialises a DETACHED mount object (another fd), and
// move_mount attaches it at a target path via the `vfs::mount`
// primitives. Replaces the prior memfd/EOPNOTSUPP stubs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as LockClass};
use syscall::errno::Errno;
use vfs::{Dentry, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};
use hal::USER_VA_END;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// fstypes the new mount API can materialise (mirrors `sys_mount`).
/// # C: O(1)
pub(crate) fn fstype_ok(t: &str) -> bool {
    matches!(t, "tmpfs" | "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup2" | "ramfs")
}

/// fd-backed `fs_context` builder created by `fsopen`.
pub struct FsContextInode {
    pub fstype: String,
    pub source: Spinlock<String, LockClass>,
    ino: Ino,
}

impl FsContextInode {
    /// # C: O(1)
    pub fn new(fstype: String) -> Arc<Self> {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { fstype, source: Spinlock::new(String::new()), ino })
    }
}

impl Inode for FsContextInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn as_any(&self) -> Option<&dyn Any> { Some(self) }
}

/// Detached mount object created by `fsmount` (materialise-by-fstype at
/// attach) or `open_tree(OPEN_TREE_CLONE)` (carries the cloned subtree's
/// root inode + fs). `move_mount` attaches it at a target path.
pub struct MountObjectInode {
    pub fstype: String,
    pub source: String,
    /// Some for an `open_tree` clone: the captured (fs, root) to bind at
    /// the target. None for `fsmount`: materialise a fresh `fstype` mount.
    pub clone_of: Option<(Arc<dyn vfs::fs::FileSystem>, InodeRef)>,
    ino: Ino,
}

impl MountObjectInode {
    /// `fsmount`: materialise-by-fstype at attach time.
    /// # C: O(1)
    pub fn new(fstype: String, source: String) -> Arc<Self> {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { fstype, source, clone_of: None, ino })
    }
    /// `open_tree(OPEN_TREE_CLONE)`: capture an existing mount's (fs, root).
    /// # C: O(1)
    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> Arc<Self> {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { fstype: String::new(), source: String::new(),
                        clone_of: Some((fs, root)), ino })
    }
}

impl Inode for MountObjectInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn as_any(&self) -> Option<&dyn Any> { Some(self) }
}

/// # C: O(max)
pub(crate) fn read_cstr(p: u64, max: usize) -> Option<String> {
    if p == 0 || p >= USER_VA_END { return None; }
    // SAFETY: p in user range; bounded read via the shared helper.
    let b = unsafe { devfs::read_user_cstr(p, max) }?;
    core::str::from_utf8(b).ok().map(|s| s.to_string())
}

/// Install `inode` as a fresh O_RDWR fd named `name`. Returns the fd or a
/// negative errno. `cloexec` sets FD_CLOEXEC.
/// # C: O(1)
pub(crate) fn install_fd(inode: InodeRef, name: &str, cloexec: bool) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, name.to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) {
        Ok(fd) => { if cloexec { let _ = fdt.set_cloexec(fd, true); } fd as i64 }
        Err(e) => -(e as i64),
    }
}

/// Fetch the inode behind `fd` in the calling task.
/// # C: O(1)
pub(crate) fn fd_inode(fd: i32) -> Option<InodeRef> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd).ok().map(|f| f.inode().clone())
}
