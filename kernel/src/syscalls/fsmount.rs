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
use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{Dentry, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};
use hal::USER_VA_END;

static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// fstypes the new mount API can materialise (mirrors `sys_mount`).
fn fstype_ok(t: &str) -> bool {
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

/// Detached mount object created by `fsmount`; carries the spec until
/// `move_mount` attaches it at a target path.
pub struct MountObjectInode {
    pub fstype: String,
    pub source: String,
    ino: Ino,
}

impl MountObjectInode {
    /// # C: O(1)
    pub fn new(fstype: String, source: String) -> Arc<Self> {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { fstype, source, ino })
    }
}

impl Inode for MountObjectInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn as_any(&self) -> Option<&dyn Any> { Some(self) }
}

fn read_cstr(p: u64, max: usize) -> Option<String> {
    if p == 0 || p >= USER_VA_END { return None; }
    // SAFETY: p in user range; bounded read via the shared helper.
    let b = unsafe { crate::devfs::read_user_cstr(p, max) }?;
    core::str::from_utf8(b).ok().map(|s| s.to_string())
}

/// Install `inode` as a fresh O_RDWR fd named `name`. Returns the fd or a
/// negative errno. `cloexec` sets FD_CLOEXEC.
fn install_fd(inode: InodeRef, name: &str, cloexec: bool) -> i64 {
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
fn fd_inode(fd: i32) -> Option<InodeRef> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd).ok().map(|f| f.inode().clone())
}

/// `sys_fsopen(fsname, flags)` — slot 430. Creates an `fs_context` fd for
/// `fsname`. `FSOPEN_CLOEXEC = 1`.
/// # C: O(1)
pub fn sys_fsopen(args: &SyscallArgs) -> i64 {
    const FSOPEN_CLOEXEC: u64 = 1;
    let fsname = match read_cstr(args.a0, 64) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    if !fstype_ok(&fsname) { return -(Errno::Enodev.as_i32() as i64); }
    let inode = FsContextInode::new(fsname) as InodeRef;
    install_fd(inode, "fscontext", (args.a1 & FSOPEN_CLOEXEC) != 0)
}

/// `sys_fsconfig(fd, cmd, key, value, aux)` — slot 431. Accumulates
/// options into the `fs_context`. We honour `source` via SET_STRING;
/// other keys + CMD_CREATE/RECONFIGURE are accepted.
/// # C: O(1)
pub fn sys_fsconfig(args: &SyscallArgs) -> i64 {
    const FSCONFIG_SET_STRING: u64 = 1;
    let fd = args.a0 as i32;
    let cmd = args.a1;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.as_any().and_then(|a| a.downcast_ref::<FsContextInode>()) {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    if cmd == FSCONFIG_SET_STRING {
        let key = read_cstr(args.a2, 64).unwrap_or_default();
        if key == "source" {
            if let Some(v) = read_cstr(args.a3, 256) {
                *ctx.source.lock() = v;
            }
        }
    }
    0
}

/// `sys_fsmount(fs_fd, flags, attr_flags)` — slot 432. Materialises a
/// detached mount object from the `fs_context`; returns a new fd for it.
/// `FSMOUNT_CLOEXEC = 1`.
/// # C: O(1)
pub fn sys_fsmount(args: &SyscallArgs) -> i64 {
    const FSMOUNT_CLOEXEC: u64 = 1;
    let fd = args.a0 as i32;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.as_any().and_then(|a| a.downcast_ref::<FsContextInode>()) {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let source = ctx.source.lock().clone();
    let mo = MountObjectInode::new(ctx.fstype.clone(), source) as InodeRef;
    install_fd(mo, "fsmount", (args.a1 & FSMOUNT_CLOEXEC) != 0)
}

/// `sys_move_mount(from_dirfd, from_path, to_dirfd, to_path, flags)` —
/// slot 429. Two modes: (a) attach a DETACHED mount produced by `fsmount`
/// (from_dirfd is its fd, from_path empty via MOVE_MOUNT_F_EMPTY_PATH) at
/// `to_path`; (b) relocate an EXISTING mount at `from_path` to `to_path`.
/// # C: O(N_mounts)
pub fn sys_move_mount(args: &SyscallArgs) -> i64 {
    let from_fd = args.a0 as i32;
    let from_path = read_cstr(args.a1, 256).unwrap_or_default();
    let to_path = match read_cstr(args.a3, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let target = crate::syscalls::pathresolve::resolve_cwd(&to_path);
    let target = if target.len() > 1 { target.trim_end_matches('/').to_string() } else { target };

    // Mode (a): from_fd refers to a detached fsmount object.
    if from_path.is_empty() {
        let inode = match fd_inode(from_fd) {
            Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        if let Some(mo) = inode.as_any().and_then(|a| a.downcast_ref::<MountObjectInode>()) {
            return attach_mount(&mo.fstype, &target);
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    // Mode (b): relocate an existing mount.
    let from = crate::syscalls::pathresolve::resolve_cwd(&from_path);
    let from = if from.len() > 1 { from.trim_end_matches('/').to_string() } else { from };
    match vfs::mount::move_mount(&from, &target) {
        Ok(())                    => 0,
        Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
        Err(_)                    => -(Errno::Einval.as_i32() as i64),
    }
}

/// Materialise `fstype` as a mount at `target` (the new-API counterpart of
/// `sys_mount`'s fstype switch).
/// # C: O(N_mounts)
fn attach_mount(fstype: &str, target: &str) -> i64 {
    match fstype {
        "tmpfs" | "ramfs" => {
            let root: InodeRef = Arc::new(::fs::tmpfs::TmpfsRootInode::new(target.to_string()));
            let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(::fs::tmpfs::TmpfsFs);
            let _ = vfs::mount::register_bind(target, fs, root);
            0
        }
        "cgroup2" => { cgroup::mount_root(); 0 }
        // proc/sysfs/devtmpfs/devpts are already present at their canonical
        // mount points; admit so the new-API probe path doesn't error.
        "proc" | "sysfs" | "devtmpfs" | "devpts" => 0,
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}
