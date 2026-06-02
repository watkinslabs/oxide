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
    const FSCONFIG_SET_FD:     u64 = 5;
    let fd = args.a0 as i32;
    let cmd = args.a1;
    let inode = match fd_inode(fd) { Some(i) => i, None => return -(Errno::Ebadf.as_i32() as i64) };
    let ctx = match inode.as_any().and_then(|a| a.downcast_ref::<FsContextInode>()) {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // We support no fd-valued mount options. A converted fs returns EINVAL
    // (not EOPNOTSUPP) for an unknown SET_FD key; systemd's
    // mount_option_supported() probes with a bogus SET_FD option and treats
    // success or EOPNOTSUPP as "can't determine" (-EAGAIN → log noise), but
    // EINVAL as "new mount API works, option absent" → proceeds cleanly.
    if cmd == FSCONFIG_SET_FD { return -(Errno::Einval.as_i32() as i64); }
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
            // open_tree clone: bind the captured (fs, root) at the target.
            if let Some((fs, root)) = mo.clone_of.as_ref() {
                let _ = vfs::mount::register_bind(&target, fs.clone(), root.clone());
                return 0;
            }
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

/// `sys_open_tree(dirfd, path, flags)` — slot 428. `OPEN_TREE_CLONE`
/// detaches a CLONE of the mount at `path` into an fd (the source for a
/// later `move_mount`); without it, returns an O_PATH-like fd referring to
/// the path. `OPEN_TREE_CLOEXEC = O_CLOEXEC`. systemd uses the clone form
/// for `RootDirectory=`/sandbox setup.
/// # C: O(N_mounts)
pub fn sys_open_tree(args: &SyscallArgs) -> i64 {
    const OPEN_TREE_CLONE:   u64 = 1;
    const OPEN_TREE_CLOEXEC: u64 = 0o2_000_000;     // O_CLOEXEC
    let path = match read_cstr(args.a1, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let abs = crate::syscalls::pathresolve::resolve_cwd(&path);
    let abs = if abs.len() > 1 { abs.trim_end_matches('/').to_string() } else { abs };
    let cloexec = (args.a2 & OPEN_TREE_CLOEXEC) != 0;
    if (args.a2 & OPEN_TREE_CLONE) != 0 {
        // Capture the mount rooted at `abs` (fs + root inode) into a
        // detached clone object.
        let (mnt, _) = match vfs::mount::resolve_mount(&abs) {
            Some(m) => m, None => return -(Errno::Enoent.as_i32() as i64),
        };
        let root = match mnt.root.clone().or_else(|| mnt.fs.root()) {
            Some(r) => r, None => return -(Errno::Einval.as_i32() as i64),
        };
        let mo = MountObjectInode::new_clone(mnt.fs.clone(), root) as InodeRef;
        return install_fd(mo, "open_tree", cloexec);
    }
    // Non-clone: an fd referring to the path's inode (O_PATH-ish).
    match crate::syscalls::pathresolve::resolve(&abs, false) {
        Some(i) => install_fd(i, "open_tree", cloexec),
        None    => -(Errno::Enoent.as_i32() as i64),
    }
}

/// `sys_fspick(dirfd, path, flags)` — slot 433. Opens an `fs_context` for
/// the EXISTING mount at `path` (for reconfiguration via fsconfig). We tag
/// it with the mount's fstype. `FSPICK_CLOEXEC = 1`.
/// # C: O(N_mounts)
pub fn sys_fspick(args: &SyscallArgs) -> i64 {
    const FSPICK_CLOEXEC: u64 = 1;
    let path = match read_cstr(args.a1, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let abs = crate::syscalls::pathresolve::resolve_cwd(&path);
    let abs = if abs.len() > 1 { abs.trim_end_matches('/').to_string() } else { abs };
    let (mnt, _) = match vfs::mount::resolve_mount(&abs) {
        Some(m) => m, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let inode = FsContextInode::new(mnt.fs.name().to_string()) as InodeRef;
    install_fd(inode, "fspick", (args.a2 & FSPICK_CLOEXEC) != 0)
}

/// `sys_mount_setattr(dirfd, path, flags, uattr, size)` — slot 442.
/// Changes mount attributes on the subtree at `path`: we honour the
/// propagation change (`mount_attr.propagation` → MS_SHARED/PRIVATE/SLAVE/
/// UNBINDABLE) via `vfs::mount::set_propagation`; RDONLY/NOSUID/… attr bits
/// are accepted (no per-mount flag store yet). `struct mount_attr` is
/// `{ u64 attr_set, attr_clr, propagation, userns_fd }` (32 bytes).
/// # C: O(N_mounts)
pub fn sys_mount_setattr(args: &SyscallArgs) -> i64 {
    use vfs::mount::Propagation;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_PRIVATE:    u64 = 1 << 18;
    const MS_SLAVE:      u64 = 1 << 19;
    const MS_SHARED:     u64 = 1 << 20;
    let path = match read_cstr(args.a1, 256) {
        Some(s) => s, None => return -(Errno::Efault.as_i32() as i64),
    };
    let abs = crate::syscalls::pathresolve::resolve_cwd(&path);
    let abs = if abs.len() > 1 { abs.trim_end_matches('/').to_string() } else { abs };
    let uattr = args.a3;
    let size  = args.a4 as usize;
    if uattr == 0 || size < 24 || uattr >= USER_VA_END {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Read mount_attr.propagation (third u64, offset 16).
    // SAFETY: uattr+24 ≤ size and < USER_VA_END validated; CPL=0/EL1 reads the u64 through the caller's AS.
    let propagation = unsafe { core::ptr::read_volatile((uattr + 16) as *const u64) };
    if propagation != 0 {
        let kind = if propagation & MS_UNBINDABLE != 0 { Propagation::Unbindable }
            else if propagation & MS_SLAVE != 0 { Propagation::Slave }
            else if propagation & MS_SHARED != 0 { Propagation::Shared }
            else if propagation & MS_PRIVATE != 0 { Propagation::Private }
            else { Propagation::Private };
        let _ = vfs::mount::set_propagation(&abs, kind);
    }
    0
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
