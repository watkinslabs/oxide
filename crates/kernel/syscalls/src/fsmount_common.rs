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

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as LockClass};
use syscall::errno::Errno;
use vfs::{Dentry, File, FileType, InodeRef, OpenFlags};
use vfs::{InodeBuilder, default_inode_ops, default_file_ops, mk_mode};
use hal::USER_VA_END;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// Linux `may_mount()` gate: every new-mount-API operation that creates,
/// reconfigures or attaches a mount requires CAP_SYS_ADMIN in the caller's
/// (user) namespace. Returns `Some(-EPERM)` to short-circuit, `None` to
/// proceed — mirrors the legacy `mount(2)`/`umount2(2)` check (D49).
/// # C: O(1)
pub(crate) fn require_sys_admin() -> Option<i64> {
    match sched::live::current() {
        Some(c) if c.has_cap(sched::cap::SYS_ADMIN) => None,
        _ => Some(-(Errno::Eperm.as_i32() as i64)),
    }
}

/// fstypes the new mount API can materialise (mirrors `sys_mount`).
/// # C: O(1)
pub(crate) fn fstype_ok(t: &str) -> bool {
    matches!(t,
        "tmpfs" | "ramfs" | "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup2"
        | "ext4"
        | "securityfs" | "efivarfs" | "pstore" | "bpf" | "configfs" | "debugfs"
        | "tracefs" | "fusectl" | "mqueue" | "hugetlbfs" | "autofs" | "binfmt_misc")
}

fn source_disk_name(source: &str) -> &str {
    source.rsplit('/').next().unwrap_or(source)
}

/// fstypes whose new-mount-API path is THREADED through a real
/// [`vfs::fs::FsContext`] (`fsopen`→`fsconfig`→`vfs_get_tree`→`fsmount`→
/// `move_mount`/`attach_sb`) rather than the legacy string-bag deferred to
/// [`mount_fstype`] at `move_mount`. Restricted to pseudo fstypes whose backend
/// `root()` is a target-INDEPENDENT singleton, so the SB realized at
/// `fsconfig(CMD_CREATE)` (which does not yet know the mount target) is
/// byte-identical to what `mount_fstype` would graft. tmpfs/ramfs (bake the
/// mount path into `rel()`), the PseudoFs group (seed the root ino from the
/// target path), ext4 (`FS_REQUIRES_DEV`), cgroup2/autofs/devtmpfs/devpts/cgroup
/// stay on the `mount_fstype` fallback. # C: O(1)
pub(crate) fn fstype_converted(t: &str) -> bool {
    matches!(t, "proc" | "sysfs" | "debugfs" | "tracefs")
}

// `s_magic` (linux/magic.h) for the simple kernfs/ramfs-class api-fses that
// mount EMPTY then get populated by the kernel/userspace. Named (not bare
// literals) so the statfs `f_type` a tool reads is the real Linux magic.
const SECURITYFS_MAGIC: u64 = 0x7363_6673;
const EFIVARFS_MAGIC:   u64 = 0xde5e_81e4;
const PSTOREFS_MAGIC:   u64 = 0x6165_676C;
const BPF_FS_MAGIC:     u64 = 0xcafe_4a11;
const CONFIGFS_MAGIC:   u64 = 0x6265_6570;
const FUSE_CTL_MAGIC:   u64 = 0x6573_5546;
const MQUEUE_MAGIC:     u64 = 0x1980_0202;
const HUGETLBFS_MAGIC:  u64 = 0x9584_58f6;

/// `s_magic` for ext4 (linux/magic.h `EXT4_SUPER_MAGIC`) — stamped on the
/// registry entry so it surfaces in `/proc/filesystems`; the live statfs
/// `f_type` still comes from the constructed `Ext4Mount`.
const EXT4_MAGIC: u64 = 0xef53;

/// One-time guard: register every constructor-bearing `file_system_type` into
/// the VFS registry (`vfs::fs::register_fs`) before the first dispatch. Held
/// across registration so concurrent first mounts serialise. # C: O(1) after first.
static FS_TYPES_REGISTERED: Spinlock<bool, LockClass> = Spinlock::new(false);

/// Idempotently populate the `file_system_type` registry (D40). # C: O(N) once.
fn ensure_filesystems_registered() {
    let mut done = FS_TYPES_REGISTERED.lock();
    if *done { return; }
    register_filesystems();
    *done = true;
}

/// Register each fstype the old hard-coded `match fstype { … }` materialised as
/// a name→constructor entry (Linux `register_filesystem`). Every backend crate
/// is in scope here (the VFS crate must not depend on them), so the constructor
/// closures build the SAME backend object the match did; the mount engine then
/// builds the `SuperBlock` (`build_sb`). The four fstypes whose construction is
/// NOT a clean backend-object constructor stay in [`mount_fstype_with_data`]'s
/// fallback match (cgroup2 → `cgroup::mount_at`; devtmpfs/devpts/cgroup →
/// devfs-registry admit-noop). # C: O(N)
fn register_filesystems() {
    use vfs::fs::{register_fs, FsFlags, FsType, MountSpec};
    type R = vfs::fs::KResult<MountSpec>;

    // tmpfs / ramfs — each mount is a fresh instance owning its own tree; the
    // engine binds its per-mount root (Linux `mount_nodev`). Admit-and-ignore.
    fn tmpfs_ctor(_s: &str, target: &str, _d: &str) -> R {
        let tfs = ::fs::tmpfs::TmpfsFs::new(target.to_string());
        let root = tfs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = tfs;
        Ok(MountSpec { fs, bind_root: Some(root), strict: false })
    }
    let _ = register_fs(FsType::new("tmpfs", 0, FsFlags::empty(), Box::new(tmpfs_ctor)));
    let _ = register_fs(FsType::new("ramfs", 0, FsFlags::empty(), Box::new(tmpfs_ctor)));

    // ext4 — block-device backed: resolve the source disk, open the on-disk SB.
    let _ = register_fs(FsType::new("ext4", EXT4_MAGIC, FsFlags::FS_REQUIRES_DEV,
        Box::new(|source: &str, _t: &str, _d: &str| -> R {
            let name = source_disk_name(source);
            if name.is_empty() { return Err(vfs::VfsError::Einval); }
            let dev = block::registry::by_name(name).map(|d| d.dev.clone())
                .or_else(|| block::registry::by_serial(name)).ok_or(vfs::VfsError::Enoent)?;
            let fs: Arc<dyn vfs::fs::FileSystem> =
                ext4::rootfs::Ext4Mount::open(dev).map_err(|_| vfs::VfsError::Einval)?;
            Ok(MountSpec { fs, bind_root: None, strict: true })
        })));

    // proc / sysfs / debugfs / tracefs — singleton pseudo-fs objects, admit-and-ignore.
    let _ = register_fs(FsType::new("proc", 0, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            Ok(MountSpec { fs: Arc::new(procfs::fs_impl::ProcfsFs), bind_root: None, strict: false })
        })));
    let _ = register_fs(FsType::new("sysfs", 0, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            Ok(MountSpec { fs: Arc::new(sysfs::SysfsFs), bind_root: None, strict: false })
        })));
    let _ = register_fs(FsType::new("debugfs", 0, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            Ok(MountSpec { fs: Arc::new(tracefs::fs_impl::DebugfsFs), bind_root: None, strict: false })
        })));
    let _ = register_fs(FsType::new("tracefs", 0, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            Ok(MountSpec { fs: Arc::new(tracefs::fs_impl::TracefsFs), bind_root: None, strict: false })
        })));

    // Simple kernfs/ramfs-class api-fses: a REAL empty `PseudoFs` (own SB +
    // magic + dir root). Register failure surfaces as errno (strict).
    macro_rules! pseudo { ($name:literal, $magic:expr) => {
        let _ = register_fs(FsType::new($name, $magic, FsFlags::empty(),
            Box::new(|_s: &str, target: &str, _d: &str| -> R {
                let fs: Arc<dyn vfs::fs::FileSystem> = kernfs::PseudoFs::new($name, $magic, target);
                Ok(MountSpec { fs, bind_root: None, strict: true })
            })));
    }; }
    pseudo!("securityfs", SECURITYFS_MAGIC);
    pseudo!("efivarfs",   EFIVARFS_MAGIC);
    pseudo!("pstore",     PSTOREFS_MAGIC);
    pseudo!("bpf",        BPF_FS_MAGIC);
    pseudo!("configfs",   CONFIGFS_MAGIC);
    pseudo!("fusectl",    FUSE_CTL_MAGIC);
    pseudo!("mqueue",     MQUEUE_MAGIC);
    pseudo!("hugetlbfs",  HUGETLBFS_MAGIC);

    // autofs — option-string parsed at construct; bad options → errno.
    let _ = register_fs(FsType::new("autofs", 0, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, data: &str| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::autofs::AutofsFs::new(data)?;
            Ok(MountSpec { fs, bind_root: None, strict: true })
        })));

    // binfmt_misc — empty registry fs.
    let _ = register_fs(FsType::new("binfmt_misc", 0, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::binfmt_misc::BinfmtMiscFs::new();
            Ok(MountSpec { fs, bind_root: None, strict: true })
        })));
}

/// Graft a constructor-produced [`vfs::fs::MountSpec`] onto the walked mountpoint
/// dentry, preserving the legacy per-fstype error policy via `spec.strict`:
/// admit-and-ignore (old `let _ = register(); 0`) vs surface-errno. # C: O(depth)
fn graft_mount(spec: vfs::fs::MountSpec, target_d: &Arc<Dentry>) -> i64 {
    if spec.strict {
        let res = match spec.bind_root {
            Some(root) => vfs::mount::register_bind(Some(target_d.clone()), spec.fs, root),
            None       => vfs::mount::register(Some(target_d.clone()), spec.fs),
        };
        match res {
            Ok(()) => { let _ = vfs::mount::propagate_mount(target_d); 0 }
            Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
            Err(e) => crate::namei_common::errno_from_vfs(e),
        }
    } else {
        match spec.bind_root {
            Some(root) => { let _ = vfs::mount::register_bind(Some(target_d.clone()), spec.fs, root); }
            None       => { let _ = vfs::mount::register(Some(target_d.clone()), spec.fs); }
        }
        let _ = vfs::mount::propagate_mount(target_d);
        0
    }
}

/// Materialise a filesystem type at `target` (the walked mountpoint dentry
/// `target_d` + its rendered path string `target`). The single fstype
/// dispatcher shared by old mount(2) and the new fsopen/fsmount/move_mount
/// API path. The engine takes the caller-walked dentry; `target` (string) is
/// used only as fs INPUT (tmpfs root-inode path, ext4/cgroup naming).
/// # C: O(N_mounts + optional block-registry lookup)
pub(crate) fn mount_fstype(source: &str, fstype: &str, target: &str, target_d: &Arc<Dentry>) -> i64 {
    mount_fstype_with_data(source, fstype, target, target_d, "")
}

/// Same dispatcher as `mount_fstype`, with the old mount(2) data string
/// passed through for filesystems that have Linux option protocols.
pub(crate) fn mount_fstype_with_data(
    source: &str,
    fstype: &str,
    target: &str,
    target_d: &Arc<Dentry>,
    data: &str,
) -> i64 {
    // D40: resolve `-t <type>` through the name-keyed `file_system_type`
    // registry (Linux `get_fs_type`) instead of a hard-coded `match fstype`.
    ensure_filesystems_registered();
    if let Some(ty) = vfs::fs::get_fs(fstype) {
        let spec = match ty.construct(source, target, data) {
            Ok(s) => s,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        return graft_mount(spec, target_d);
    }
    // Fallback: fstypes whose construction is NOT a clean backend-object
    // constructor (so they cannot live in the registry without restructuring
    // the boot mount path). Left here deliberately per D40 SAFETY.
    match fstype {
        // cgroup2 has its own mount engine (`cgroup::mount_at`), not a plain
        // `FileSystem` graft.
        "cgroup2" => match cgroup::mount_at(target, Some(target_d.clone())) {
            Ok(()) => 0,
            Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
            Err(e) => crate::namei_common::errno_from_vfs(e),
        }
        // devtmpfs/devpts/cgroup(v1) still admit-noop: their content lives in
        // the devfs registry (no standalone whole-path FileSystem to register),
        // and systemd's private-dev path uses a tmpfs (registered above), not
        // devtmpfs. They want a real DevfsFs/DevptsFs superblock once one
        // exists (residual).
        "devtmpfs" | "devpts" | "cgroup" => 0,
        // Unknown fstype: Linux `get_fs_type` fails to find a registered
        // file_system_type → mount(2)/fsmount return ENODEV, not EOPNOTSUPP (D48).
        _ => -(Errno::Enodev.as_i32() as i64),
    }
}

/// fd-backed `fs_context` builder created by `fsopen`/`fspick` — backend state
/// (`i_private`) of a concrete `vfs::Inode`.
pub struct FsContextInode {
    pub fstype: String,
    pub source: Spinlock<String, LockClass>,
    /// Accumulated `fsconfig` key/value options (Linux `fs_context` parameters),
    /// in submission order. SET_FLAG stores an empty value; SET_STRING/PATH/
    /// BINARY store the textual value. Consumed by the fstype materialiser on the
    /// LEGACY `mount_fstype` path (`fc == None`).
    pub options: Spinlock<Vec<(String, String)>, LockClass>,
    /// New mount-API context for a CONVERTED pseudo fstype ([`fstype_converted`]):
    /// the real [`vfs::fs::FsContext`] threaded through `fsconfig`/`vfs_get_tree`.
    /// `None` for fstypes still on the `mount_fstype` fallback AND for every
    /// `fspick` context (Step-1 reconfigure stays on the legacy no-op path).
    pub fc: Spinlock<Option<vfs::fs::FsContext>, LockClass>,
}

impl FsContextInode {
    /// `fsopen`: build an `fs_context` anon inode tagged with `fstype`. For a
    /// CONVERTED pseudo fstype this allocates a real `vfs::fs::FsContext`
    /// (`FsContext::for_mount`); otherwise `fc == None` and options accumulate in
    /// the string-bag for the `mount_fstype` fallback. # C: O(1)
    pub fn new(fstype: String) -> InodeRef {
        let fc = if fstype_converted(&fstype) {
            ensure_filesystems_registered();
            vfs::fs::get_fs_type(&fstype).map(|ty| vfs::fs::FsContext::for_mount(ty, 0))
        } else {
            None
        };
        Self::build(fstype, fc)
    }

    /// `fspick`: build a LEGACY `fs_context` inode tagged with the picked mount's
    /// `fstype` (no threaded `FsContext`; Step-1 `fsconfig(RECONFIGURE)` remains a
    /// no-op, byte-identical to the prior behaviour). # C: O(1)
    pub fn new_legacy(fstype: String) -> InodeRef {
        Self::build(fstype, None)
    }

    /// # C: O(1)
    fn build(fstype: String, fc: Option<vfs::fs::FsContext>) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(Self {
                fstype,
                source: Spinlock::new(String::new()),
                options: Spinlock::new(Vec::new()),
                fc: Spinlock::new(fc),
            }))
            .build()
    }
}

/// Detached mount object created by `fsmount` (CONVERTED: an already-realized
/// SB; LEGACY: materialise-by-fstype at attach) or `open_tree(OPEN_TREE_CLONE)`
/// (the cloned subtree's root inode + fs). `move_mount` attaches it at a target.
pub struct MountObjectInode {
    pub fstype: String,
    pub source: String,
    /// CONVERTED path: the `SuperBlock` realized by `vfs_get_tree` at
    /// `fsconfig(CMD_CREATE)` plus its root dentry — `move_mount` grafts it via
    /// [`vfs::mount::attach_sb`]. `None` ⇒ unconverted fstype: `move_mount` falls
    /// back to [`mount_fstype`] (byte-identical to the prior behaviour).
    pub realized: Option<(Arc<vfs::SuperBlock>, Arc<Dentry>)>,
    /// `fsmount(2)` `MOUNT_ATTR_*` the caller requested (validated in fsmount,
    /// D51). STORED but NOT yet applied on the realized graft: the prior path
    /// silently dropped these, so applying them would change the booted
    /// mount-table state — deferred behind a boot-verify (see move_mount).
    pub mnt_attrs: u64,
    /// Some for an `open_tree` clone: the captured (fs, root) to bind at the
    /// target. None otherwise.
    pub clone_of: Option<(Arc<dyn vfs::fs::FileSystem>, InodeRef)>,
}

impl MountObjectInode {
    /// `fsmount` LEGACY: materialise-by-fstype at attach time. # C: O(1)
    pub fn new(fstype: String, source: String, mnt_attrs: u64) -> InodeRef {
        Self::build(Self { fstype, source, realized: None, mnt_attrs, clone_of: None })
    }
    /// `fsmount` CONVERTED: carry the already-realized (sb, root dentry). # C: O(1)
    pub fn new_realized(sb: Arc<vfs::SuperBlock>, root: Arc<Dentry>, fstype: String,
        source: String, mnt_attrs: u64) -> InodeRef {
        Self::build(Self { fstype, source, realized: Some((sb, root)), mnt_attrs, clone_of: None })
    }
    /// `open_tree(OPEN_TREE_CLONE)`: capture an existing mount's (fs, root).
    /// # C: O(1)
    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> InodeRef {
        Self::build(Self { fstype: String::new(), source: String::new(),
            realized: None, mnt_attrs: 0, clone_of: Some((fs, root)) })
    }
    /// Wrap the mount-object state into a concrete `vfs::Inode`. # C: O(1)
    fn build(data: Self) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(data))
            .build()
    }
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
    let dentry = vfs::dcache::d_alloc_pseudo(name, inode.clone(), &crate::anon_dname::ANON_INODE_OPS);
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
