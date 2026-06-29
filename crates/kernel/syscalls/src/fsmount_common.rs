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
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as LockClass};
use syscall::errno::Errno;
use vfs::{Dentry, File, FileType, InodeRef, OpenFlags};
use vfs::{InodeBuilder, default_inode_ops, default_file_ops, mk_mode};
use hal::USER_VA_END;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

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

/// Register a fresh empty kernfs-class instance (`kernfs::PseudoFs`) of fstype
/// `t` (magic `magic`) at the caller-walked mountpoint dentry, exactly as
/// procfs/sysfs/debugfs/tracefs are registered. Returns the `move_mount`/
/// `mount(2)` success/errno. # C: O(depth)
fn register_pseudofs(t: &'static str, magic: u64, target: &str, target_d: &Arc<Dentry>) -> i64 {
    let fs: Arc<dyn vfs::fs::FileSystem> = kernfs::PseudoFs::new(t, magic, target);
    match vfs::mount::register(Some(target_d.clone()), fs) {
        Ok(()) => { let _ = vfs::mount::propagate_mount(target_d); 0 }
        Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
        Err(e) => crate::namei_common::errno_from_vfs(e),
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
    match fstype {
        "tmpfs" | "ramfs" => {
            // Each `mount -t tmpfs` is a fresh instance owning its own tree.
            let tfs = ::fs::tmpfs::TmpfsFs::new(target.to_string());
            let root: InodeRef = tfs.root_inode();
            let fs: Arc<dyn vfs::fs::FileSystem> = tfs;
            let _ = vfs::mount::register_bind(Some(target_d.clone()), fs, root);
            let _ = vfs::mount::propagate_mount(target_d);
            0
        }
        "ext4" => {
            let name = source_disk_name(source);
            if name.is_empty() { return -(Errno::Einval.as_i32() as i64); }
            let dev = block::registry::by_name(name)
                .map(|d| d.dev.clone())
                .or_else(|| block::registry::by_serial(name));
            let dev = match dev {
                Some(d) => d,
                None => return -(Errno::Enoent.as_i32() as i64),
            };
            let fs = match ext4::rootfs::Ext4Mount::open(dev) {
                Ok(f) => f,
                Err(_) => return -(Errno::Einval.as_i32() as i64),
            };
            match vfs::mount::register(Some(target_d.clone()), fs) {
                Ok(()) => {
                    let _ = vfs::mount::propagate_mount(target_d);
                    0
                }
                Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                Err(e) => crate::namei_common::errno_from_vfs(e),
            }
        }
        "cgroup2" => match cgroup::mount_at(target, Some(target_d.clone())) {
            Ok(()) => 0,
            Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
            Err(e) => crate::namei_common::errno_from_vfs(e),
        }
        "proc" => {
            let _ = vfs::mount::register(Some(target_d.clone()), Arc::new(procfs::fs_impl::ProcfsFs));
            let _ = vfs::mount::propagate_mount(target_d);
            0
        }
        // A fresh sysfs INSTANCE must enter the unified mount table, exactly
        // like procfs/debugfs/tracefs above. systemd's `mount_private_sysfs`
        // (namespace.c `mount_private_apivfs`) mounts a new sysfs at a unique
        // mkdtemp staging dir, then `mount(staging, entry, MS_MOVE)` relocates
        // it into the sandbox root. The old `=> 0` admit-noop registered
        // NOTHING, so the staging path was not an exact mount → the follow-up
        // MS_MOVE hit `move_mount`'s `mount_exact_at … ok_or(Einval)` and the
        // executor failed step NAMESPACE (status=226). Registering the real
        // SysfsFs (the same fs kmain mounts at /sys) makes the staging mount
        // resolvable; after the executor's pivot_root re-roots staging→/, its
        // `mount_point` lands back at /sys and `SysfsFs::lookup("/sys/…")`
        // resolves normally. Boot never re-mounts /sys (the kernel mounted it),
        // so this never stacks a duplicate at /sys.
        "sysfs" => {
            let _ = vfs::mount::register(Some(target_d.clone()), Arc::new(sysfs::SysfsFs));
            let _ = vfs::mount::propagate_mount(target_d);
            0
        }
        // devtmpfs/devpts/cgroup(v1) instances still admit-noop: their content
        // lives in the devfs registry (no standalone whole-path FileSystem to
        // register), and systemd's private-dev path uses a tmpfs (registered
        // above), not devtmpfs — so the captured NAMESPACE failure does not
        // exercise them. They share sysfs's old latent MS_MOVE/umount2 gap and
        // want a real DevfsFs/DevptsFs superblock once one exists (residual).
        "devtmpfs" | "devpts" | "cgroup" => 0,
        // Real (devfs-delegating) superblocks so the mount enters the unified
        // table and passes libmount's post-mount verify + statfs f_type magic.
        // The old `=> 0` admit-noop made these invisible → helper exit 32.
        "debugfs" => {
            let _ = vfs::mount::register(Some(target_d.clone()), Arc::new(tracefs::fs_impl::DebugfsFs));
            let _ = vfs::mount::propagate_mount(target_d);
            0
        }
        "tracefs" => {
            let _ = vfs::mount::register(Some(target_d.clone()), Arc::new(tracefs::fs_impl::TracefsFs));
            let _ = vfs::mount::propagate_mount(target_d);
            0
        }
        // Simple kernfs/ramfs-class api-fses: each gets a REAL empty
        // `PseudoFs` instance (own SB + magic + directory root) so it enters
        // the unified mount table, shows in mountinfo, and reports its true
        // `statfs` f_type — the old `=> 0` admit-noop registered nothing
        // (mount succeeded but was invisible → libmount verify failed).
        "securityfs" => register_pseudofs("securityfs", SECURITYFS_MAGIC, target, target_d),
        "efivarfs"   => register_pseudofs("efivarfs",   EFIVARFS_MAGIC,   target, target_d),
        "pstore"     => register_pseudofs("pstore",     PSTOREFS_MAGIC,   target, target_d),
        "bpf"        => register_pseudofs("bpf",        BPF_FS_MAGIC,     target, target_d),
        "configfs"   => register_pseudofs("configfs",   CONFIGFS_MAGIC,   target, target_d),
        "fusectl"    => register_pseudofs("fusectl",    FUSE_CTL_MAGIC,   target, target_d),
        "mqueue"     => register_pseudofs("mqueue",     MQUEUE_MAGIC,     target, target_d),
        "hugetlbfs"  => register_pseudofs("hugetlbfs",  HUGETLBFS_MAGIC,  target, target_d),
        "autofs" => {
            let fs: Arc<dyn vfs::fs::FileSystem> = match ::fs::autofs::AutofsFs::new(data) {
                Ok(fs) => fs,
                Err(e) => return crate::namei_common::errno_from_vfs(e),
            };
            match vfs::mount::register(Some(target_d.clone()), fs) {
                Ok(()) => {
                    let _ = vfs::mount::propagate_mount(target_d);
                    0
                }
                Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                Err(e) => crate::namei_common::errno_from_vfs(e),
            }
        }
        "binfmt_misc" => {
            let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::binfmt_misc::BinfmtMiscFs::new();
            match vfs::mount::register(Some(target_d.clone()), fs) {
                Ok(()) => {
                    let _ = vfs::mount::propagate_mount(target_d);
                    0
                }
                Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
                Err(e) => crate::namei_common::errno_from_vfs(e),
            }
        }
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}

/// fd-backed `fs_context` builder created by `fsopen` — backend state
/// (`i_private`) of a concrete `vfs::Inode`.
pub struct FsContextInode {
    pub fstype: String,
    pub source: Spinlock<String, LockClass>,
}

impl FsContextInode {
    /// Build an `fs_context` anon inode tagged with `fstype`. # C: O(1)
    pub fn new(fstype: String) -> InodeRef {
        let ino = NEXT_FSCTX_INO.fetch_add(1, Ordering::Relaxed);
        InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600), default_inode_ops(), default_file_ops())
            .private(Arc::new(Self { fstype, source: Spinlock::new(String::new()) }))
            .build()
    }
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
}

impl MountObjectInode {
    /// `fsmount`: materialise-by-fstype at attach time. Returns the anon inode.
    /// # C: O(1)
    pub fn new(fstype: String, source: String) -> InodeRef {
        Self::build(Self { fstype, source, clone_of: None })
    }
    /// `open_tree(OPEN_TREE_CLONE)`: capture an existing mount's (fs, root).
    /// # C: O(1)
    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> InodeRef {
        Self::build(Self { fstype: String::new(), source: String::new(), clone_of: Some((fs, root)) })
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
