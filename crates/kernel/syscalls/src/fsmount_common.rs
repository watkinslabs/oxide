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

/// [D6] `lookup_bdev` (Linux `block/bdev.c`) extended: resolve an ext4 `source`
/// to its backing device AND its stable `dev_t`
/// (`Some` ⇒ ext4 `dev_id()` reports it, so the engine `sget`-shares one
/// `SuperBlock` keyed on it with the real `major:minor` `s_dev`). Mirrors the ctor
/// device resolution: real `lookup_bdev` (path → S_ISBLK → `i_rdev` → registered
/// disk) carries the node's `i_rdev` as the canonical dev_t; the by-name fallback
/// synthesises the disk's dev_t; the by-serial fallback (the root/home volume
/// bound BEFORE /dev naming) has no clean disk index, so its dev_t is `None` (a
/// fresh anon SB — never break the rootfs). `None` device ⇒ caller errors ENOENT.
/// # C: O(path-depth + N_disks)
fn resolve_ext4_source(source: &str) -> Option<(Arc<dyn block::BlockDevice>, Option<u64>)> {
    // Linux `lookup_bdev`: the block node's `i_rdev` IS the canonical `dev_t`.
    if source.starts_with('/') {
        if let Some(vp) = crate::pathresolve::resolve_path(source, false) {
            if vp.inode.file_type() == FileType::BlockDev {
                let rdev = vp.inode.rdev();
                if let Some(d) = block::registry::by_dev(rdev) {
                    return Some((d.dev.clone(), Some(rdev as u64)));
                }
            }
        }
    }
    let name = source_disk_name(source);
    if name.is_empty() { return None; }
    // by-name: a registered disk yields its synthetic dev_t.
    if let Some(d) = block::registry::by_name(name) {
        return Some((d.dev.clone(), Some(block::registry::dev_t_of(&d.name, d.index) as u64)));
    }
    // by-serial (root/home pre-/dev): device only, no resolvable dev_t.
    block::registry::by_serial(name).map(|dev| (dev, None))
}

/// fstypes whose new-mount-API path is THREADED through a real
/// [`vfs::fs::FsContext`] (`fsopen`→`fsconfig`→`vfs_get_tree`→`fsmount`→
/// `move_mount`/`attach_sb`) rather than the legacy string-bag deferred to
/// [`mount_fstype`] at `move_mount`. Restricted to pseudo fstypes whose backend
/// `root()` is a target-INDEPENDENT singleton, so the SB realized at
/// `fsconfig(CMD_CREATE)` (which does not yet know the mount target) is
/// byte-identical to what `mount_fstype` would graft. ext4's ctor keys off
/// `source` (the block device), NOT the target, so it too realizes identically
/// at CMD_CREATE: `fsconfig("source",dev)` sets `fc.source`, the
/// `FS_REQUIRES_DEV` gate (fs_context `vfs_get_tree`) enforces a source, and
/// `LegacyFsContextOps::get_tree` → `FsType::mount(fc.source(),opts)` → the ext4
/// ctor opens the same SB `mount_fstype` would (D13/D14 for ext4). The PseudoFs
/// group (securityfs/efivarfs/pstore/bpf/configfs/fusectl/mqueue/hugetlbfs) is
/// now converted too: its root ino is the fixed Linux pseudo-fs root ino
/// (`kernfs::PSEUDO_ROOT_INO` = 1), no longer seeded from the target path, so it
/// realizes byte-identically at CMD_CREATE. tmpfs/ramfs are converted too: their
/// baked mount path (`mount_path`/`rel()`) is gone — root ino is fixed
/// (`ROOT_INO`), write ops are i_op-routed (create/unlink/link/rename), so the
/// SB realizes identically at any mount point. cgroup2 is converted too: the
/// unified hierarchy is a global singleton (`cgroup::realize_tree` marks the tree
/// mounted + returns the `(CgroupFs, root CgDir)` pair), its `CgroupFs` is
/// zero-sized and resolution is per-component from the root, so its SB is
/// target-independent and realizes byte-identically at CMD_CREATE (D13/D14).
/// devtmpfs is converted too: the global `/dev` tree is a singleton (`DevfsFs`,
/// own SB + TMPFS_MAGIC + the `/dev` `DevDir` root), so its SB is
/// target-independent and realizes byte-identically at CMD_CREATE (D8/D21).
/// autofs/devpts/cgroup(v1) stay on the `mount_fstype` fallback. # C: O(1)
pub(crate) fn fstype_converted(t: &str) -> bool {
    matches!(t,
        "proc" | "sysfs" | "debugfs" | "tracefs" | "ext4"
        // devtmpfs: singleton global `/dev` tree (`DevfsFs`), target-independent.
        | "devtmpfs"
        // PseudoFs group: now target-independent (fixed Linux root ino = 1,
        // `kernfs::PSEUDO_ROOT_INO`), so the SB realized at fsconfig(CMD_CREATE)
        // is byte-identical to mount_fstype's graft (D13/D14).
        | "securityfs" | "efivarfs" | "pstore" | "bpf"
        | "configfs" | "fusectl" | "mqueue" | "hugetlbfs"
        // tmpfs/ramfs: now TARGET-INDEPENDENT (mount_path/rel() removed; root
        // ino fixed at ROOT_INO, write ops i_op-routed incl. link/linkat), so
        // the SB realized at fsconfig(CMD_CREATE) is byte-identical to
        // mount_fstype's graft regardless of mount point (`/` == `/run`). D13/D14.
        | "tmpfs" | "ramfs"
        // cgroup2: unified hierarchy = global singleton; SB target-independent.
        | "cgroup2")
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

/// `s_magic` for cgroup2 (linux/magic.h `CGROUP2_SUPER_MAGIC`) — surfaced in
/// `/proc/filesystems`; the live statfs `f_type` still comes from `CgroupFs::magic`.
const CGROUP2_MAGIC: u64 = 0x6367_7270;

/// `s_magic` for devtmpfs (linux/magic.h `TMPFS_MAGIC` — devtmpfs shares the
/// tmpfs SB magic) — surfaced in `/proc/filesystems`; the live statfs `f_type`
/// comes from `devfs::DevfsFs::magic`.
const DEVTMPFS_MAGIC: u64 = 0x0102_1994;

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
/// builds the `SuperBlock` (`build_sb`). The fstypes whose construction is
/// NOT a clean backend-object constructor stay in [`mount_fstype_with_data`]'s
/// fallback match (cgroup(v1) admit-noop; devpts keeps a boot-tolerant fallback
/// arm in addition to its first-class registration; devtmpfs is now a registered
/// singleton `DevfsFs` `file_system_type`, off the fallback).
/// cgroup2 is now a registered `file_system_type` (`cgroup::realize_tree`),
/// not a fallback arm. # C: O(N)
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
            // D26 `lookup_bdev` (path → S_ISBLK → i_rdev → by_dev) with a legacy
            // basename name/serial fallback (the root volume binds by virtio
            // serial before /dev naming settles), now also yielding the [D6]
            // stable `dev_t` so two mounts of the same device sget-share one SB.
            let (dev, dev_t) = resolve_ext4_source(source).ok_or(vfs::VfsError::Enoent)?;
            let fs: Arc<dyn vfs::fs::FileSystem> =
                ext4::rootfs::Ext4Mount::open_with_dev(dev, dev_t).map_err(|_| vfs::VfsError::Einval)?;
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
            Box::new(|_s: &str, _t: &str, _d: &str| -> R {
                let fs: Arc<dyn vfs::fs::FileSystem> = kernfs::PseudoFs::new($name, $magic);
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

    // devpts — first-class pseudo-fs (D36/D37): a singleton `DevptsFs` SB whose
    // root holds `ptmx` + the per-pty slave nodes. `mount -t devpts` / fsopen
    // materialise the real `DEVPTS_MAGIC` SB instead of the old admit-noop. The
    // slaves stay mirrored in the devfs registry (devpts::allocate_pair) as a
    // fallback, so the boot /dev/pts setup is non-fatal if no devpts is mounted.
    // strict:false preserves the old devpts path's unconditional-success
    // semantics (admit-and-ignore, like devtmpfs) to keep the boot mount-path
    // change conservative.
    let _ = register_fs(FsType::new("devpts", devpts::DEVPTS_MAGIC, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = devpts::devpts_fs();
            Ok(MountSpec { fs, bind_root: None, strict: false })
        })));

    // devtmpfs — the global `/dev` tree (`DevfsFs`): a singleton SB-bearing
    // backend (own SB + TMPFS_MAGIC + the `/dev` `DevDir` root). TARGET-
    // INDEPENDENT: `DevfsFs` is zero-sized and `root()` resolves the global
    // `/dev` dir, so the SB realized at `fsconfig(CMD_CREATE)` is byte-identical
    // regardless of mount point (D8/D21). strict:false preserves the prior
    // devtmpfs admit-and-ignore mount(2) semantics. The boot `/dev` mount stays
    // kernel-internal (kmain) — this only services an explicit `mount -t
    // devtmpfs` (e.g. systemd's container/sandbox private-dev). `bind_root:None`
    // ⇒ the engine binds `DevfsFs::root()` (the `/dev` `DevDir`).
    let _ = register_fs(FsType::new("devtmpfs", DEVTMPFS_MAGIC, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(devfs::DevfsFs);
            Ok(MountSpec { fs, bind_root: None, strict: false })
        })));

    // cgroup2 — the unified hierarchy (cgroup v2). TARGET-INDEPENDENT: the
    // hierarchy is a global singleton (`cgroup::realize_tree` marks it mounted,
    // idempotently, and returns the `(CgroupFs, root CgDir)` pair), so the SB
    // realized at `fsconfig(CMD_CREATE)` is byte-identical to the SB
    // `cgroup::mount_at` grafts at the boot mount. `bind_root` is the root
    // `CgDir` (whose `fsid`=CGROUP2_FSID + root ino are stamped on the inode,
    // not the SB, so they survive any mount path). strict:false preserves the
    // prior cgroup2 admit-and-ignore mount(2) semantics (`mount_at` tolerated a
    // re-mount of the shared hierarchy). The boot `/sys/fs/cgroup` mount stays
    // on `cgroup::mount_root()` (kernel-internal, kmain) — unaffected.
    let _ = register_fs(FsType::new("cgroup2", CGROUP2_MAGIC, FsFlags::empty(),
        Box::new(|_s: &str, _t: &str, _d: &str| -> R {
            let (fs, root) = cgroup::realize_tree();
            Ok(MountSpec { fs, bind_root: Some(root), strict: false })
        })));
}

/// Graft a constructor-produced [`vfs::fs::MountSpec`] onto the walked mountpoint
/// dentry, preserving the legacy per-fstype error policy via `spec.strict`:
/// admit-and-ignore (old `let _ = register(); 0`) vs surface-errno. # C: O(depth)
fn graft_mount(spec: vfs::fs::MountSpec, target_d: &Arc<Dentry>, parent_hint: Option<u64>) -> i64 {
    if spec.strict {
        let res = match spec.bind_root {
            Some(root) => vfs::mount::register_bind_at(Some(target_d.clone()), spec.fs, root, parent_hint),
            None       => vfs::mount::register_at(Some(target_d.clone()), spec.fs, parent_hint),
        };
        match res {
            Ok(()) => { let _ = vfs::mount::propagate_mount(target_d); 0 }
            Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
            Err(e) => crate::namei_common::errno_from_vfs(e),
        }
    } else {
        match spec.bind_root {
            Some(root) => { let _ = vfs::mount::register_bind_at(Some(target_d.clone()), spec.fs, root, parent_hint); }
            None       => { let _ = vfs::mount::register_at(Some(target_d.clone()), spec.fs, parent_hint); }
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
        // Parent = the mount the target-dir walk crossed into (Linux `path->mnt`),
        // not a re-derivation from the bind-shared mountpoint dentry.
        let phint = crate::pathresolve::resolve_path(target, false).map(|p| p.mnt_id);
        return graft_mount(spec, target_d, phint);
    }
    // Fallback: fstypes whose construction is NOT a clean backend-object
    // constructor (so they cannot live in the registry without restructuring
    // the boot mount path). Left here deliberately per D40 SAFETY.
    match fstype {
        // cgroup (v1) still admit-noop: cgroup-v1 is descoped (v2-only in-tree,
        // no consumer), so there is no standalone whole-path FileSystem to
        // register. devpts is kept as a boot-tolerant fallback arm here in
        // addition to its first-class `DevptsFs` registration above. devtmpfs is
        // now a registered `devtmpfs` `file_system_type` (singleton `DevfsFs`),
        // off this fallback. cgroup-v1 is the documented D8/D21 residual.
        "devpts" | "cgroup" => 0,
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

    /// `fspick`: build a RECONFIGURE `fs_context` inode bound to the LIVE
    /// superblock + root dentry of the picked mount (superblock D15). The caller
    /// constructs `fc` via [`vfs::fs::FsContext::for_reconfigure`] over the
    /// resolved mount's `(sb, root)`, so a later `fsconfig(CMD_RECONFIGURE)`
    /// threads through [`vfs::fs::reconfigure_super`] (431_fsconfig.rs:64) and
    /// applies the parsed params + masked `sb_flags` to THAT sb in place, instead
    /// of the prior no-op legacy context. # C: O(1)
    pub fn new_reconfigure(fstype: String, fc: vfs::fs::FsContext) -> InodeRef {
        Self::build(fstype, Some(fc))
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
    /// D51). Applied on the realized graft by `move_mount` via
    /// [`vfs::mount::mount_attr_to_mnt`] + [`vfs::mount::attach_sb_with_flags`],
    /// which stamps the mapped MNT_* option bits on the new mount before it goes
    /// live (so a following `propagate_mount` peer-copy inherits them). ATOMIC so
    /// a `mount_setattr(fd,"",AT_EMPTY_PATH,...)` on the still-DETACHED object
    /// (systemd's fsmount→mount_setattr→move_mount sequence) can fold additional
    /// MOUNT_ATTR_* bits in before the attach reads them.
    pub mnt_attrs: AtomicU64,
    /// Some for an `open_tree` clone: the captured (fs, root) to bind at the
    /// target. None otherwise. (Legacy non-recursive path; superseded by
    /// `detached_tree` for the D24 recursive clone.)
    pub clone_of: Option<(Arc<dyn vfs::fs::FileSystem>, InodeRef)>,
    /// D24 Stage 1a: an `open_tree(OPEN_TREE_CLONE)` detaches a CLONE of the
    /// source mount SUBTREE (recursive when `AT_RECURSIVE`) here as an UNLINKED
    /// node list. `move_mount` TAKEs it and commits hash-only
    /// ([`vfs::mount::commit_tree_hashonly`]); the [`Drop`] below releases an
    /// uncommitted list ([`vfs::mount::release_clone_tree`]) so an `open_tree`
    /// fd closed without a `move_mount` balances the clones' SB active refs.
    pub detached_tree: Spinlock<Option<Vec<vfs::mount::CloneNode>>, LockClass>,
}

impl Drop for MountObjectInode {
    /// Release an UNCOMMITTED detached clone tree (fd closed without move_mount).
    /// # C: O(N × master slaves)
    fn drop(&mut self) {
        if let Some(tree) = self.detached_tree.lock().take() {
            vfs::mount::release_clone_tree(&tree);
        }
    }
}

impl MountObjectInode {
    /// `fsmount` LEGACY: materialise-by-fstype at attach time. # C: O(1)
    pub fn new(fstype: String, source: String, mnt_attrs: u64) -> InodeRef {
        Self::build(Self { fstype, source, realized: None, mnt_attrs: AtomicU64::new(mnt_attrs),
            clone_of: None, detached_tree: Spinlock::new(None) })
    }
    /// `fsmount` CONVERTED: carry the already-realized (sb, root dentry). # C: O(1)
    pub fn new_realized(sb: Arc<vfs::SuperBlock>, root: Arc<Dentry>, fstype: String,
        source: String, mnt_attrs: u64) -> InodeRef {
        Self::build(Self { fstype, source, realized: Some((sb, root)),
            mnt_attrs: AtomicU64::new(mnt_attrs), clone_of: None,
            detached_tree: Spinlock::new(None) })
    }
    /// `open_tree(OPEN_TREE_CLONE)`: capture an existing mount's (fs, root).
    /// # C: O(1)
    pub fn new_clone(fs: Arc<dyn vfs::fs::FileSystem>, root: InodeRef) -> InodeRef {
        Self::build(Self { fstype: String::new(), source: String::new(),
            realized: None, mnt_attrs: AtomicU64::new(0), clone_of: Some((fs, root)),
            detached_tree: Spinlock::new(None) })
    }
    /// D24 Stage 1a `open_tree(OPEN_TREE_CLONE[, AT_RECURSIVE])`: carry a DETACHED
    /// clone of the source mount subtree ([`vfs::mount::clone_mount_tree`]).
    /// # C: O(1)
    pub fn new_clone_tree(tree: Vec<vfs::mount::CloneNode>) -> InodeRef {
        Self::build(Self { fstype: String::new(), source: String::new(),
            realized: None, mnt_attrs: AtomicU64::new(0), clone_of: None,
            detached_tree: Spinlock::new(Some(tree)) })
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
    match fdt.alloc_limit(file, cur.nofile_soft()) {
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
