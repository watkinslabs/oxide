#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;

use core::sync::atomic::AtomicU64;
use sync::{Spinlock, TaskList as LockClass};
use vfs::FileType;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// # C: O(1)
/// Resolve a `source=` pathname to the block device it names. Shared by
/// every filesystem that requires one.
fn resolve_block_source(
    source: &str,
    access: u32,
) -> vfs::KResult<(Arc<dyn block::BlockDevice>, Option<u64>)> {
    let vp = crate::pathresolve::resolve_path_raw(source, false)?;
    if vp.inode.file_type() != FileType::BlockDev {
        return Err(vfs::VfsError::Enotblk);
    }
    if !vfs::may_open_dev(vp.mnt_id) {
        return Err(vfs::VfsError::Eacces);
    }
    let rdev = vp.inode.rdev();
    // Linux `lookup_bdev` checks nodev but not block-inode DAC.
    // `bdev_file_open_by_dev` then checks device policy before ENXIO.
    vfs::device_permission(FileType::BlockDev, rdev, access)?;
    let disk = block::registry::by_dev(rdev).ok_or(vfs::VfsError::Enxio)?;
    Ok((disk.dev.clone(), Some(rdev as u64)))
}

const SECURITYFS_MAGIC: u64 = 0x7363_6673;
/// `SELINUX_MAGIC` — the mandatory-access-control interface at `/sys/fs/selinux`.
const SELINUXFS_MAGIC: u64 = selinuxfs::SELINUX_MAGIC;
const EFIVARFS_MAGIC: u64 = 0xde5e_81e4;
const PSTOREFS_MAGIC: u64 = 0x6165_676C;
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
/// `FUSE_CTL_SUPER_MAGIC` — the fuse CONTROL
/// filesystem mounted at `/sys/fs/fuse/connections`. Distinct from
/// `FUSE_SUPER_MAGIC` (0x65735546) by one nibble; reporting the latter makes
/// every `statfs`-based fuse probe misidentify the control mount.
const FUSE_CTL_MAGIC: u64 = 0x6573_5543;
const FUSE_SUPER_MAGIC: u64 = fs::fuse::FUSE_SUPER_MAGIC;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const EXT4_MAGIC: u64 = 0xef53;
const CGROUP2_MAGIC: u64 = cgroup::CGROUP2_SUPER_MAGIC;
const DEVTMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;
const TMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;
const RAMFS_MAGIC: u64 = fs::tmpfs::RAMFS_MAGIC;
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const DEBUGFS_MAGIC: u64 = 0x6462_6720;
const TRACEFS_MAGIC: u64 = 0x7472_6163;
const CONFIGFS_MAGIC: u64 = 0x6265_6570;
const AUTOFS_SUPER_MAGIC: u64 = 0x0187;
const BINFMTFS_MAGIC: u64 = 0x4249_4e4d;

static FS_TYPES_REGISTERED: Spinlock<bool, LockClass> = Spinlock::new(false);

/// # C: O(N) once.
pub fn ensure_filesystems_registered() {
    let mut done = FS_TYPES_REGISTERED.lock();
    if *done { return; }
    register_filesystems();
    *done = true;
}

/// Which types publish a parameter table, and why the rest do not.
///
/// A table is a promise about a filesystem's WHOLE option surface, enforced on
/// both entry points: `mount(2)` now builds an `FsContext` and admits its
/// comma-separated blob through the same verdict `fsconfig(2)` applies, so a
/// key absent from the table fails the real mount, not merely the probe.
///
/// A table lists what the reference accepts, in full, INCLUDING a name that is
/// answered somewhere other than the mount. Omitting a name would make a mount
/// the reference accepts fail outright, which is worse than listing it; where a
/// listed name is answered elsewhere, the registration below says where.
///
/// `Some(&[])` is a real declaration and not a default: the VFS admits every
/// key against it, finds none, and reports the parameter unknown — exactly what
/// the reference does for a type whose context operations carry no
/// `parse_param` at all. `proc`, `sysfs`, `configfs`, `securityfs`, `fusectl`,
/// `mqueue` and `binfmt_misc` are those types.
///
/// Every registered type now publishes a table, so an option no filesystem here
/// implements fails the mount instead of being accepted and dropped.
///
/// `pstore` publishes a table and is still the most permissive type here,
/// because its reference parse SWALLOWS every negative answer — an unknown
/// key, a value that is not a number, a bare word where a number belongs. The
/// table is what makes a valid `kmsg_bytes=` reach the capture; the leniency
/// is enforced by pstore's own admission, not by omitting the table.
/// The calling task's cgroup-namespace root path, for `nsdelegate`.
///
/// The cgroup crate is a leaf with no `sched`/`nscg` dependency (the same
/// reason its signal and freeze hooks are installed rather than called), so the
/// live lookup lives here and the DECISION it feeds — is this cgroup inside
/// that root — lives in the cgroup crate where it is hosted-tested.
/// # C: O(1)
fn cgroup_ns_root_of_caller() -> Option<alloc::string::String> {
    let cur = sched::live::current()?;
    let ns = cur.namespace_owner(namespace_identity::NamespaceKind::Cgroup)?;
    Some(nscg::cgroup_ns::root_of(&ns))
}

/// Is the caller mounting from the initial user namespace?
///
/// Stands for `capable(CAP_SYS_ADMIN)` at the point overlayfs asks it: the
/// mount permission check has already run, so what is left to decide is
/// whether this caller may write the private markers into the `trusted.`
/// namespace, and only a mount from the initial namespace may.
/// # C: O(1)
fn in_initial_user_ns() -> bool {
    let initial = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    match sched::live::current()
        .and_then(|t| t.namespace_owner(namespace_identity::NamespaceKind::User)) {
        Some(ns) => namespace_identity::NamespaceRef::ptr_eq(&ns, &initial),
        // No task: an in-kernel mount, which runs with full privilege.
        None => true,
    }
}

/// The caller's filesystem identity — the id a 9P mount attaches under, and
/// therefore the identity the SERVER checks every operation on this mount
/// against. Not the real uid: `setfsuid(2)` exists precisely so a service can
/// act on a filesystem as somebody else, and attaching as the real uid would
/// ignore that. An in-kernel mount has no task and attaches as root.
/// # C: O(1)
fn caller_fsuid() -> u32 { caller_fsids().0 }

/// The caller's filesystem uid and gid together, for a mount that reports both
/// to its server. # C: O(1)
fn caller_fsids() -> (u32, u32) {
    use core::sync::atomic::Ordering;
    match sched::live::current() {
        Some(t) => (t.creds.fsuid.load(Ordering::Acquire), t.creds.fsgid.load(Ordering::Acquire)),
        None => (0, 0),
    }
}

fn register_filesystems() {
    use vfs::fs::{superblock_from_filesystem, FsFlags, FsType, register_fs};
    type R = vfs::fs::KResult<Arc<vfs::SuperBlock>>;

    // One-time: give the cgroup crate its view of the caller's cgroup namespace
    // so `nsdelegate` can be enforced.
    cgroup::state::set_cgroup_ns_root_hook(cgroup_ns_root_of_caller);

    // ext4's reports. The publisher goes in before the type is registered, and
    // publishing whatever mounted earlier is part of installing it.
    super::fs_surfaces::install_ext4_publisher();

    // Every registered constructor funnels its `sb_flags` word through here:
    // Linux stamps `s_flags` in `alloc_super()`, so the flags a `mount -o
    // ro,nosuid,noatime` requested land on the superblock the fill-super
    // creates — and an `sget` HIT keeps the flags the live instance already has.
    fn mounted(ty: Arc<dyn vfs::FileSystemType>, fs: Arc<dyn vfs::fs::FileSystem>, root: Option<vfs::InodeRef>,
        s_id: &str, sb_flags: u64) -> R {
        superblock_from_filesystem(ty, fs, root, s_id.to_string(), sb_flags)
    }

    fn tmpfs_ctor(ty: Arc<dyn vfs::FileSystemType>, _s: Option<&str>, target: &str, d: &str, sb_flags: u64,
        _p: &[vfs::fs::FsParameter]) -> R {
        // Honour the `-o mode=/uid=/gid=/size=/nr_inodes=` option string: the
        // per-user runtime dir (systemd-user-runtime-dir) mounts /run/user/UID
        // mode 0700 owned by UID:UID, and pam_systemd/`systemd --user` reject a
        // root-owned 0755 runtime dir. Was: option string dropped → every
        // tmpfs mounted root:root 0755 half-RAM (real-Linux divergence).
        // An option string the filesystem cannot honour fails the mount with
        // that option's error, rather than mounting something that ignores it.
        let tfs = ::fs::tmpfs::TmpfsFs::from_mount_data(target.to_string(), d)?;
        let root = tfs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = tfs;
        mounted(ty, fs, Some(root), target, sb_flags)
    }
    // ramfs is a SEPARATE Linux filesystem type, not an alias: `ramfs_fill_super`
    // stamps RAMFS_MAGIC and imposes no block/inode ceiling. Sharing tmpfs's
    // constructor made every ramfs mount report `tmpfs`/TMPFS_MAGIC to statfs(2)
    // and to /proc/mounts.
    fn ramfs_ctor(ty: Arc<dyn vfs::FileSystemType>, _s: Option<&str>, target: &str, d: &str, sb_flags: u64,
        _p: &[vfs::fs::FsParameter]) -> R {
        let rfs = ::fs::tmpfs::TmpfsFs::ramfs_from_mount_data(d)?;
        let root = rfs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = rfs;
        mounted(ty, fs, Some(root), target, sb_flags)
    }
    let _ = register_fs(FsType::with_parameters("tmpfs", TMPFS_MAGIC,
        FsFlags::FS_USERNS_MOUNT | FsFlags::FS_ALLOW_IDMAP, Box::new(tmpfs_ctor),
        Some(::fs::tmpfs::TMPFS_PARAMS)));
    let _ = register_fs(FsType::with_parameters("ramfs", RAMFS_MAGIC,
        FsFlags::FS_USERNS_MOUNT, Box::new(ramfs_ctor), Some(::fs::tmpfs::RAMFS_PARAMS)));
    let _ = register_fs(FsType::with_parameters("ext4", EXT4_MAGIC,
        FsFlags::FS_REQUIRES_DEV | FsFlags::FS_ALLOW_IDMAP, Box::new(|ty, source: Option<&str>, _t: &str, d: &str, sb_flags: u64, _p: &[vfs::fs::FsParameter]| -> R {
        let source = source.ok_or(vfs::VfsError::Enoent)?;
        let access = vfs::MAY_READ
            | if sb_flags & vfs::superblock::SB_RDONLY == 0 { vfs::MAY_WRITE } else { 0 };
        let (dev, dev_t) = resolve_block_source(source, access)?;
        // Honour the `-o usrquota/grpquota/prjquota/usrjquota=/grpjquota=/
        // jqfmt=/quota/noquota` option string. Was: dropped on the floor, so
        // every quota mount option was silently accepted and did nothing.
        let fs: Arc<dyn vfs::fs::FileSystem> = ext4::rootfs::Ext4Mount::open_with_data(dev, dev_t, d)?;
        mounted(ty, fs, None, source, sb_flags)
    }), Some(ext4::rootfs::EXT4_PARAMS)));
    // FAT is what the EFI system partition and almost every removable medium
    // carry. `vfat` and `msdos` are two TYPES over one on-disk format, and the
    // difference is the naming rules: `msdos` neither reads nor writes
    // long-name slots, so a name it cannot spell in eleven bytes does not
    // exist there. Sharing one constructor gave an `msdos` mount long names it
    // did not ask for — strictly more information than the type promises, and
    // not what the type means.
    fn fat_ctor(ty: Arc<dyn vfs::FileSystemType>, source: Option<&str>, d: &str, sb_flags: u64,
                type_name: &'static str, base: fatfs::Options) -> R {
        let source = source.ok_or(vfs::VfsError::Enoent)?;
        let write = sb_flags & vfs::superblock::SB_RDONLY == 0;
        let access = vfs::MAY_READ | if write { vfs::MAY_WRITE } else { 0 };
        let (dev, _dev_t) = resolve_block_source(source, access)?;
        // The option string decides which characters a name spells
        // (`codepage=`), whether a lowercase name round-trips (`shortname=`),
        // and which instant every timestamp on the volume means (`tz=`), so a
        // string that cannot be honoured fails the mount rather than mounting
        // something that ignores it.
        let opts = fatfs::opts::parse(base, d).map_err(fatfs::mount::errno_to_vfs)?;
        let fatfs = fatfs::FatFs::open_typed(dev, source, write, type_name, opts)?;
        // A mount that asked to write and could not — a medium that refuses
        // writes — mounts READ-ONLY rather than failing, and the superblock
        // says so, because reporting writable when the volume is not fails
        // every write at the first one instead of at the mount. A volume left
        // DIRTY is not that case: it mounts read-write with a warning, exactly
        // as the reference does.
        let sb_flags = if fatfs.is_writable() { sb_flags } else { sb_flags | vfs::superblock::SB_RDONLY };
        let root = fatfs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = fatfs;
        mounted(ty, fs, Some(root), source, sb_flags)
    }
    let _ = register_fs(FsType::new("vfat", fatfs::MSDOS_SUPER_MAGIC, FsFlags::FS_REQUIRES_DEV,
        Box::new(|ty, s: Option<&str>, _t: &str, d: &str, f: u64, _p: &[vfs::fs::FsParameter]| -> R {
            fat_ctor(ty, s, d, f, "vfat", fatfs::Options::vfat())
        })));
    let _ = register_fs(FsType::new("msdos", fatfs::MSDOS_SUPER_MAGIC, FsFlags::FS_REQUIRES_DEV,
        Box::new(|ty, s: Option<&str>, _t: &str, d: &str, f: u64, _p: &[vfs::fs::FsParameter]| -> R {
            fat_ctor(ty, s, d, f, "msdos", fatfs::Options::msdos())
        })));
    // OverlayFS is what makes a container image runnable: its layers are
    // ordinary directories rather than a device, so it takes no source and
    // resolves every layer out of the option string. `FS_USERNS_MOUNT` because
    // an unprivileged container runtime mounts it inside its own user
    // namespace — and that is exactly the caller whose private markers have to
    // go in the unprivileged attribute namespace, which is why the constructor
    // has to know which namespace it is being mounted from.
    fn overlay_ctor(ty: Arc<dyn vfs::FileSystemType>, d: &str, sb_flags: u64) -> R {
        let resolve = |p: &str| -> Result<vfs::InodeRef, syscall::errno::Errno> {
            vfs::resolve_abs(p).map_err(overlayfs::err::to_errno)
        };
        let fs = overlayfs::OverlayFs::open(d, &resolve, in_initial_user_ns())
            .map_err(overlayfs::err::to_vfs)?;
        let root = fs.root_inode();
        // A mount with no writable layer reports itself read-only, so a write
        // fails at `open` with `EROFS` rather than halfway through.
        let sb_flags = if fs.writable() { sb_flags } else { sb_flags | vfs::superblock::SB_RDONLY };
        let f: Arc<dyn vfs::fs::FileSystem> = fs;
        mounted(ty, f, Some(root), overlayfs::FS_NAME, sb_flags)
    }
    for name in [overlayfs::FS_NAME, overlayfs::FS_NAME_LEGACY] {
        let _ = register_fs(FsType::new(name, overlayfs::OVERLAYFS_SUPER_MAGIC,
            FsFlags::FS_USERNS_MOUNT,
            Box::new(|ty, _s: Option<&str>, _t: &str, d: &str, f: u64,
                      _p: &[vfs::fs::FsParameter]| -> R { overlay_ctor(ty, d, f) })));
    }
    // exFAT is what large removable media carry: FAT cannot hold a file over
    // four gigabytes, so every camera card and external drive sold for use
    // between machines is this. It is a SEPARATE type over a separate
    // implementation, not a wider FAT — allocation goes through a bitmap and a
    // name is a checksummed set of entries.
    let _ = register_fs(FsType::new("exfat", exfatfs::EXFAT_SUPER_MAGIC, FsFlags::FS_REQUIRES_DEV,
        Box::new(|ty, source: Option<&str>, _t: &str, d: &str, sb_flags: u64,
                  _p: &[vfs::fs::FsParameter]| -> R {
        let source = source.ok_or(vfs::VfsError::Enoent)?;
        let write = sb_flags & vfs::superblock::SB_RDONLY == 0;
        let access = vfs::MAY_READ | if write { vfs::MAY_WRITE } else { 0 };
        let (dev, _dev_t) = resolve_block_source(source, access)?;
        // The option string decides which owner and mode every entry presents
        // with and which instant a timestamp carrying no offset of its own
        // means, so a string that cannot be honoured fails the mount rather
        // than mounting something that ignores it.
        let opts = exfatfs::opts::parse(exfatfs::Options::defaults(), d)
            .map_err(exfatfs::mount::errno_to_vfs)?;
        let fs = exfatfs::ExfatFs::open_with(dev, source, write, opts)?;
        // A mount that asked to write and could not mounts READ-ONLY rather
        // than failing, and the superblock says so; reporting writable when
        // the medium is not fails every write at the first one instead of at
        // the mount.
        let sb_flags = if fs.is_writable() { sb_flags } else { sb_flags | vfs::superblock::SB_RDONLY };
        let root = fs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = fs;
        mounted(ty, fs, Some(root), source, sb_flags)
    })));
    // NTFS is what a disk shared with Windows carries. A volume left DIRTY
    // mounts READ-ONLY here rather than read-write with a warning, which is
    // the opposite of what FAT and exFAT do and is deliberate: this filesystem
    // has a journal, and writing to a volume whose journal has not been
    // replayed loses whatever the journal was about to redo.
    let _ = register_fs(FsType::new("ntfs3", ntfs3::NTFS_SUPER_MAGIC, FsFlags::FS_REQUIRES_DEV,
        Box::new(|ty, source: Option<&str>, _t: &str, d: &str, sb_flags: u64,
                  _p: &[vfs::fs::FsParameter]| -> R {
        let source = source.ok_or(vfs::VfsError::Enoent)?;
        let write = sb_flags & vfs::superblock::SB_RDONLY == 0;
        let access = vfs::MAY_READ | if write { vfs::MAY_WRITE } else { 0 };
        let (dev, _dev_t) = resolve_block_source(source, access)?;
        let opts = ntfs3::opts::parse(ntfs3::Options::defaults(), d)
            .map_err(ntfs3::mount::errno_to_vfs)?;
        let fs = ntfs3::NtfsFs::open_with(dev, source, write, opts)?;
        super::fs_surfaces::ntfs3_publish_surfaces(&fs);
        let sb_flags = if fs.is_writable() { sb_flags } else { sb_flags | vfs::superblock::SB_RDONLY };
        let root = fs.root_inode()?;
        let fs: Arc<dyn vfs::fs::FileSystem> = fs;
        mounted(ty, fs, Some(root), source, sb_flags)
    })));
    // F2FS is a log-structured filesystem: it never overwrites in place, so a
    // volume whose last mount did not checkpoint carries writes the checkpoint
    // does not name. Recovery replays those at mount from the node chain, which
    // is why this mounts read-write on an unclean volume where NTFS above will
    // not — replay is the designed path here, not a repair.
    let _ = register_fs(FsType::new("f2fs", f2fs::F2FS_SUPER_MAGIC, FsFlags::FS_REQUIRES_DEV,
        Box::new(|ty, source: Option<&str>, _t: &str, d: &str, sb_flags: u64,
                  _p: &[vfs::fs::FsParameter]| -> R {
        let source = source.ok_or(vfs::VfsError::Enoent)?;
        let write = sb_flags & vfs::superblock::SB_RDONLY == 0;
        let access = vfs::MAY_READ | if write { vfs::MAY_WRITE } else { 0 };
        let (dev, _dev_t) = resolve_block_source(source, access)?;
        let opts = f2fs::opts::parse(f2fs::Options::defaults(), d)
            .map_err(f2fs::errno_to_vfs)?;
        let fs = f2fs::F2fs::open_with(dev, source, write, opts)?;
        super::fs_surfaces::f2fs_publish_surfaces(&fs);
        let sb_flags = if fs.is_writable() { sb_flags } else { sb_flags | vfs::superblock::SB_RDONLY };
        let root = fs.root_inode()?;
        let quota_fs = Arc::clone(&fs);
        let fs: Arc<dyn vfs::fs::FileSystem> = fs;
        let sb = mounted(ty, fs, Some(root), source, sb_flags)?;
        // `quotactl` resolves a record through the hooks a filesystem installs
        // on its superblock. Without them every command answers ESRCH on a
        // volume whose quota files are present and being accounted, so this is
        // what makes the volume's own quota machinery reachable at all.
        f2fs::mount::quota::install(&sb, &quota_fs);
        Ok(sb)
    })));
    // procfs declares the three options it ENFORCES (`gid=`, `hidepid=`,
    // `subset=`) and builds a per-mount root that carries them. The table was an
    // empty list while the root inode was a process-global singleton — there was
    // nowhere for a mount's own answer to live, so declaring a name would have
    // claimed a confinement nothing applied. Each name is here because its
    // enforcement is, and `procfs::fs_info` holds both halves so they cannot
    // drift: an option in the table with no enforcement fails that module's own
    // table-versus-parse test.
    let _ = register_fs(FsType::with_parameters("proc", PROC_SUPER_MAGIC, FsFlags::FS_USERNS_MOUNT | FsFlags::FS_USERNS_MOUNT_RESTRICTED | FsFlags::FS_DISALLOW_NOTIFY_PERM, Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        // Which argument carries the options is `procfs::fs_info`'s decision and
        // is hosted-tested there: `mount(2)` puts them in the DATA BLOB, while
        // this slice holds only pinned open files. Reading the slice here made
        // every option silently do nothing.
        let info = procfs::fs_info::info_for_mount(d, p)?;
        let user_ns = sched::live::current()
            .and_then(|task| task.namespace_owner(namespace_identity::NamespaceKind::User))
            .unwrap_or_else(|| namespace_identity::initial(namespace_identity::NamespaceKind::User));
        mounted(ty, Arc::new(procfs::fs_impl::ProcfsFs::new(info, user_ns)), None, "proc", sb_flags)
    }), Some(procfs::fs_info::PROC_PARAMS)));
    // sysfs's context operations carry no `parse_param`, so every key in a
    // sysfs option string reaches the unknown-parameter report. `Some(&[])`
    // says that in a form the admission path can check; the `ro`/`rw`/`sync`
    // family never reaches it, being superblock flags the VFS claims first.
    let _ = register_fs(FsType::with_parameters("sysfs", SYSFS_MAGIC, FsFlags::FS_USERNS_MOUNT | FsFlags::FS_USERNS_MOUNT_RESTRICTED, Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        crate::fsmount_pseudo_params::admit_no_params(d, p)?;
        mounted(ty, Arc::new(sysfs::SysfsFs), None, "sysfs", sb_flags)
    }), Some(kernfs::mount_opts::NO_PARAMETERS)));
    // debugfs owns its parse because it is the one type here that SWALLOWS a
    // key it does not know: the reference turns the "no such parameter" answer
    // into success, so a strict table would fail mounts it completes. Its
    // `uid=`/`gid=`/`mode=` still land on the debugfs tree root, and a declared
    // key with a bad value still fails — see `tracefs::context`.
    let _ = register_fs(FsType::with_context_parameters(
        "debugfs", DEBUGFS_MAGIC, FsFlags::empty(),
        Arc::new(tracefs::context::DebugfsContextOps), tracefs::mount_opts::DEBUGFS_PARAMS,
    ));
    // tracefs declares and enforces the same three, and unlike debugfs it
    // REFUSES a key it does not declare.
    let _ = register_fs(FsType::with_parameters("tracefs", TRACEFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        tracefs::mount_opts::mount_tracefs(d, p)?;
        mounted(ty, Arc::new(tracefs::fs_impl::TracefsFs), None, "tracefs", sb_flags)
    }), Some(tracefs::mount_opts::TRACEFS_PARAMS)));
    // A generic-tree type whose reference declares NO parameter. The empty
    // table is the declaration; the constructor refuses anything in the blob.
    macro_rules! pseudo_no_params { ($name:literal, $magic:expr) => {
        let _ = register_fs(FsType::with_parameters($name, $magic, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> =
                crate::fsmount_pseudo_params::pseudo_no_params($name, $magic, d, p)?;
            mounted(ty, fs, None, $name, sb_flags)
        }), Some(kernfs::mount_opts::NO_PARAMETERS)));
    }; }
    // A generic-tree type whose options name its root's owner and mode. Each
    // mount builds its own tree, so the stamp is per instance.
    macro_rules! pseudo_root_attr { ($name:literal, $magic:expr, $params:expr) => {
        let _ = register_fs(FsType::with_parameters($name, $magic, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> =
                crate::fsmount_pseudo_params::pseudo_with_root_attr($name, $magic, $params, d, p)?;
            mounted(ty, fs, None, $name, sb_flags)
        }), Some($params)));
    }; }
    pseudo_no_params!("securityfs", SECURITYFS_MAGIC);
    // selinuxfs declares no parameter, and unlike the generic pseudo types
    // its mount root is the policy interface's OWN tree — a fresh empty tree
    // would mount and then answer every probe userspace makes with ENOENT.
    let _ = register_fs(FsType::with_parameters("selinuxfs", SELINUXFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        crate::fsmount_pseudo_params::admit_no_params(d, p)?;
        mounted(ty, Arc::new(selinuxfs::SelinuxFs), None, "selinuxfs", sb_flags)
    }), Some(kernfs::mount_opts::NO_PARAMETERS)));
    // efivarfs takes `uid=`/`gid=` and NO `mode=`; the two-name table is why
    // `mount -t efivarfs -o mode=700` fails and the same line on tracefs does not.
    pseudo_root_attr!("efivarfs", EFIVARFS_MAGIC, crate::fsmount_pseudo_params::EFIVARFS_PARAMS);
    // pstore declares its one byte-count option and CONSUMES it: the value
    // bounds how much of the kernel log the next captured record carries, so
    // a mount naming it changes what a crash report contains. The mount also
    // publishes whatever records the persistent-RAM backend recovered from the
    // previous boot — a file per record, unlinking one erases it.
    //
    // The table does not make the mount strict: pstore's admission swallows
    // every negative answer, so `-o kmsg_bytes=rubbish` and `-o nosuchopt`
    // both mount and simply change nothing, which is what the reference does
    // and what no other type registered here does.
    let _ = register_fs(FsType::with_parameters("pstore", PSTOREFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = pstore::mount(d, p)?;
        mounted(ty, fs, None, "pstore", sb_flags)
    }), Some(pstore::PSTORE_PARAMS)));
    // bpffs declares the reference's seven. `uid`/`gid`/`mode` land on the
    // instance root here; the four `delegate_*` values name what a bpf TOKEN
    // created from this mount may do, which the token subsystem answers, not
    // the mount.
    pseudo_root_attr!("bpf", BPF_FS_MAGIC, crate::fsmount_pseudo_params::BPF_PARAMS);
    let _ = register_fs(FsType::with_parameters("configfs", CONFIGFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        tracefs::mount_opts::mount_configfs(d, p)?;
        mounted(ty, Arc::new(tracefs::fs_impl::ConfigfsFs), None, "configfs", sb_flags)
    }), Some(tracefs::mount_opts::CONFIGFS_PARAMS)));
    pseudo_no_params!("fusectl", FUSE_CTL_MAGIC);
    pseudo_no_params!("mqueue", MQUEUE_MAGIC);
    // hugetlbfs registers itself: its constructor, its seven-name table and
    // the pool behind them all live in the filesystem, so the type's whole
    // option surface is described where it is enforced.
    let _ = ::fs::hugetlbfs::register();
    let _ = register_fs(FsType::with_context_parameters(
        "autofs", AUTOFS_SUPER_MAGIC, FsFlags::empty(),
        Arc::new(::fs::autofs::AutofsContextOps), ::fs::autofs::AUTOFS_PARAMS,
    ));
    // binfmt_misc's context operations carry no `parse_param` either: it keys
    // its instance on the caller's user namespace, not on an option.
    let _ = register_fs(FsType::with_parameters("binfmt_misc", BINFMTFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        crate::fsmount_pseudo_params::admit_no_params(d, p)?;
        let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::binfmt_misc::BinfmtMiscFs::new();
        mounted(ty, fs, None, "binfmt_misc", sb_flags)
    }), Some(kernfs::mount_opts::NO_PARAMETERS)));
    // virtiofs is the same host share as 9P through a different protocol: a
    // FUSE superblock whose courier is a virtio queue rather than a daemon on
    // `/dev/fuse`. It reports itself as `virtiofs`, not as `fuse`, because
    // `/proc/mounts` is how userspace decides what a mount is.
    let _ = register_fs(FsType::with_parameters(
        ::fs::fuse::virtiofs::VIRTIOFS_FS_NAME, FUSE_SUPER_MAGIC, FsFlags::empty(),
        Box::new(|ty, source: Option<&str>, _t: &str, _d: &str, sb_flags: u64,
                  _p: &[vfs::fs::FsParameter]| -> R {
            let tag = source.ok_or(vfs::VfsError::Enoent)?;
            let (uid, gid) = caller_fsids();
            let fs = ::fs::fuse::virtiofs::mount_by_tag(tag, uid, gid)?;
            let root = fs.root_inode();
            let fs: Arc<dyn vfs::fs::FileSystem> = fs;
            mounted(ty, fs, Some(root), tag, sb_flags)
        }), Some(::fs::fuse::virtiofs::VIRTIOFS_PARAMS)));

    // 9P is how a hypervisor exports a HOST directory into this guest, so a
    // file can move in or out without rebuilding an image. The mount source is
    // the transport's device name — a virtio mount tag — not a block device,
    // which is why the type carries no `FS_REQUIRES_DEV`.
    let _ = register_fs(FsType::with_parameters(
        ::fs::ninep_fs::NINEP_FS_NAME, ninep::V9FS_MAGIC, FsFlags::FS_ALLOW_IDMAP,
        Box::new(|ty, source: Option<&str>, _t: &str, d: &str, sb_flags: u64,
                  _p: &[vfs::fs::FsParameter]| -> R {
            let source = source.ok_or(vfs::VfsError::Enoent)?;
            let fs = ::fs::ninep_fs::mount_9p(source, d, caller_fsuid())?;
            super::fs_surfaces::ninep_claim_subsys();
            let root = fs.root_inode();
            let fs: Arc<dyn vfs::fs::FileSystem> = fs;
            mounted(ty, fs, Some(root), source, sb_flags)
        }), Some(::fs::ninep_fs::NINEP_PARAMS)));

    let _ = register_fs(FsType::with_context_parameters(
        "fuse", FUSE_SUPER_MAGIC, FsFlags::empty(),
        Arc::new(::fs::fuse::FuseContextOps), ::fs::fuse::FUSE_PARAMS,
    ));
    // devpts declares the six options the reference does and ENFORCES all of
    // them: `uid=`/`gid=`/`mode=` stamp every pty slave node, `ptmxmode=` the
    // instance `ptmx`, `max=` bounds index allocation, and `newinstance` is the
    // reference's own accepted no-op. systemd passes
    // `-o gid=5,mode=620,ptmxmode=000` on EVERY boot, and all of it used to be
    // discarded — slaves were born 0o620 by a hardcode that happened to match
    // the requested mode, with no owner set at all.
    let _ = register_fs(FsType::with_parameters("devpts", devpts::DEVPTS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        let opts = devpts::mount_opts::opts_for_mount(d, p)?;
        let dfs = devpts::DevptsFs::new(opts);
        let fs: Arc<dyn vfs::fs::FileSystem> = dfs;
        mounted(ty, fs, None, "devpts", sb_flags)
    }), Some(devpts::mount_opts::DEVPTS_PARAMS)));
    // devtmpfs has no option table of its own: it borrows the parse of the
    // filesystem it is built on (tmpfs) and then hands back the ONE device
    // tree, which every mount of it shares. So the table admits exactly what a
    // tmpfs mount admits — a key outside it fails, as it does in the reference
    // — while a size or an owner cannot re-shape a tree that already exists and
    // is shared, and the reference does not let it either.
    let _ = register_fs(FsType::with_parameters("devtmpfs", DEVTMPFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        // Borrowing the table means borrowing its VALUE grammar too: without
        // this, `-o size=64mb` — which a real tmpfs mount refuses — was
        // admitted here on the key alone.
        ::fs::tmpfs::validate_opts(d)?;
        let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(devfs::DevfsFs);
        mounted(ty, fs, None, "devtmpfs", sb_flags)
    }), Some(::fs::tmpfs::TMPFS_PARAMS)));
    // cgroup2 declares the six flags the reference does. They are hierarchy-wide
    // (Linux keeps them in `cgrp_dfl_root.flags`, not per mount), so a mount
    // naming one turns it on for the whole default hierarchy — and a remount
    // ORs, never clears, so a second mount cannot silently drop a delegation
    // boundary. Every name is declared because omitting one would fail a mount
    // the reference accepts; which of them this kernel can act on is recorded
    // per flag on `cgroup::root_flags::RootFlag`.
    let _ = register_fs(FsType::with_parameters("cgroup2", CGROUP2_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, d: &str, sb_flags, p: &[vfs::fs::FsParameter]| -> R {
        let flags = cgroup::root_flags::flags_for_mount(d, p)?;
        cgroup::state::add_root_flags(flags);
        let (fs, root) = cgroup::realize_tree();
        mounted(ty, fs, Some(root), "cgroup2", sb_flags)
    }), Some(cgroup::root_flags::CGROUP2_PARAMS)));
}
