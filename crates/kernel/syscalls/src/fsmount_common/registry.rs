#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;

use core::sync::atomic::AtomicU64;
use sync::{Spinlock, TaskList as LockClass};
use vfs::FileType;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// # C: O(1)
fn resolve_ext4_source(
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

fn register_filesystems() {
    use vfs::fs::{superblock_from_filesystem, FsFlags, FsType, register_fs};
    type R = vfs::fs::KResult<Arc<vfs::SuperBlock>>;

    // One-time: give the cgroup crate its view of the caller's cgroup namespace
    // so `nsdelegate` can be enforced.
    cgroup::state::set_cgroup_ns_root_hook(cgroup_ns_root_of_caller);

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
        let (dev, dev_t) = resolve_ext4_source(source, access)?;
        // Honour the `-o usrquota/grpquota/prjquota/usrjquota=/grpjquota=/
        // jqfmt=/quota/noquota` option string. Was: dropped on the floor, so
        // every quota mount option was silently accepted and did nothing.
        let fs: Arc<dyn vfs::fs::FileSystem> = ext4::rootfs::Ext4Mount::open_with_data(dev, dev_t, d)?;
        mounted(ty, fs, None, source, sb_flags)
    }), Some(ext4::rootfs::EXT4_PARAMS)));
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
    let _ = register_fs(FsType::with_parameters("devtmpfs", DEVTMPFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
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
