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
/// `FUSE_CTL_SUPER_MAGIC` (Linux fs/fuse/control.c) — the fuse CONTROL
/// filesystem mounted at `/sys/fs/fuse/connections`. Distinct from
/// `FUSE_SUPER_MAGIC` (0x65735546) by one nibble; reporting the latter makes
/// every `statfs`-based fuse probe misidentify the control mount.
const FUSE_CTL_MAGIC: u64 = 0x6573_5543;
const FUSE_SUPER_MAGIC: u64 = fs::fuse::FUSE_SUPER_MAGIC;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
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
/// So a table is published only where the option string is actually delivered
/// to the backend — `tmpfs`, `ramfs`, `ext4`, `autofs`, `fuse` — and it lists
/// what the reference accepts, in full, INCLUDING names not yet acted on.
/// Listing a name we ignore is honest about the mount succeeding; omitting it
/// would make a mount the reference accepts fail outright, which is worse.
///
/// Every other type here takes `None`: its constructor discards the data
/// string entirely, so it has no option surface to describe. `None` keeps the
/// pre-table behaviour exactly — the blob travels whole and nothing in it is
/// refused. `devpts` and `cgroup2` are no longer in that set: each publishes
/// and consumes its reference parameter table below.
///
/// `proc` is the exception, and `Some(&[])` is a real declaration rather than
/// a default — see its registration below.
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
        let tfs = ::fs::tmpfs::TmpfsFs::from_mount_data(target.to_string(), d);
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
        let rfs = ::fs::tmpfs::TmpfsFs::ramfs_from_mount_data(d);
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
    let _ = register_fs(FsType::new("sysfs", SYSFS_MAGIC, FsFlags::FS_USERNS_MOUNT | FsFlags::FS_USERNS_MOUNT_RESTRICTED, Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        mounted(ty, Arc::new(sysfs::SysfsFs), None, "sysfs", sb_flags)
    })));
    let _ = register_fs(FsType::new("debugfs", DEBUGFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        mounted(ty, Arc::new(tracefs::fs_impl::DebugfsFs), None, "debugfs", sb_flags)
    })));
    let _ = register_fs(FsType::new("tracefs", TRACEFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        mounted(ty, Arc::new(tracefs::fs_impl::TracefsFs), None, "tracefs", sb_flags)
    })));
    macro_rules! pseudo { ($name:literal, $magic:expr) => {
        let _ = register_fs(FsType::new($name, $magic, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = kernfs::PseudoFs::new($name, $magic);
            mounted(ty, fs, None, $name, sb_flags)
        })));
    }; }
    pseudo!("securityfs", SECURITYFS_MAGIC);
    pseudo!("efivarfs", EFIVARFS_MAGIC);
    pseudo!("pstore", PSTOREFS_MAGIC);
    pseudo!("bpf", BPF_FS_MAGIC);
    let _ = register_fs(FsType::new("configfs", CONFIGFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        mounted(ty, Arc::new(tracefs::fs_impl::ConfigfsFs), None, "configfs", sb_flags)
    })));
    pseudo!("fusectl", FUSE_CTL_MAGIC);
    pseudo!("mqueue", MQUEUE_MAGIC);
    pseudo!("hugetlbfs", HUGETLBFS_MAGIC);
    let _ = register_fs(FsType::with_context_parameters(
        "autofs", AUTOFS_SUPER_MAGIC, FsFlags::empty(),
        Arc::new(::fs::autofs::AutofsContextOps), ::fs::autofs::AUTOFS_PARAMS,
    ));
    let _ = register_fs(FsType::new("binfmt_misc", BINFMTFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::binfmt_misc::BinfmtMiscFs::new();
        mounted(ty, fs, None, "binfmt_misc", sb_flags)
    })));
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
    let _ = register_fs(FsType::new("devtmpfs", DEVTMPFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _, sb_flags, _p: &[vfs::fs::FsParameter]| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(devfs::DevfsFs);
        mounted(ty, fs, None, "devtmpfs", sb_flags)
    })));
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
