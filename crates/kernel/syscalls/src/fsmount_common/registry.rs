#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;

use core::sync::atomic::AtomicU64;
use sync::{Spinlock, TaskList as LockClass};
use syscall::errno::Errno;
use vfs::FileType;

pub(crate) static NEXT_FSCTX_INO: AtomicU64 = AtomicU64::new(0x4600_0000);

/// # C: O(1)
pub(crate) fn require_sys_admin() -> Option<i64> {
    match sched::live::current() {
        Some(c) if c.has_cap(sched::cap::SYS_ADMIN) => None,
        _ => Some(-(Errno::Eperm.as_i32() as i64)),
    }
}

/// # C: O(1)
pub(crate) fn fstype_ok(t: &str) -> bool {
    matches!(t,
        "tmpfs" | "ramfs" | "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup2"
        | "ext4"
        | "securityfs" | "efivarfs" | "pstore" | "bpf" | "configfs" | "debugfs"
        | "tracefs" | "fuse" | "fusectl" | "mqueue" | "hugetlbfs" | "autofs" | "binfmt_misc")
}

fn source_disk_name(source: &str) -> &str {
    source.rsplit('/').next().unwrap_or(source)
}

fn resolve_ext4_source(source: &str) -> Option<(Arc<dyn block::BlockDevice>, Option<u64>)> {
    if source.starts_with('/') {
        if let Ok(vp) = crate::pathresolve::resolve_path_raw(source, false) {
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
    if let Some(d) = block::registry::by_name(name) {
        return Some((d.dev.clone(), block::registry::dev_t_of(&d.name, d.index).map(|d| d as u64)));
    }
    block::registry::by_serial(name).map(|dev| (dev, None))
}

const SECURITYFS_MAGIC: u64 = 0x7363_6673;
const EFIVARFS_MAGIC: u64 = 0xde5e_81e4;
const PSTOREFS_MAGIC: u64 = 0x6165_676C;
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
const FUSE_CTL_MAGIC: u64 = fs::fuse::FUSE_SUPER_MAGIC;
const FUSE_SUPER_MAGIC: u64 = fs::fuse::FUSE_SUPER_MAGIC;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
const EXT4_MAGIC: u64 = 0xef53;
const CGROUP2_MAGIC: u64 = cgroup::CGROUP2_SUPER_MAGIC;
const DEVTMPFS_MAGIC: u64 = vfs::uapi::TMPFS_SUPER_MAGIC;

static FS_TYPES_REGISTERED: Spinlock<bool, LockClass> = Spinlock::new(false);

/// # C: O(N) once.
pub fn ensure_filesystems_registered() {
    let mut done = FS_TYPES_REGISTERED.lock();
    if *done { return; }
    register_filesystems();
    *done = true;
}

fn register_filesystems() {
    use vfs::fs::{superblock_from_filesystem, FsFlags, FsType, register_fs};
    type R = vfs::fs::KResult<Arc<vfs::SuperBlock>>;

    fn mounted(ty: Arc<dyn vfs::FileSystemType>, fs: Arc<dyn vfs::fs::FileSystem>, root: Option<vfs::InodeRef>,
        s_id: &str) -> R {
        superblock_from_filesystem(ty, fs, root, s_id.to_string())
    }

    fn tmpfs_ctor(ty: Arc<dyn vfs::FileSystemType>, _s: Option<&str>, target: &str, d: &str) -> R {
        // Honour the `-o mode=/uid=/gid=/size=/nr_inodes=` option string: the
        // per-user runtime dir (systemd-user-runtime-dir) mounts /run/user/UID
        // mode 0700 owned by UID:UID, and pam_systemd/`systemd --user` reject a
        // root-owned 0755 runtime dir. Was: option string dropped → every
        // tmpfs mounted root:root 0755 half-RAM (real-Linux divergence).
        let tfs = ::fs::tmpfs::TmpfsFs::from_mount_data(target.to_string(), d);
        let root = tfs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = tfs;
        mounted(ty, fs, Some(root), target)
    }
    let _ = register_fs(FsType::new("tmpfs", 0, FsFlags::empty(), Box::new(tmpfs_ctor)));
    let _ = register_fs(FsType::new("ramfs", 0, FsFlags::empty(), Box::new(tmpfs_ctor)));
    let _ = register_fs(FsType::new("ext4", EXT4_MAGIC, FsFlags::FS_REQUIRES_DEV, Box::new(|ty, source: Option<&str>, _t: &str, _d: &str| -> R {
        let source = source.ok_or(vfs::VfsError::Enoent)?;
        let (dev, dev_t) = resolve_ext4_source(source).ok_or(vfs::VfsError::Enoent)?;
        let fs: Arc<dyn vfs::fs::FileSystem> = ext4::rootfs::Ext4Mount::open_with_dev(dev, dev_t).map_err(|_| vfs::VfsError::Einval)?;
        mounted(ty, fs, None, source)
    })));
    let _ = register_fs(FsType::new("proc", 0, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        mounted(ty, Arc::new(procfs::fs_impl::ProcfsFs), None, "proc")
    })));
    let _ = register_fs(FsType::new("sysfs", 0, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        mounted(ty, Arc::new(sysfs::SysfsFs), None, "sysfs")
    })));
    let _ = register_fs(FsType::new("debugfs", 0, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        mounted(ty, Arc::new(tracefs::fs_impl::DebugfsFs), None, "debugfs")
    })));
    let _ = register_fs(FsType::new("tracefs", 0, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        mounted(ty, Arc::new(tracefs::fs_impl::TracefsFs), None, "tracefs")
    })));
    macro_rules! pseudo { ($name:literal, $magic:expr) => {
        let _ = register_fs(FsType::new($name, $magic, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = kernfs::PseudoFs::new($name, $magic);
            mounted(ty, fs, None, $name)
        })));
    }; }
    pseudo!("securityfs", SECURITYFS_MAGIC);
    pseudo!("efivarfs", EFIVARFS_MAGIC);
    pseudo!("pstore", PSTOREFS_MAGIC);
    pseudo!("bpf", BPF_FS_MAGIC);
    let _ = register_fs(FsType::new("configfs", 0, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        mounted(ty, Arc::new(tracefs::fs_impl::ConfigfsFs), None, "configfs")
    })));
    pseudo!("fusectl", FUSE_CTL_MAGIC);
    pseudo!("mqueue", MQUEUE_MAGIC);
    pseudo!("hugetlbfs", HUGETLBFS_MAGIC);
    let _ = register_fs(FsType::new("autofs", 0, FsFlags::empty(), Box::new(|ty, _, _, data: &str| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::autofs::AutofsFs::new(data)?;
        mounted(ty, fs, None, "autofs")
    })));
    let _ = register_fs(FsType::new("binfmt_misc", 0, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::binfmt_misc::BinfmtMiscFs::new();
        mounted(ty, fs, None, "binfmt_misc")
    })));
    let _ = register_fs(FsType::new("fuse", FUSE_SUPER_MAGIC, FsFlags::empty(), Box::new(|ty, _s: Option<&str>, _t: &str, data: &str| -> R {
        let (fs, root) = ::fs::fuse::mount_from_data(data)?;
        mounted(ty, fs, Some(root), "fuse")
    })));
    let _ = register_fs(FsType::new("devpts", devpts::DEVPTS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = devpts::devpts_fs();
        mounted(ty, fs, None, "devpts")
    })));
    let _ = register_fs(FsType::new("devtmpfs", DEVTMPFS_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(devfs::DevfsFs);
        mounted(ty, fs, None, "devtmpfs")
    })));
    let _ = register_fs(FsType::new("cgroup2", CGROUP2_MAGIC, FsFlags::empty(), Box::new(|ty, _, _, _| -> R {
        let (fs, root) = cgroup::realize_tree();
        mounted(ty, fs, Some(root), "cgroup2")
    })));
}
