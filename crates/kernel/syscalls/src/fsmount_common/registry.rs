#![cfg(target_os = "oxide-kernel")]

use alloc::boxed::Box;
use alloc::string::{String, ToString};
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
        | "tracefs" | "fusectl" | "mqueue" | "hugetlbfs" | "autofs" | "binfmt_misc")
}

fn source_disk_name(source: &str) -> &str {
    source.rsplit('/').next().unwrap_or(source)
}

fn resolve_ext4_source(source: &str) -> Option<(Arc<dyn block::BlockDevice>, Option<u64>)> {
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
    if let Some(d) = block::registry::by_name(name) {
        return Some((d.dev.clone(), Some(block::registry::dev_t_of(&d.name, d.index) as u64)));
    }
    block::registry::by_serial(name).map(|dev| (dev, None))
}

/// # C: O(1)
pub(crate) fn fstype_converted(t: &str) -> bool {
    matches!(t,
        "proc" | "sysfs" | "debugfs" | "tracefs" | "ext4"
        | "devtmpfs"
        | "securityfs" | "efivarfs" | "pstore" | "bpf"
        | "configfs" | "fusectl" | "mqueue" | "hugetlbfs"
        | "tmpfs" | "ramfs"
        | "cgroup2")
}

const SECURITYFS_MAGIC: u64 = 0x7363_6673;
const EFIVARFS_MAGIC: u64 = 0xde5e_81e4;
const PSTOREFS_MAGIC: u64 = 0x6165_676C;
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
const CONFIGFS_MAGIC: u64 = 0x6265_6570;
const FUSE_CTL_MAGIC: u64 = 0x6573_5546;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
const EXT4_MAGIC: u64 = 0xef53;
const CGROUP2_MAGIC: u64 = 0x6367_7270;
const DEVTMPFS_MAGIC: u64 = 0x0102_1994;

static FS_TYPES_REGISTERED: Spinlock<bool, LockClass> = Spinlock::new(false);

/// # C: O(N) once.
pub(crate) fn ensure_filesystems_registered() {
    let mut done = FS_TYPES_REGISTERED.lock();
    if *done { return; }
    register_filesystems();
    *done = true;
}

fn register_filesystems() {
    use vfs::fs::{FsFlags, FsType, MountSpec, register_fs};
    type R = vfs::fs::KResult<MountSpec>;

    fn tmpfs_ctor(_s: &str, target: &str, _d: &str) -> R {
        let tfs = ::fs::tmpfs::TmpfsFs::new(target.to_string());
        let root = tfs.root_inode();
        let fs: Arc<dyn vfs::fs::FileSystem> = tfs;
        Ok(MountSpec { fs, bind_root: Some(root), strict: false })
    }
    let _ = register_fs(FsType::new("tmpfs", 0, FsFlags::empty(), Box::new(tmpfs_ctor)));
    let _ = register_fs(FsType::new("ramfs", 0, FsFlags::empty(), Box::new(tmpfs_ctor)));
    let _ = register_fs(FsType::new("ext4", EXT4_MAGIC, FsFlags::FS_REQUIRES_DEV, Box::new(|source: &str, _t: &str, _d: &str| -> R {
        let (dev, dev_t) = resolve_ext4_source(source).ok_or(vfs::VfsError::Enoent)?;
        let fs: Arc<dyn vfs::fs::FileSystem> = ext4::rootfs::Ext4Mount::open_with_dev(dev, dev_t).map_err(|_| vfs::VfsError::Einval)?;
        Ok(MountSpec { fs, bind_root: None, strict: true })
    })));
    let _ = register_fs(FsType::new("proc", 0, FsFlags::empty(), Box::new(|_, _, _| -> R {
        Ok(MountSpec { fs: Arc::new(procfs::fs_impl::ProcfsFs), bind_root: None, strict: false })
    })));
    let _ = register_fs(FsType::new("sysfs", 0, FsFlags::empty(), Box::new(|_, _, _| -> R {
        Ok(MountSpec { fs: Arc::new(sysfs::SysfsFs), bind_root: None, strict: false })
    })));
    let _ = register_fs(FsType::new("debugfs", 0, FsFlags::empty(), Box::new(|_, _, _| -> R {
        Ok(MountSpec { fs: Arc::new(tracefs::fs_impl::DebugfsFs), bind_root: None, strict: false })
    })));
    let _ = register_fs(FsType::new("tracefs", 0, FsFlags::empty(), Box::new(|_, _, _| -> R {
        Ok(MountSpec { fs: Arc::new(tracefs::fs_impl::TracefsFs), bind_root: None, strict: false })
    })));
    macro_rules! pseudo { ($name:literal, $magic:expr) => {
        let _ = register_fs(FsType::new($name, $magic, FsFlags::empty(), Box::new(|_, _, _| -> R {
            let fs: Arc<dyn vfs::fs::FileSystem> = kernfs::PseudoFs::new($name, $magic);
            Ok(MountSpec { fs, bind_root: None, strict: true })
        })));
    }; }
    pseudo!("securityfs", SECURITYFS_MAGIC);
    pseudo!("efivarfs", EFIVARFS_MAGIC);
    pseudo!("pstore", PSTOREFS_MAGIC);
    pseudo!("bpf", BPF_FS_MAGIC);
    pseudo!("configfs", CONFIGFS_MAGIC);
    pseudo!("fusectl", FUSE_CTL_MAGIC);
    pseudo!("mqueue", MQUEUE_MAGIC);
    pseudo!("hugetlbfs", HUGETLBFS_MAGIC);
    let _ = register_fs(FsType::new("autofs", 0, FsFlags::empty(), Box::new(|_, _, data: &str| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::autofs::AutofsFs::new(data)?;
        Ok(MountSpec { fs, bind_root: None, strict: true })
    })));
    let _ = register_fs(FsType::new("binfmt_misc", 0, FsFlags::empty(), Box::new(|_, _, _| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = ::fs::binfmt_misc::BinfmtMiscFs::new();
        Ok(MountSpec { fs, bind_root: None, strict: true })
    })));
    let _ = register_fs(FsType::new("devpts", devpts::DEVPTS_MAGIC, FsFlags::empty(), Box::new(|_, _, _| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = devpts::devpts_fs();
        Ok(MountSpec { fs, bind_root: None, strict: false })
    })));
    let _ = register_fs(FsType::new("devtmpfs", DEVTMPFS_MAGIC, FsFlags::empty(), Box::new(|_, _, _| -> R {
        let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(devfs::DevfsFs);
        Ok(MountSpec { fs, bind_root: None, strict: false })
    })));
    let _ = register_fs(FsType::new("cgroup2", CGROUP2_MAGIC, FsFlags::empty(), Box::new(|_, _, _| -> R {
        let (fs, root) = cgroup::realize_tree();
        Ok(MountSpec { fs, bind_root: Some(root), strict: false })
    })));
}
