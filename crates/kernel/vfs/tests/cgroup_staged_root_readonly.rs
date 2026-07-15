//! Regression for the systemd cgroup EROFS boot blocker: recursive RO applied
//! to `/run/systemd/mount-rootfs` must hit only the staged clone tree. The live
//! `/sys/fs/cgroup/cgroup.subtree_control` remains on the original RW cgroup
//! mount, while the staged path resolves through the cloned cgroup mount and is
//! `MNT_RDONLY`/`EROFS` shaped.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::mount::{MNT_RDONLY, Propagation};
use vfs::{
    Cred, Dentry, File, FileOps, FileType, InodeOps, InodeRef, KResult, LookupFlags, OpenFlags,
    VfsError, default_file_ops, default_inode_ops, mk_mode,
};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT_INO: AtomicU64 = AtomicU64::new(0xC600);

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(dir(NEXT_INO.fetch_add(1, Ordering::Relaxed)))
    }
}
fn dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops()).build()
}

struct RootFs;
impl FileSystem for RootFs {
    fn name(&self) -> &str { "rootfs_cgroup_ro_test" }
    fn root(&self) -> Option<InodeRef> { Some(dir(0xC610_0001)) }
}

struct CgFileOps;
impl FileOps for CgFileOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

fn cgroup_file() -> InodeRef {
    InodeBuilder::new(0xC610_1001, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(CgFileOps)).build()
}

struct CgDirOps;
impl InodeOps for CgDirOps {
    fn lookup(&self, _inode: &Inode, n: &str) -> KResult<InodeRef> {
        if n == "cgroup.subtree_control" { Ok(cgroup_file()) } else { Err(VfsError::Enoent) }
    }
}
fn cgroup_root() -> InodeRef {
    InodeBuilder::new(0xC610_1000, mk_mode(FileType::Directory, 0o755), Arc::new(CgDirOps), default_file_ops()).build()
}

struct CgroupFs;
impl FileSystem for CgroupFs {
    fn name(&self) -> &str { "cgroup2" }
    fn magic(&self) -> u64 { 0x6367_7270 }
    fn root(&self) -> Option<InodeRef> { Some(cgroup_root()) }
}

fn lookup(root: &Arc<Dentry>, root_mnt: u64, path: &str) -> vfs::VfsPath {
    vfs::path_lookup_at_root_cred(
        root.clone(), root_mnt, root.clone(), root_mnt, path,
        LookupFlags::default(), Cred::root(),
    ).expect("path resolves")
}

fn write_file_at(p: &vfs::VfsPath) -> Arc<File> {
    File::new_at(p.inode.clone(), p.dentry.clone(), OpenFlags::O_WRONLY, p.mnt_id, vfs::FileCred::root())
}

#[test]
fn recursive_ro_staged_root_does_not_poison_live_cgroup_mount() {
    let _g = guard();
    common::register("/", Arc::new(RootFs)).expect("root mount");
    common::register("/sys/fs/cgroup", Arc::new(CgroupFs)).expect("cgroup mount");

    let root_mnt = vfs::mount::root_mount_id(vfs::mount::current_ns()).expect("root id");
    let root = vfs::mount::root_dentry_for_mount_id(root_mnt).expect("root dentry");
    let orig_cg = common::mount_at_path_exact("/sys/fs/cgroup").expect("original cgroup mount");
    assert_eq!(orig_cg.flags() & MNT_RDONLY, 0, "original cgroup mount starts RW");

    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("systemd make-rslave /");
    let cloned = common::bind_submounts_rec("/", "/run/systemd/mount-rootfs");
    assert!(cloned >= 1, "recursive bind clones at least the cgroup submount");
    let staged_root = common::mount_at_path_exact("/run/systemd/mount-rootfs").expect("staged root clone");
    let staged_cg = common::mount_at_path_exact("/run/systemd/mount-rootfs/sys/fs/cgroup")
        .expect("staged cgroup clone");
    assert_ne!(staged_cg.mnt_id, orig_cg.mnt_id, "staged cgroup is a clone, not the live mount");

    vfs::mount::mnt_setattr_tree_by_id(staged_root.mnt_id, MNT_RDONLY, 0)
        .expect("recursive MNT_RDONLY on staged root");

    let live = lookup(&root, root_mnt, "/sys/fs/cgroup/cgroup.subtree_control");
    assert_eq!(live.mnt_id, orig_cg.mnt_id, "live cgroup file resolves through original mount");
    assert_eq!(orig_cg.flags() & MNT_RDONLY, 0, "live cgroup mount remains RW");
    assert!(!orig_cg.sb().is_readonly(), "live cgroup superblock remains RW");
    let subtree_write = b"+pids";
    assert_eq!(write_file_at(&live).write(subtree_write), Ok(subtree_write.len()),
        "live cgroup write is not EROFS-shaped");

    let staged = lookup(&root, root_mnt, "/run/systemd/mount-rootfs/sys/fs/cgroup/cgroup.subtree_control");
    assert_eq!(staged.mnt_id, staged_cg.mnt_id, "staged cgroup file resolves through clone mount");
    assert_ne!(staged_cg.flags() & MNT_RDONLY, 0, "staged cgroup clone is MNT_RDONLY");
    assert_eq!(write_file_at(&staged).write(subtree_write), Err(VfsError::Erofs),
        "staged cgroup write is EROFS-shaped through cloned RO mount");
}
