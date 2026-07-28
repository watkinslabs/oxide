//! Linux `fs/namespace.c init_mount_tree()`: once the root filesystem is
//! mounted, `init_fs` carries root == pwd == the namespace root `struct path`,
//! and every task's `fs_struct` starts from it.
//!
//! `/proc/<pid>/root` resolves out of `fs->root` (`fs/proc/base.c`
//! `proc_root_link` → `get_task_root`), so a task whose root is unset makes
//! that magic link ENOENT. systemd's `running_in_chroot()` compares
//! `/proc/1/root` with `/`, reads the failure as "I am in a chroot", and every
//! systemd/udev tool then short-circuits — `udevadm trigger` prints "Running in
//! chroot, ignoring request" and the udev database stays empty for the whole
//! boot.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use std::sync::{Mutex, OnceLock};

use sched::{SchedClass, Task};
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult};

static SERIAL: Mutex<()> = Mutex::new(());
static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();

const ROOT_INO: u64 = 2;
const DIR_MODE: u16 = 0o755;

struct RootDirOps;
impl InodeOps for RootDirOps {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> { Err(vfs::VfsError::Enoent) }
}

fn root_inode() -> InodeRef {
    ROOT_INODE.get_or_init(|| {
        InodeBuilder::new(ROOT_INO, mk_mode(FileType::Directory, DIR_MODE),
            Arc::new(RootDirOps), default_file_ops()).build()
    }).clone()
}

fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

struct RootFs { root: InodeRef }
impl FileSystem for RootFs {
    fn name(&self) -> &str { "rootfs" }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

/// Mount `rootfs` as the namespace root, exactly as boot does.
fn install_root_mount() {
    let inode = root_inode();
    ROOT.get_or_init(|| Dentry::new_root(inode.clone()));
    vfs::set_root_dentry_provider(root_provider);
    let fs: Arc<dyn FileSystem> = Arc::new(RootFs { root: inode });
    let ty = vfs::fs::FsType::new(fs.name(), fs.magic(), fs.fs_flags(),
        Box::new(|_, _, _, _| unreachable!("fixture fs is mounted explicitly")));
    vfs::mount::register_typed(ty, None, fs).expect("namespace root mount");
}

#[test]
fn task_fs_context_starts_at_the_namespace_root() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    install_root_mount();
    let ns = vfs::mount::current_ns();
    let root_mnt = vfs::mount::root_mount_id(ns).expect("namespace root mount id");

    let task = Task::new(0x1472, "init", SchedClass::Normal { weight: 1024 });
    let snapshot = task.fs_context_snapshot();

    let root = snapshot.root_vfs().expect(
        "fs_struct.root must be the namespace root after init_mount_tree, not unset");
    assert_eq!(root.mnt_id, root_mnt, "fs_struct.root carries the root mount id");
    assert_eq!(root.inode.ino(), ROOT_INO);

    let pwd = snapshot.cwd_vfs().expect("fs_struct.pwd is set by init_mount_tree too");
    assert_eq!(pwd.mnt_id, root_mnt);
    assert_eq!(snapshot.root(), "/");
    assert_eq!(snapshot.cwd(), "/");
}

#[test]
fn namespace_root_path_pairs_mount_id_with_its_own_mnt_root() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    install_root_mount();
    let ns = vfs::mount::current_ns();
    let mnt_id = vfs::mount::root_mount_id(ns).expect("namespace root mount id");
    let path = vfs::mount::root_path_for_ns(ns).expect("namespace root struct path");
    assert_eq!(path.mnt_id, mnt_id);
    assert!(Arc::ptr_eq(&path.dentry,
        &vfs::mount::root_dentry_for_mount_id(mnt_id).expect("mnt_root")));
    assert!(vfs::mount::root_path_for_ns(0xDEAD_BEEF).is_none(),
        "an unmounted namespace has no root path");
}
