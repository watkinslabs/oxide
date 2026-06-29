//! mount-D6 + D14 WIRING: the mount engine routes a device-backed backend's
//! superblock through [`vfs::superblock::sget`] (two mounts of the same backing
//! device SHARE one `SuperBlock` + bump `s_active`), an anon/pseudo backend
//! (`dev_id() == None`) keeps a fresh per-mount instance, and the production
//! bind path's single-call [`vfs::mount::attach_recursive_mnt`] grafts a mount
//! exactly like the old `register` + `propagate_mount` pair. Driven over the
//! real global mount table, no QEMU.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::{default_file_ops, mk_mode, FileType, InodeOps, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}

/// Backend with a configurable backing-device id. `dev = Some(_)` ⇒ a
/// device-backed fs the engine must share via `sget`; `None` ⇒ an anon/pseudo
/// fs that gets a per-mount anon SB.
struct DevFs { dev: Option<u64>, root_ino: u64 }
impl FileSystem for DevFs {
    fn name(&self) -> &str { "devfs_test" }
    fn magic(&self) -> u64 { 0xEF53 }
    fn dev_id(&self) -> Option<u64> { self.dev }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}

/// D6: two mounts of the SAME backing device (distinct backend instances, same
/// `dev_id`) SHARE one `SuperBlock` (`sget` hit) and the share bumps `s_active`.
#[test]
fn same_dev_shares_one_superblock() {
    let _g = guard();
    let dev = 0x9A00_0001;
    let a = Arc::new(DevFs { dev: Some(dev), root_ino: 0x11 });
    let b = Arc::new(DevFs { dev: Some(dev), root_ino: 0x22 }); // distinct backend, same dev
    common::register("/d6_a", a).expect("register a");
    common::register("/d6_b", b).expect("register b");
    let ma = common::mount_at_path_exact("/d6_a").expect("mount a");
    let mb = common::mount_at_path_exact("/d6_b").expect("mount b");
    assert!(Arc::ptr_eq(ma.sb(), mb.sb()), "same dev → one shared SuperBlock");
    assert_eq!(ma.sb().s_dev, dev, "shared SB carries the backing-device id as s_dev");
    assert!(ma.sb().s_active() >= 2, "each live mount holds one s_active (>=2 shared)");
}

/// D6: distinct backing devices get distinct superblock instances.
#[test]
fn distinct_dev_distinct_superblock() {
    let _g = guard();
    let a = Arc::new(DevFs { dev: Some(0x9B00_0001), root_ino: 0x31 });
    let b = Arc::new(DevFs { dev: Some(0x9B00_0002), root_ino: 0x32 });
    common::register("/d6_c", a).expect("register c");
    common::register("/d6_d", b).expect("register d");
    let sa = common::mount_at_path_exact("/d6_c").unwrap().sb().clone();
    let sb = common::mount_at_path_exact("/d6_d").unwrap().sb().clone();
    assert!(!Arc::ptr_eq(&sa, &sb), "different dev → different SuperBlock");
}

/// D6: an anon/pseudo backend (`dev_id() == None`) is NEVER shared — every
/// mount gets a fresh per-instance anon `s_dev` (Linux `get_tree_nodev`).
#[test]
fn anon_fs_not_shared() {
    let _g = guard();
    let a = Arc::new(DevFs { dev: None, root_ino: 0x41 });
    let b = Arc::new(DevFs { dev: None, root_ino: 0x42 });
    common::register("/d6_e", a).expect("register e");
    common::register("/d6_f", b).expect("register f");
    let sa = common::mount_at_path_exact("/d6_e").unwrap().sb().clone();
    let sb = common::mount_at_path_exact("/d6_f").unwrap().sb().clone();
    assert!(!Arc::ptr_eq(&sa, &sb), "anon fs → fresh per-mount SuperBlock");
    assert_ne!(sa.s_dev, sb.s_dev, "anon fs → distinct per-instance s_dev");
}

/// D14: the single-call atomic graft `attach_recursive_mnt` (the production
/// MS_BIND primitive) attaches a mount visible in the table, with no separate
/// register + propagate window. A private graft propagates 0 mirrors.
#[test]
fn attach_recursive_grafts_mount() {
    let _g = guard();
    let fs = Arc::new(DevFs { dev: None, root_ino: 0x51 });
    let src_root: InodeRef = make_tdir(0xBEEF);
    let mp = common::dentry("/d14_bind");
    let mirrors = vfs::mount::attach_recursive_mnt(Some(mp), fs, Some(src_root.clone()))
        .expect("attach_recursive_mnt");
    assert_eq!(mirrors, 0, "private graft propagates no mirror copies");
    let m = common::mount_at_path_exact("/d14_bind").expect("graft present in table");
    assert_eq!(m.root.as_ref().map(|i| i.ino()), Some(0xBEEF),
        "graft keeps the bind source-subtree root (mnt_root)");
    assert!(m.sb().s_root().is_some(), "graft carries its own SuperBlock");
}
