//! B1 acceptance: every mount carries a real `SuperBlock` (Linux `mnt_sb`),
//! allocated by `SuperBlock::for_backend` inside the mount engine — NOT only
//! by `object_model.rs`. Proves each backend mounts via a superblock with a
//! valid `s_root` dentry + `s_magic`, a per-instance `s_dev`, and a working
//! `statfs`; and that a bind keeps `mnt_root` (source subtree) while owning
//! its own SB. Driven over the real global mount table, no QEMU.

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

/// A backend standing in for any real fs (tmpfs/ext4/procfs/…): it carries a
/// `magic` + a root inode, exactly the surface `for_backend` reads.
struct TestFs { magic: u64, root_ino: u64 }
impl FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn magic(&self) -> u64 { self.magic }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}

/// T-mount-sb: a registered fs mounts via a SuperBlock with a valid s_root
/// dentry over the fs root inode, the backend's s_magic, and a nonzero s_dev.
#[test]
fn mount_carries_real_superblock() {
    let _g = guard();
    let fs = Arc::new(TestFs { magic: 0x0102_1994, root_ino: 0xA1 });
    common::register("/sb_a", fs.clone()).expect("register");
    let m = common::mount_at_path_exact("/sb_a").expect("mount present");
    let sb = m.sb();
    assert!(sb.s_root().is_some(), "SuperBlock has an s_root dentry");
    let root_d = sb.s_root().unwrap();
    assert!(root_d.is_root(), "s_root is a superblock-root dentry (D_ROOT)");
    assert!(root_d.parent().is_none(), "s_root is parentless");
    assert_eq!(sb.s_root_inode().map(|i| i.ino()), Some(0xA1),
        "s_root dentry covers the fs root inode");
    assert_eq!(sb.s_magic, fs.magic(), "s_magic == backend magic");
    assert_ne!(sb.s_dev, 0, "per-instance s_dev allocated (get_anon_bdev)");
    // The SB reaches the backend (Linux mnt_sb->s_fs).
    assert_eq!(m.fs().magic(), fs.magic(), "mount reaches backend via sb.fs()");
}

/// T-statfs-real: statfs reports the mount's own SB magic, not a guess.
#[test]
fn statfs_reads_superblock_magic() {
    let _g = guard();
    let fs = Arc::new(TestFs { magic: 0x6367_7270, root_ino: 0xB2 }); // cgroup2
    common::register("/sb_stat", fs.clone()).expect("register");
    let m = common::mount_at_path_exact("/sb_stat").expect("mount present");
    let st = m.sb().statfs().expect("statfs");
    assert_eq!(st.f_type, fs.magic(), "f_type == s_magic");
    assert_eq!(st.f_bsize, 4096, "f_bsize defaulted from s_blocksize");
}

/// T-statfs-fsid: `SuperBlock::statfs` defaults `f_fsid` from `s_dev` (Linux
/// packs the device id into `__fsid_t`) when the backend reports none.
#[test]
fn statfs_defaults_fsid_from_s_dev() {
    let _g = guard();
    let fs = Arc::new(TestFs { magic: 0x0102_1994, root_ino: 0xC3 });
    common::register("/sb_fsid", fs).expect("register");
    let m = common::mount_at_path_exact("/sb_fsid").expect("mount present");
    let st = m.sb().statfs().expect("statfs");
    assert_eq!(st.f_fsid, m.sb().s_dev, "f_fsid defaulted from s_dev");
    assert_ne!(st.f_fsid, 0, "f_fsid is a real (nonzero) fs identity");
}

/// T-anon-dev-unique: two instances of the same fs type get distinct s_dev,
/// the thing a per-fs-type constant could not express.
#[test]
fn two_instances_get_distinct_s_dev() {
    let _g = guard();
    let a = Arc::new(TestFs { magic: 0x0102_1994, root_ino: 1 });
    let b = Arc::new(TestFs { magic: 0x0102_1994, root_ino: 2 });
    common::register("/sb_one", a).expect("register a");
    common::register("/sb_two", b).expect("register b");
    let da = common::mount_at_path_exact("/sb_one").unwrap().sb().s_dev;
    let db = common::mount_at_path_exact("/sb_two").unwrap().sb().s_dev;
    assert_ne!(da, db, "distinct mount instances → distinct s_dev");
}

/// T-bind-shares: a bind keeps mnt_root (the source subtree root inode) while
/// carrying its own SuperBlock.
#[test]
fn bind_keeps_mnt_root_with_own_sb() {
    let _g = guard();
    let fs = Arc::new(TestFs { magic: 0xEF53, root_ino: 0xC3 });
    let source_root: InodeRef = make_tdir(0xDEAD);
    common::register_bind("/sb_bind", fs.clone(), source_root.clone()).expect("bind");
    let m = common::mount_at_path_exact("/sb_bind").expect("bind present");
    assert_eq!(m.mnt_root().and_then(|r| r.inode()).map(|i| i.ino()), Some(0xDEAD),
        "mnt_root is the bind source subtree root");
    assert!(m.sb().s_root().is_some(), "bind still carries its own SuperBlock");
}

/// T-put-super-umount (D17): the last umount of an SB runs `put_super`
/// (Linux `deactivate_super`/`generic_shutdown_super`) — s_root + icache are
/// torn down deterministically, not left dangling on Arc-refcount timing.
#[test]
fn last_umount_runs_put_super() {
    let _g = guard();
    let fs = Arc::new(TestFs { magic: 0xEF53, root_ino: 0xD4 });
    common::register("/sb_pu", fs.clone()).expect("register");
    let m = common::mount_at_path_exact("/sb_pu").expect("mount present");
    let sb = m.sb(); // hold a strong ref so we can observe post-umount teardown
    assert!(sb.s_root().is_some(), "s_root present before umount");
    assert_eq!(common::unregister("/sb_pu"), 1, "umount detached one mount");
    assert!(sb.s_root().is_none(),
        "put_super cleared s_root on last umount (deterministic teardown)");
}
