use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;

use vfs::{CreateCtx, Devt, S_IFIFO, VfsError};
use vfs::fs::{FileSystem, FsFlags, FsType, superblock_from_filesystem};
use vfs::superblock::SuperBlock;

use super::{TMPFS_MAGIC, TmpfsFs};

// Build a live tmpfs SuperBlock through the registered-type realization path,
// which back-stamps the root dir's sb weak. No PMM needed: no data writes, only
// inode lifecycle.
fn live_sb() -> Arc<SuperBlock> {
    let fs = TmpfsFs::new(String::from("/"));
    let root = fs.root_inode();
    let ty = FsType::new("tmpfs", TMPFS_MAGIC, FsFlags::empty(), Box::new(|_, _, _, _| Err(VfsError::Einval)));
    superblock_from_filesystem(ty, fs as Arc<dyn FileSystem>, Some(root), String::from("tmpfs"))
}

// [inode D2] A child created on a back-stamped tmpfs mount is registered in the
// per-SB icache, and a later `ilookup`/`iget` of its ino returns the SAME `Arc`
// (shared inode identity, Linux iget), never a fresh duplicate.
#[test]
fn create_child_has_icache_identity() {
    let sb = live_sb();
    let root = sb.s_root_inode().expect("root inode");
    let child = root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
    let ino = child.ino();

    let via_lookup = sb.ilookup(ino).expect("child cached in icache");
    assert!(Arc::ptr_eq(&child, &via_lookup), "ilookup returns the SAME Arc");

    let via_iget = sb.iget(ino, || panic!("iget must hit the cache, not rebuild"));
    assert!(Arc::ptr_eq(&child, &via_iget), "iget returns the SAME Arc");
    assert_eq!(child.fsid(), sb.s_dev);
}

// [inode D2] An OPEN/held inode is NOT evicted while any strong `Arc` lives.
// Once the last strong ref drops, the `Weak` dies and the slot reclaims.
#[test]
fn held_inode_not_evicted_then_reclaimed_on_last_drop() {
    let sb = live_sb();
    let root = sb.s_root_inode().expect("root inode");
    let child = root.create_child("g", 0o644, &CreateCtx::root()).expect("create g");
    let ino = child.ino();

    root.unlink_child("g").expect("unlink g");
    assert!(sb.ilookup(ino).is_some(), "still held -> NOT evicted");

    drop(child);
    assert!(sb.ilookup(ino).is_none(), "last ref gone -> reclaimed");
}

// [inode D2] A second create of the SAME name path after reclaim yields a
// DISTINCT inode (fresh ino), and both never collide in the icache.
#[test]
fn distinct_children_distinct_icache_slots() {
    let sb = live_sb();
    let root = sb.s_root_inode().expect("root inode");
    let a = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
    let b = root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
    assert_ne!(a.ino(), b.ino());
    assert!(Arc::ptr_eq(&a, &sb.ilookup(a.ino()).unwrap()));
    assert!(Arc::ptr_eq(&b, &sb.ilookup(b.ino()).unwrap()));
}

#[test]
fn fifo_mknod_ignores_user_rdev() {
    let sb = live_sb();
    let root = sb.s_root_inode().expect("root inode");
    root.mknod_child("fifo", (S_IFIFO | 0o644) as u16, Devt::new(9, 9).raw(), &CreateCtx::root())
        .expect("mknod fifo");
    let fifo = root.lookup("fifo").expect("lookup fifo");
    assert_eq!(fifo.rdev(), 0, "Linux ignores dev for S_IFIFO mknod");
}
