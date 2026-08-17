//! A device node holds extended attributes, so an attribute nobody has set
//! reads as ABSENT rather than as unsupported.
//!
//! devtmpfs is the shared-memory filesystem, whose superblock carries handlers
//! for the security, trusted and user namespaces. A label read on a terminal is
//! therefore answered `ENODATA` when no label was stored — and the login stack
//! branches on exactly that: "not supported" is a filesystem that cannot hold
//! the attribute, and it treats the answer as a hard failure rather than as an
//! unlabelled object. Our `/dev` nodes held no store at all, so every such read
//! was `EOPNOTSUPP`.
//!
//! These assertions need no security policy: with no module loaded the label
//! path declines the name and the read falls through to the filesystem's own
//! store, which is the code under test. The negative control is the third test:
//! an inode that never joined devtmpfs still answers `EOPNOTSUPP`, so a blanket
//! "every inode has a store" regression cannot pass this file.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use fs::xattr::{vfs_getxattr, vfs_listxattr, vfs_setxattr, XattrCred};
use syscall::errno::Errno;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef};

fn e(x: Errno) -> i64 { -(x.as_i32() as i64) }

fn get(ino: &InodeRef, name: &str) -> Result<Vec<u8>, i64> {
    vfs_getxattr(ino, name, &XattrCred::root())
}

/// A `/dev` node reached the way a path walk reaches one: the devtmpfs mount
/// root, then the directory's own `->lookup` for the component. Nothing here
/// touches devfs's internals, so a store granted only through some test-visible
/// side door could not satisfy it.
fn dev_node(name: &str) -> InodeRef {
    let root = devfs::instance().root().expect("devtmpfs has a mount root");
    let op = alloc::sync::Arc::clone(root.i_op());
    op.lookup(&root, name).expect("the node resolves under /dev")
}

/// Publish a node under `/dev` through the registration funnel every driver's
/// hotplug path uses, then resolve it by walk.
fn published_dev_node(path: &'static str, name: &str) -> InodeRef {
    devfs::register(path, devfs::misc::make_null_inode());
    dev_node(name)
}

/// An inode of the same shape that never joined devtmpfs.
fn unpublished_node() -> InodeRef {
    InodeBuilder::new(4242, mk_mode(FileType::CharDev, 0o620), default_inode_ops(), default_file_ops())
        .owner(0, 0).build()
}

/// The boot failure: the login stack asks a terminal for its label and is told
/// the operation is not supported. With no module loaded the answer must be
/// "no such attribute" — the object is simply unlabelled.
#[test]
fn a_device_node_reports_an_unset_label_as_absent() {
    // A character device node on devtmpfs, which is what `/dev/tty2` is; the
    // console crate self-registers the real terminals only on a booted kernel.
    let tty = published_dev_node("/dev/b2260_tty2", "b2260_tty2");
    assert_eq!(get(&tty, "security.selinux"), Err(e(Errno::Enodata)),
        "an unset label on a device node is absent, not unsupported");
}

/// Every namespace the shared-memory superblock carries a handler for answers
/// the same way; the ones it does not carry are still unsupported.
#[test]
fn each_namespace_answers_as_the_superblocks_handler_set_says() {
    let n = dev_node("null");

    // security.* and trusted.* have handlers: absent means absent.
    assert_eq!(get(&n, "security.ima"), Err(e(Errno::Enodata)), "security.* handler present");
    assert_eq!(get(&n, "trusted.overlay.opaque"), Err(e(Errno::Enodata)), "trusted.* handler present");

    // user.* has a handler, but the VFS refuses the namespace on anything that
    // is not a regular file, directory or socket BEFORE any store is consulted —
    // a read of a hidden attribute is ENODATA, which is the same answer by a
    // different route, and is unaffected by this store.
    assert_eq!(get(&n, "user.comment"), Err(e(Errno::Enodata)), "user.* on a char device is refused");

    // system.* and an unregistered namespace have no handler at all.
    assert_eq!(get(&n, "system.posix_something"), Err(e(Errno::Eopnotsupp)), "no system.* handler");
    assert_eq!(get(&n, "b2260ns.x"), Err(e(Errno::Eopnotsupp)), "no handler for an unknown namespace");
    // A bare prefix names no attribute.
    assert_eq!(get(&n, "security."), Err(e(Errno::Einval)), "a bare prefix is EINVAL");
}

/// NEGATIVE CONTROL. The store is granted where a node JOINS devtmpfs, not to
/// every inode ever built: an inode of the same shape that was never published
/// still reports that its filesystem cannot hold attributes. Without this, a
/// change that handed every inode a store would pass the two tests above.
#[test]
fn an_inode_that_never_joined_devtmpfs_still_has_no_store() {
    let orphan = unpublished_node();
    assert_eq!(get(&orphan, "security.ima"), Err(e(Errno::Eopnotsupp)),
        "a filesystem with no attribute handlers is unsupported, not absent");
    assert_eq!(get(&orphan, "trusted.x"), Err(e(Errno::Eopnotsupp)));
}

/// The store is real, not a shape that only reports absence: a value written to
/// a device node reads back, and lists.
#[test]
fn a_device_node_stores_and_returns_a_value() {
    let n = published_dev_node("/dev/b2260_rw", "b2260_rw");
    let c = XattrCred::root();
    vfs_setxattr(&n, "security.ima", b"digest".to_vec(), 0, &c).expect("the node accepts a value");
    assert_eq!(get(&n, "security.ima"), Ok(b"digest".to_vec()));
    // A DIFFERENT name in the same namespace is still absent — the store
    // answers per name, so a test that only read back what it wrote could not
    // tell a real map from a constant.
    assert_eq!(get(&n, "security.evm"), Err(e(Errno::Enodata)));

    let names: Vec<String> = String::from_utf8(vfs_listxattr(&n, &c).expect("list"))
        .expect("names are text").split('\0').filter(|s| !s.is_empty()).map(String::from).collect();
    assert_eq!(names, alloc::vec![String::from("security.ima")], "the written name is listed");
}

/// A node minted by a driver's `dev_t` — no factory, no filesystem knowledge in
/// the producer at all — gets the same answer. This is the case a per-constructor
/// fix would have missed, since those inodes are built inside the VFS device-node
/// helper that on-disk filesystems share.
#[test]
fn a_dev_t_minted_driver_node_holds_attributes_too() {
    devfs::add_device_node("block", "b2260_disk", Some((254, 90)), None);
    let n = dev_node("b2260_disk");
    assert_eq!(get(&n, "security.selinux"), Err(e(Errno::Enodata)),
        "a driver-minted node joins the same superblock");
    devfs::del_device_node("b2260_disk");
}
