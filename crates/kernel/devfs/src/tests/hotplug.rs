// Device hot-unplug / rebind through a REAL devtmpfs mount and a real dcache
// walk — the layer the tree-level `lookup` tests cannot reach.
//
// A driver unbind removes the `/dev` node and a rebind republishes the SAME
// name carrying a DIFFERENT backend object (same inode number: an evdev node's
// number is derived from its event index). A dentry cached by the first walk
// therefore has to be invalidated by the removal, or every later `open(2)`
// reaches the dead object of the previous binding and reports `ENODEV` while
// the device is live.

use alloc::string::String;
use alloc::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::FileSystemType;
use vfs::{InodeRef, LookupFlags, SuperBlock};

use crate::tests::TEST_SERIAL;

/// `/dev`-relative node the rebind cases publish, unique to this file so a
/// concurrently running test never observes it.
const NODE_NAME: &str = "input/b1614event0";
const NODE_PATH: &str = "/input/b1614event0";
const DEV_NODE_PATH: &str = "/dev/input/b1614event0";
/// Both generations mint this same inode number, exactly as a republished
/// evdev node does: identity must come from the object, never the number.
const NODE_INO: u64 = 0x3f00_1614;
const NODE_CLASS: &str = "input";
const NODE_PERMISSIONS: u16 = 0o600;

struct DevtmpfsType;

impl FileSystemType for DevtmpfsType {
    fn name(&self) -> &str { "devtmpfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<SuperBlock>> {
        Err(vfs::VfsError::Enodev)
    }
}

fn mount_devtmpfs() -> Arc<SuperBlock> {
    let fs: Arc<dyn FileSystem> = Arc::new(crate::DevfsFs);
    vfs::fs::superblock_from_filesystem(
        Arc::new(DevtmpfsType),
        fs,
        crate::DevfsFs.root(),
        String::from("devtmpfs-test"),
    ).expect("realize devtmpfs")
}

/// One driver-binding generation's node inode. Distinct `Arc` per call.
fn generation_inode() -> InodeRef {
    vfs::InodeBuilder::new(
        NODE_INO,
        vfs::mk_mode(vfs::FileType::CharDev, NODE_PERMISSIONS),
        vfs::default_inode_ops(),
        vfs::default_file_ops(),
    ).build()
}

fn publish(inode: &InodeRef) {
    let published = InodeRef::clone(inode);
    let factory: crate::NodeFactory = Arc::new(move || InodeRef::clone(&published));
    crate::add_device_node(NODE_CLASS, NODE_NAME, None, Some(factory));
}

fn resolve(root: &Arc<vfs::Dentry>) -> Option<InodeRef> {
    vfs::path_lookup(root.clone(), root.clone(), NODE_PATH, LookupFlags::default())
        .ok()
        .map(|(inode, _)| inode)
}

#[test]
fn a_rebound_device_publishes_a_node_that_resolves_to_the_new_generation() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    crate::register_dir("/dev/input");

    let first = generation_inode();
    publish(&first);
    let sb = mount_devtmpfs();
    let root = sb.s_root().expect("devtmpfs root dentry");
    let resolved = resolve(&root).expect("first binding resolves");
    assert!(Arc::ptr_eq(&resolved, &first), "first binding serves its own node");

    // Unbind, then rebind: same name, same inode number, new object.
    crate::del_device_node(NODE_NAME);
    let second = generation_inode();
    publish(&second);

    let resolved = resolve(&root).expect("rebound node resolves");
    assert!(
        Arc::ptr_eq(&resolved, &second),
        "a rebind must not keep serving the previous binding's node",
    );
    crate::del_device_node(NODE_NAME);
}

#[test]
fn an_unplugged_device_node_stops_resolving_through_the_dcache() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    crate::register_dir("/dev/input");

    let node = generation_inode();
    publish(&node);
    let sb = mount_devtmpfs();
    let root = sb.s_root().expect("devtmpfs root dentry");
    assert!(resolve(&root).is_some(), "node resolves while the device is bound");

    crate::del_device_node(NODE_NAME);
    assert!(
        resolve(&root).is_none(),
        "hot-unplug must invalidate the cached dentry, not only the tree entry",
    );
    assert!(crate::lookup(DEV_NODE_PATH).is_none(), "and the tree entry is gone too");
}

/// The removal must not disturb an unrelated sibling's cached dentry: Linux
/// unlinks the removed name, it does not flush the directory.
#[test]
fn unplugging_one_node_leaves_its_siblings_cached() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    crate::register_dir("/dev/input");
    const SIBLING_NAME: &str = "input/b1614event1";
    const SIBLING_PATH: &str = "/input/b1614event1";

    let node = generation_inode();
    publish(&node);
    let sibling = generation_inode();
    let published = InodeRef::clone(&sibling);
    let factory: crate::NodeFactory = Arc::new(move || InodeRef::clone(&published));
    crate::add_device_node(NODE_CLASS, SIBLING_NAME, None, Some(factory));

    let sb = mount_devtmpfs();
    let root = sb.s_root().expect("devtmpfs root dentry");
    assert!(resolve(&root).is_some());
    let (sibling_inode, _) =
        vfs::path_lookup(root.clone(), root.clone(), SIBLING_PATH, LookupFlags::default())
            .expect("sibling resolves");
    assert!(Arc::ptr_eq(&sibling_inode, &sibling));

    crate::del_device_node(NODE_NAME);
    let (still_there, _) =
        vfs::path_lookup(root.clone(), root.clone(), SIBLING_PATH, LookupFlags::default())
            .expect("sibling survives a sibling's hot-unplug");
    assert!(Arc::ptr_eq(&still_there, &sibling));
    crate::del_device_node(SIBLING_NAME);
}
