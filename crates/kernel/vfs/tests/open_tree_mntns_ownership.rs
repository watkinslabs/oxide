//! Detached open-tree namespace ownership across a destination switch.

use std::sync::{Arc, Mutex};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult};

mod common;

static CURRENT_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);

fn current_namespace() -> vfs::mntns::MntNamespaceRef {
    CURRENT_NS.lock().unwrap().as_ref().cloned().unwrap_or_else(vfs::mntns::initial)
}

fn set_current(namespace: Option<vfs::mntns::MntNamespaceRef>) {
    *CURRENT_NS.lock().unwrap() = namespace;
}

struct TestFs { ino: u64 }

impl FileSystem for TestFs {
    fn name(&self) -> &str { "open-tree-mntns-owner" }
    fn root(&self) -> Option<InodeRef> { Some(test_dir(self.ino)) }
}

struct TestDirOps;

impl vfs::InodeOps for TestDirOps {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> {
        Ok(test_dir(0xB865))
    }
}

fn test_dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(TestDirOps), vfs::default_file_ops()).build()
}

fn test_fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TestFs { ino }) }

#[test]
fn detached_clone_pins_source_then_rebinds_to_destination() {
    common::install();
    vfs::mount::set_current_ns_provider(current_namespace);
    let init = vfs::mntns::initial();
    let source = vfs::mntns::allocate(init.owner_user_namespace()).unwrap();
    let destination = vfs::mntns::allocate(init.owner_user_namespace()).unwrap();
    let (source_id, destination_id) = (source.id(), destination.id());

    set_current(Some(source.clone()));
    common::register("/", test_fs(1)).unwrap();
    let source_root = vfs::mount::root_mount_id(source_id).unwrap();
    let tree = vfs::mount::clone_mount_tree(
        &vfs::mount::mount_by_id(source_root).unwrap(), true);
    let clone_id = tree.iter().find(|node| node.rel.is_empty()).unwrap().m.mnt_id;

    set_current(Some(destination.clone()));
    common::register("/", test_fs(2)).unwrap();
    let destination_root = vfs::mount::root_mount_id(destination_id).unwrap();
    drop(source);
    assert!(vfs::mntns::ns_by_id(source_id).is_some(),
        "detached mount-object tree retains the exact source owner");

    let target = common::dentry("/attached");
    assert_eq!(vfs::mount::commit_tree_hashonly_at(tree, &target, destination_root), 1);

    assert!(vfs::mntns::ns_by_id(source_id).is_none(),
        "source finalizes after the detached tree releases its owner");
    assert!(vfs::mount::snapshot_ns_view(source_id).is_empty(),
        "source finalizer cannot reap or republish the rebound clone");
    let clone = vfs::mount::mount_by_id(clone_id).expect("clone published in destination");
    assert_eq!(clone.namespace_id(), destination_id,
        "published clone is rebound to the exact destination namespace");
    assert!(vfs::mount::check_mnt(&clone), "destination current view accepts clone");
    assert!(vfs::mount::snapshot_ns_view(destination_id)
        .iter().any(|mount| mount.mnt_id == clone_id));

    set_current(None);
    drop(destination);
}
