//! Default-ACL inheritance over a writable ext4 image.
//!
//! The test drives the VFS creation operations, then the legacy path helpers
//! that feed the same filesystem, so an ACL decision that is not joined to the
//! create transaction cannot look complete from one entry point only.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::posix_acl::{from_xattr, to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                     ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};
use vfs::{CreateCtx, InodeRef, S_IFIFO};

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
const R: u16 = 4;
const W: u16 = 2;
const X: u16 = 1;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = IMAGE.len() as u64 / u64::from(SECTOR);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default()
    };
    disk.submit_sync(&mut req).expect("image write");
    disk
}

fn e(tag: u16, perm: u16) -> AclEntry { AclEntry { tag, perm, id: ACL_UNDEFINED_ID } }

/// A default ACL with a named user, forcing an access ACL on every child.
fn named_default() -> Vec<u8> {
    to_xattr(&[
        e(ACL_USER_OBJ, R | W | X),
        AclEntry { tag: ACL_USER, perm: R | W, id: 1000 },
        e(ACL_GROUP_OBJ, R | X),
        e(ACL_MASK, R | W | X),
        e(ACL_OTHER, R | X),
    ])
}

/// Fits on the parent but not twice on a child directory's one xattr block.
fn default_that_overflows_a_child() -> Vec<u8> {
    let mut entries = Vec::new();
    entries.push(e(ACL_USER_OBJ, R | W | X));
    for id in 1000..1070 {
        entries.push(AclEntry { tag: ACL_USER, perm: R | W, id });
    }
    entries.push(e(ACL_GROUP_OBJ, R | X));
    entries.push(e(ACL_MASK, R | W | X));
    entries.push(e(ACL_OTHER, R | X));
    to_xattr(&entries)
}

fn named_access(inode: &InodeRef) {
    let got = from_xattr(&inode.getxattr("system.posix_acl_access").expect("access ACL"))
        .expect("access ACL interchange form");
    assert_eq!(got[1], AclEntry { tag: ACL_USER, perm: R | W, id: 1000 },
               "the named default entry must reach the child access ACL");
}

fn setup() -> (Arc<ext4::rootfs::Ext4Mount>, Arc<ext4::rootfs::RootfsState>, InodeRef, Vec<u8>) {
    let mount = ext4::rootfs::Ext4Mount::open(build_disk()).expect("mount");
    let state = mount.state().clone();
    let root = state.wrap_any_ino(2).expect("root");
    let parent = root.mkdir("acl", 0o777, &CreateCtx::root()).expect("parent directory");
    let blob = named_default();
    parent.setxattr("system.posix_acl_default", blob.clone(), false, false)
        .expect("parent default ACL");
    (mount, state, parent, blob)
}

#[test]
fn every_vfs_create_kind_obeys_the_parent_default_acl() {
    let (_mount, _state, parent, blob) = setup();
    // A zeroing umask makes it unambiguous that the ACL, rather than the
    // ordinary umask path, decided the permission bits.
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &vfs::Cred::root(), umask: 0o777 };

    let file = parent.create_child("file", 0o666, &ctx).expect("file create");
    assert_eq!(file.i_mode() & 0o777, 0o664);
    named_access(&file);
    assert!(file.getxattr("system.posix_acl_default").is_err());

    let dir = parent.mkdir("dir", 0o777, &ctx).expect("directory create");
    named_access(&dir);
    assert_eq!(dir.getxattr("system.posix_acl_default").expect("directory default ACL"), blob);
    let deep = dir.mkdir("deep", 0o777, &ctx).expect("recursive directory create");
    assert_eq!(deep.getxattr("system.posix_acl_default").expect("recursive default ACL"),
               named_default());

    let tmp = parent.tmpfile(0o666, &ctx).expect("tmpfile create");
    assert_eq!(tmp.i_mode() & 0o777, 0o664);
    named_access(&tmp);

    parent.mknod_child("fifo", (S_IFIFO | 0o666) as u16, 0, &ctx).expect("FIFO create");
    let fifo = parent.lookup("fifo").expect("FIFO lookup");
    assert_eq!(fifo.i_mode() & 0o777, 0o664);
    named_access(&fifo);

    parent.symlink_child("link", b"/target", &ctx).expect("symlink create");
    let link = parent.lookup("link").expect("symlink lookup");
    assert_eq!(link.i_mode() & 0o777, 0o777, "a symlink ignores umask and default ACL");
    assert!(link.getxattr("system.posix_acl_access").is_err());
}

#[test]
fn path_helpers_share_the_acl_aware_vfs_create_path() {
    let (_mount, state, parent, blob) = setup();

    let file = state.create_at(b"/acl/helper-file", 0o666).expect("helper file create");
    named_access(&file);

    state.mkdir_at(b"/acl/helper-dir", 0o777).expect("helper directory create");
    let dir = state.lookup_inode_any(b"/acl/helper-dir").expect("helper directory lookup");
    assert_eq!(dir.getxattr("system.posix_acl_default").expect("helper directory default ACL"), blob);

    let tmp = state.create_anonymous_at(b"/acl", 0o666).expect("helper tmpfile create");
    named_access(&tmp);

    state.mknod_at(b"/acl/helper-fifo", (S_IFIFO | 0o666) as u16, 0)
        .expect("helper FIFO create");
    let fifo = state.lookup_inode_any(b"/acl/helper-fifo").expect("helper FIFO lookup");
    named_access(&fifo);

    state.symlink_at(b"/target", b"/acl/helper-link").expect("helper symlink create");
    let link = parent.lookup("helper-link").expect("helper symlink lookup");
    assert!(link.getxattr("system.posix_acl_access").is_err());
}

#[test]
fn whiteouts_inherit_the_source_directory_access_acl() {
    let (_mount, state, parent, _blob) = setup();
    let ctx = CreateCtx::root();

    parent.create_child("vfs-source", 0o644, &ctx).expect("VFS whiteout source");
    parent.rename_child("vfs-source", &parent, "vfs-destination", vfs::namei::RENAME_WHITEOUT, &ctx)
        .expect("VFS whiteout rename");
    named_access(&parent.lookup("vfs-source").expect("VFS whiteout"));

    state.create_at(b"/acl/helper-source", 0o644).expect("helper whiteout source");
    state.whiteout_at(b"/acl/helper-source", b"/acl/helper-destination").expect("helper whiteout rename");
    named_access(&parent.lookup("helper-source").expect("helper whiteout"));
}

#[test]
fn an_unstorable_inherited_acl_does_not_publish_the_child() {
    let mount = ext4::rootfs::Ext4Mount::open(build_disk()).expect("mount");
    let root = mount.state().wrap_any_ino(2).expect("root");
    let parent = root.mkdir("full", 0o777, &CreateCtx::root()).expect("parent");
    parent.setxattr("system.posix_acl_default", default_that_overflows_a_child(), false, false)
        .expect("large default ACL");

    assert!(matches!(parent.mkdir("child", 0o777, &CreateCtx::root()), Err(vfs::VfsError::Enospc)));
    assert!(matches!(parent.lookup("child"), Err(vfs::VfsError::Enoent)),
            "an ACL-store failure must roll back before the name is published");
}
