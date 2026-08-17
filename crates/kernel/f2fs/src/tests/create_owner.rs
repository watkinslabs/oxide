//! The owner ids and mode a create records, driven through the real inode
//! operations against a real image.
//!
//! Three decisions the reference makes before a filesystem ever sees the new
//! object, all of them observable: a set-group-id directory hands its group to
//! what is created inside it, a set-group-id bit the caller is not entitled to
//! is stripped, and each kind of object clamps the mode bits it may carry.

use alloc::sync::Arc;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::setattr::{Iattr, ATTR_MODE};
use vfs::{Cred, CreateCtx, GroupList, InodeRef};

use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

/// `S_ISGID`.
const SGID: u16 = 0o2000;
/// `S_ISVTX`.
const STICKY: u16 = 0o1000;

fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let bs = BLKSIZE as u32;
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(bs, bytes.len() as u64 / u64::from(bs));
    let mut req = BlockRequest::new_write(0, (bytes.len() / BLKSIZE) as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    let o = crate::opts::parse(&Options::defaults(), "acl").expect("options");
    F2fs::open_with(dev, "/dev/fake", true, o).expect("mount")
}

fn user(uid: u32, gid: u32, groups: &[u32]) -> Cred {
    Cred { uid, gid, cap_dac_override: false, cap_dac_read_search: false, cap_fowner: false,
           cap_chown: false, cap_fsetid: false, groups: GroupList::from_slice(groups) }
}

/// A directory owned by gid 500 carrying the set-group-id bit.
fn sgid_dir(fs: &Arc<F2fs>, name: &str) -> InodeRef {
    let root = fs.root_inode().expect("root");
    let dir = root.mkdir(name, 0o775, &CreateCtx::root()).expect("mkdir");
    dir.set_owner(0, 500).expect("owner");
    let ia = Iattr { valid: ATTR_MODE, mode: 0o2775, ..Iattr::default() };
    dir.setattr(&vfs::IDENTITY, &ia).expect("set sgid");
    assert_eq!(dir.i_mode() & SGID, SGID, "the fixture directory carries the bit");
    dir
}

/// The uid/gid the MEDIUM holds for an inode, not the cached view.
fn stored_owner(fs: &Arc<F2fs>, inode: &InodeRef) -> (u32, u32) {
    let node = super::F2fsOps::node(inode).expect("node");
    let v = fs.volume.lock();
    let i = v.read_inode(node.ino).expect("stored inode");
    (i.uid, i.gid)
}

#[test]
fn a_file_created_in_a_set_group_id_directory_takes_that_directorys_group() {
    let fs = mounted();
    let dir = sgid_dir(&fs, "d");
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o022 };
    let file = dir.create_child("f", 0o666, &ctx).expect("create");
    assert_eq!(file.gid(), Some(500), "the parent's group, not the caller's 1000");
    assert_eq!(file.uid(), Some(1000), "the owner is still the caller");
    assert_eq!(stored_owner(&fs, &file), (1000, 500), "and that is what was written");
}

#[test]
fn a_directory_created_in_a_set_group_id_directory_carries_the_bit_itself() {
    let fs = mounted();
    let dir = sgid_dir(&fs, "d");
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o022 };
    let sub = dir.mkdir("sub", 0o775, &ctx).expect("mkdir");
    assert_eq!(sub.i_mode() & SGID, SGID, "the template propagates down the tree");
    assert_eq!(sub.gid(), Some(500));
}

#[test]
fn a_set_group_id_bit_the_caller_is_not_entitled_to_is_stripped() {
    let fs = mounted();
    let dir = sgid_dir(&fs, "d");
    // The caller is in no group 500, so a group-executable set-group-id file
    // would let it run code as that group: the bit is dropped.
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0 };
    let file = dir.create_child("f", 0o2775, &ctx).expect("create");
    assert_eq!(file.i_mode() & SGID, 0, "stripped for a caller outside the group");
    // The same request from a member of that group keeps it.
    let member = user(1000, 1000, &[500]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &member, umask: 0 };
    let kept = dir.create_child("g", 0o2775, &ctx).expect("create");
    assert_eq!(kept.i_mode() & SGID, SGID, "a member of the group may set it");
}

#[test]
fn a_mkdir_cannot_carry_a_set_id_bit_of_its_own() {
    let fs = mounted();
    let root = fs.root_inode().unwrap();
    // The parent is NOT set-group-id, so nothing re-adds the bit after the
    // per-kind clamp drops it. The sticky bit survives the same clamp.
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0 };
    let d = root.mkdir("d", 0o3775, &ctx).expect("mkdir");
    assert_eq!(d.i_mode() & SGID, 0, "set-group-id is not a mode a mkdir may request");
    assert_eq!(d.i_mode() & STICKY, STICKY, "the sticky bit is");
    assert_eq!(d.i_mode() & 0o777, 0o775);
}

#[test]
fn the_umask_still_decides_when_the_parent_has_no_default_acl() {
    let fs = mounted();
    let root = fs.root_inode().unwrap();
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o027 };
    let file = root.create_child("f", 0o666, &ctx).expect("create");
    assert_eq!(file.i_mode() & 0o777, 0o640, "the umask is applied exactly once");
}

#[test]
fn an_unnamed_file_takes_the_same_owner_preparation_as_a_named_one() {
    let fs = mounted();
    let dir = sgid_dir(&fs, "d");
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o022 };
    let file = dir.tmpfile(0o666, &ctx).expect("tmpfile");
    assert_eq!(file.gid(), Some(500), "the parent's group reaches an O_TMPFILE create");
    assert_eq!(file.uid(), Some(1000));
    assert_eq!(file.i_mode() & 0o777, 0o644, "and so does the umask");
}

#[test]
fn a_device_node_keeps_only_the_bits_its_own_mode_asked_for() {
    let fs = mounted();
    let root = fs.root_inode().unwrap();
    let cred = user(1000, 1000, &[]);
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0 };
    root.mknod_child("c", (vfs::types::S_IFCHR | 0o644) as u16, 0x0501, &ctx).expect("mknod");
    let node = root.lookup("c").expect("lookup");
    assert_eq!(node.i_mode() & 0o7777, 0o644);
    assert_eq!(node.rdev(), 0x0501, "the device identity survives the mode preparation");
    assert_eq!(node.uid(), Some(1000));
}
