//! Default-ACL inheritance and the ACL xattr boundary, driven through the real
//! inode operations against a real image — the only place that proves the
//! decisions in `crate::acl` are reached by a create and by `setxattr`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::posix_acl::{to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_UNDEFINED_ID,
                     ACL_USER, ACL_USER_OBJ};
use vfs::{CreateCtx, FileType, InodeRef};

use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

const R: u16 = 4;
const W: u16 = 2;
const X: u16 = 1;

fn e(tag: u16, perm: u16) -> AclEntry { AclEntry { tag, perm, id: ACL_UNDEFINED_ID } }

/// A writable filesystem over a fresh fixture image, mounted with `opts`.
fn mounted_with(opts: &str) -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let bs = BLKSIZE as u32;
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(bs, bytes.len() as u64 / u64::from(bs));
    let mut req = BlockRequest::new_write(0, (bytes.len() / BLKSIZE) as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    let o = crate::opts::parse(&Options::defaults(), opts).expect("options");
    F2fs::open_with(dev, "/dev/fake", true, o).expect("mount")
}

/// u::rwx g::r-x o::r-x as the interchange blob a caller would pass in.
fn plain_default_blob() -> Vec<u8> {
    to_xattr(&[e(ACL_USER_OBJ, R | W | X), e(ACL_GROUP_OBJ, R | X), e(ACL_OTHER, R | X)])
}

/// The same plus a named user, which forces a mask and cannot be expressed by
/// mode bits alone.
fn named_default_blob() -> Vec<u8> {
    to_xattr(&[e(ACL_USER_OBJ, R | W | X), AclEntry { tag: ACL_USER, perm: R | W, id: 1000 },
               e(ACL_GROUP_OBJ, R | X), e(ACL_MASK, R | W | X), e(ACL_OTHER, R | X)])
}

/// A directory carrying `blob` as its default ACL.
fn dir_with_default(fs: &Arc<F2fs>, blob: &[u8]) -> InodeRef {
    let root = fs.root_inode().expect("root");
    let dir = root.mkdir("d", 0o777, &CreateCtx::root()).expect("mkdir");
    dir.setxattr("system.posix_acl_default", blob.to_vec(), false, false).expect("set default acl");
    dir
}

#[test]
fn an_acl_written_through_the_interface_reads_back_in_the_interchange_form() {
    let fs = mounted_with("acl");
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    let blob = named_default_blob();
    file.setxattr("system.posix_acl_access", blob.clone(), false, false).unwrap();
    // What comes back is the interchange blob, not the stored record: the
    // boundary converts both ways, and the two forms are different bytes.
    assert_eq!(file.getxattr("system.posix_acl_access").unwrap(), blob);
    assert_ne!(crate::acl::to_disk(&vfs::posix_acl::from_xattr(&blob).unwrap()).unwrap(), blob);
}

#[test]
fn a_stored_record_this_filesystem_did_not_write_is_refused() {
    let fs = mounted_with("acl");
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    // A record, not an interchange blob: version 1 is not what setxattr carries.
    let record = crate::acl::to_disk(&[e(ACL_USER_OBJ, R), e(ACL_GROUP_OBJ, R), e(ACL_OTHER, R)])
        .unwrap();
    assert_eq!(file.setxattr("system.posix_acl_access", record, false, false),
               Err(vfs::xattr::XattrError::NotSup), "version 1 in, EOPNOTSUPP out");
}

#[test]
fn a_file_created_under_a_default_acl_takes_its_mode_from_the_acl() {
    let fs = mounted_with("acl");
    let dir = dir_with_default(&fs, &plain_default_blob());
    // umask 0777 would leave a mode of 0; the default ACL decides instead.
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &vfs::Cred::root(), umask: 0o777 };
    let file = dir.create_child("f", 0o666, &ctx).unwrap();
    assert_eq!(file.i_mode() & 0o777, 0o644, "the inherited ACL, not the umask");
    // Mode-equivalent, so nothing is stored and the file lists no ACL.
    assert!(!file.listxattr().unwrap().iter().any(|n| n.starts_with("system.posix_acl")));
}

#[test]
fn a_file_created_under_a_named_default_acl_stores_its_access_acl() {
    let fs = mounted_with("acl");
    let dir = dir_with_default(&fs, &named_default_blob());
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &vfs::Cred::root(), umask: 0o022 };
    let file = dir.create_child("f", 0o666, &ctx).unwrap();
    let got = vfs::posix_acl::from_xattr(&file.getxattr("system.posix_acl_access").unwrap())
        .unwrap();
    assert_eq!(got[1], AclEntry { tag: ACL_USER, perm: R | W, id: 1000 },
               "the named user is inherited");
    // The mask allows rwx so the group bits survive; OTHER only ever allowed r-x
    // in the template, so the requested `rw` for others is narrowed to `r`.
    assert_eq!(file.i_mode() & 0o777, 0o664);
    assert_eq!(file.getxattr("system.posix_acl_default"),
               Err(vfs::xattr::XattrError::NotFound), "a regular file inherits no default ACL");
}

#[test]
fn a_directory_created_under_a_default_acl_inherits_the_template() {
    let fs = mounted_with("acl");
    let blob = named_default_blob();
    let dir = dir_with_default(&fs, &blob);
    let sub = dir.mkdir("sub", 0o777, &CreateCtx::root()).unwrap();
    assert_eq!(sub.file_type(), FileType::Directory);
    assert_eq!(sub.getxattr("system.posix_acl_default").unwrap(), blob,
               "the template propagates down the tree verbatim");
    assert!(sub.getxattr("system.posix_acl_access").is_ok());
    // And it keeps propagating: the grandchild gets it too.
    let deep = sub.mkdir("deeper", 0o777, &CreateCtx::root()).unwrap();
    assert_eq!(deep.getxattr("system.posix_acl_default").unwrap(), blob);
}

#[test]
fn a_symlink_under_a_default_acl_inherits_nothing() {
    let fs = mounted_with("acl");
    let dir = dir_with_default(&fs, &plain_default_blob());
    dir.symlink_child("l", b"/elsewhere", &CreateCtx::root()).unwrap();
    let link = dir.lookup("l").unwrap();
    assert_eq!(link.i_mode() & 0o777, 0o777);
    assert_eq!(link.getxattr("system.posix_acl_access"), Err(vfs::xattr::XattrError::NotFound));
}

#[test]
fn without_the_acl_option_nothing_is_inherited_and_the_umask_decides() {
    let fs = mounted_with("noacl");
    let dir = dir_with_default(&fs, &plain_default_blob());
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &vfs::Cred::root(), umask: 0o022 };
    let file = dir.create_child("f", 0o666, &ctx).unwrap();
    assert_eq!(file.i_mode() & 0o777, 0o644, "the umask alone");
    assert_eq!(file.getxattr("system.posix_acl_access"), Err(vfs::xattr::XattrError::NotFound));
}

// The syscall-side half: `setxattr` of an ACCESS ACL is not a plain attribute
// write. It rewrites `i_mode` from the ACL, and an ACL the mode bits can express
// on their own is not stored at all — the mode IS the ACL in that case. This
// drives the same policy layer a real `setxattr(2)` reaches, over a real inode of
// this filesystem, which is what makes it a reachability proof rather than a
// restatement of the policy layer's own tests.
#[test]
fn setting_an_access_acl_through_the_syscall_layer_rewrites_the_mode() {
    let fs = mounted_with("acl");
    let root = fs.root_inode().unwrap();
    let c = fs::xattr::XattrCred::root();
    let file = root.create_child("f", 0o777, &CreateCtx::root()).unwrap();
    assert_eq!(file.i_mode() & 0o777, 0o777);

    // u::rw- g::r-- o::r-- — the mode bits say all of it.
    let equivalent = to_xattr(&[e(ACL_USER_OBJ, R | W), e(ACL_GROUP_OBJ, R), e(ACL_OTHER, R)]);
    assert_eq!(fs::xattr::vfs_setxattr(&file, "system.posix_acl_access", equivalent, 0, &c), Ok(()));
    assert_eq!(file.i_mode() & 0o777, 0o644, "the ACL rewrote the mode");
    assert_eq!(file.getxattr("system.posix_acl_access"), Err(vfs::xattr::XattrError::NotFound),
               "a mode-equivalent ACL is not stored");

    // Add a named user and it can no longer be expressed as mode bits: the mode
    // still follows the base entries, and now the record is stored too.
    let named = to_xattr(&[e(ACL_USER_OBJ, R | W), AclEntry { tag: ACL_USER, perm: R, id: 1000 },
                           e(ACL_GROUP_OBJ, R), e(ACL_MASK, R), e(ACL_OTHER, 0)]);
    assert_eq!(fs::xattr::vfs_setxattr(&file, "system.posix_acl_access", named.clone(), 0, &c),
               Ok(()));
    assert_eq!(file.i_mode() & 0o777, 0o640, "the mask supplies the group bits");
    assert_eq!(file.getxattr("system.posix_acl_access").unwrap(), named);
    // Removal takes the record away and leaves the mode where the ACL put it.
    assert_eq!(fs::xattr::vfs_removexattr(&file, "system.posix_acl_access", &c), Ok(()));
    assert_eq!(file.getxattr("system.posix_acl_access"), Err(vfs::xattr::XattrError::NotFound));
    assert_eq!(file.i_mode() & 0o777, 0o640);
}

// A default ACL on a non-directory is refused, and the refusal is the reason a
// file cannot acquire a template it would never apply.
#[test]
fn a_default_acl_on_a_regular_file_is_refused_through_the_syscall_layer() {
    let fs = mounted_with("acl");
    let root = fs.root_inode().unwrap();
    let c = fs::xattr::XattrCred::root();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    assert_eq!(fs::xattr::vfs_setxattr(&file, "system.posix_acl_default",
                                       plain_default_blob(), 0, &c),
               Err(-(syscall::errno::Errno::Eacces as i64)));
    let dir = root.mkdir("d", 0o755, &CreateCtx::root()).unwrap();
    assert_eq!(fs::xattr::vfs_setxattr(&dir, "system.posix_acl_default",
                                       plain_default_blob(), 0, &c), Ok(()));
    assert_eq!(fs::xattr::vfs_getxattr(&dir, "system.posix_acl_default", &c),
               Ok(plain_default_blob()));
}

#[test]
fn a_directory_with_no_default_acl_leaves_the_umask_to_decide() {
    let fs = mounted_with("acl");
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &vfs::Cred::root(), umask: 0o027 };
    let file = root.create_child("f", 0o666, &ctx).unwrap();
    assert_eq!(file.i_mode() & 0o777, 0o640);
}
