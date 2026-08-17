//! ENFORCEMENT: an ACL stored on the medium decides a permission check.
//!
//! Every assertion here is a verdict only an ACL can reach — a denial the mode
//! bits alone would grant, or a grant the mode bits alone would refuse — driven
//! through the real inode operations against a real image. A test that passed
//! whether or not the ACL was consulted would be measuring nothing, so each one
//! names the mode bits that would give the opposite answer.

use alloc::sync::Arc;
use alloc::vec::Vec;
use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::posix_acl::{to_xattr, AclEntry, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                     ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ, AclType};
use vfs::setattr::{Iattr, ATTR_MODE};
use vfs::{Cred, CreateCtx, GroupList, InodeRef, MAY_EXEC, MAY_READ, MAY_WRITE, VfsError};

use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

const R: u16 = 4;
const W: u16 = 2;

fn e(tag: u16, perm: u16) -> AclEntry { AclEntry { tag, perm, id: ACL_UNDEFINED_ID } }
fn named(tag: u16, perm: u16, id: u32) -> AclEntry { AclEntry { tag, perm, id } }

/// A caller with no capability of any kind — the only cred that can observe a
/// DAC decision, since `Cred::root` holds every override.
fn user(uid: u32, gid: u32, groups: &[u32]) -> Cred {
    Cred { uid, gid, cap_dac_override: false, cap_dac_read_search: false, cap_fowner: false,
           cap_chown: false, cap_fsetid: false, groups: GroupList::from_slice(groups) }
}

fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let bs = BLKSIZE as u32;
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(bs, bytes.len() as u64 / u64::from(bs));
    let mut req = BlockRequest::new_write(0, (bytes.len() / BLKSIZE) as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    let o = crate::opts::parse(&Options::defaults(), "acl").expect("options");
    F2fs::open_with(dev, "/dev/fake", true, o).expect("mount")
}

/// A file owned by uid 100 / gid 500 with `mode`, carrying `acl` as its access
/// ACL — stored through the real attribute boundary, so what the check reads is
/// what the MEDIUM holds.
fn file_with_acl(fs: &Arc<F2fs>, name: &str, mode: u32, acl: &[AclEntry]) -> InodeRef {
    let root = fs.root_inode().expect("root");
    let file = root.create_child(name, mode, &CreateCtx::root()).expect("create");
    file.setxattr("system.posix_acl_access", to_xattr(acl), false, false).expect("set acl");
    file.set_owner(100, 500).expect("owner");
    file
}

#[test]
fn a_stored_acl_denies_a_group_the_mode_bits_grant() {
    let fs = mounted();
    // Mode 0o664 grants the owning group WRITE. The ACL's mask narrows the group
    // class to read, so a member of group 500 must be refused — a verdict the
    // mode bits alone cannot produce.
    let acl = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R | W, 1000), e(ACL_GROUP_OBJ, R | W),
               e(ACL_MASK, R), e(ACL_OTHER, R)];
    let file = file_with_acl(&fs, "denied", 0o664, &acl);
    assert_eq!(file.i_mode() & 0o777, 0o664, "the mode bits themselves grant group write");
    let cred = user(700, 500, &[]);
    assert_eq!(file.permission(MAY_WRITE, &cred), Err(VfsError::Eacces),
               "the ACL mask refuses what the group mode bits allow");
    // Read is still granted, so the refusal above is the mask and not a blanket
    // failure of the check.
    assert_eq!(file.permission(MAY_READ, &cred), Ok(()));
}

#[test]
fn a_stored_acl_grants_a_named_user_the_mode_bits_deny() {
    let fs = mounted();
    // Mode 0o600: nobody but the owner gets anything. The ACL names uid 1000.
    let acl = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R | W, 1000), e(ACL_GROUP_OBJ, R),
               e(ACL_MASK, R | W), e(ACL_OTHER, 0)];
    let file = file_with_acl(&fs, "granted", 0o660, &acl);
    assert_eq!(file.permission(MAY_WRITE, &user(1000, 9, &[])), Ok(()),
               "the named user is granted by the ACL alone");
    // Anyone else lands on `other`, which grants nothing.
    assert_eq!(file.permission(MAY_READ, &user(1001, 9, &[])), Err(VfsError::Eacces));
}

#[test]
fn a_named_group_in_the_acl_decides_a_supplementary_group_member() {
    let fs = mounted();
    let acl = [e(ACL_USER_OBJ, R | W), e(ACL_GROUP_OBJ, 0), named(ACL_GROUP, R | W, 2000),
               e(ACL_MASK, R | W), e(ACL_OTHER, 0)];
    let file = file_with_acl(&fs, "namedgroup", 0o660, &acl);
    assert_eq!(file.permission(MAY_WRITE, &user(700, 9, &[2000])), Ok(()));
    // A caller in no listed group falls to `other`.
    assert_eq!(file.permission(MAY_READ, &user(700, 9, &[2001])), Err(VfsError::Eacces));
}

#[test]
fn a_caller_matching_a_group_class_is_never_passed_on_to_other() {
    let fs = mounted();
    // `other` grants read; the owning group grants nothing. A member of the
    // owning group asking to read is REFUSED — the mode bits would grant it via
    // the other class if the walk fell through.
    let acl = [e(ACL_USER_OBJ, R | W), e(ACL_GROUP_OBJ, 0), named(ACL_GROUP, W, 2000),
               e(ACL_MASK, R | W), e(ACL_OTHER, R)];
    let file = file_with_acl(&fs, "noFallThrough", 0o664, &acl);
    assert_eq!(file.permission(MAY_READ, &user(700, 500, &[])), Err(VfsError::Eacces));
    assert_eq!(file.permission(MAY_READ, &user(700, 9, &[])), Ok(()), "a non-member does read");
}

#[test]
fn the_owner_is_decided_by_the_mode_bits_and_not_by_the_acl() {
    let fs = mounted();
    // USER_OBJ says read-only, the mode's owner bits say read-write. The owner
    // check runs ahead of the ACL, so the mode bits win — and the two are
    // deliberately inconsistent here so the test can tell which was used.
    let acl = [e(ACL_USER_OBJ, R), named(ACL_USER, R, 1000), e(ACL_GROUP_OBJ, R),
               e(ACL_MASK, R), e(ACL_OTHER, R)];
    let file = file_with_acl(&fs, "owner", 0o644, &acl);
    assert_eq!(file.permission(MAY_WRITE, &user(100, 500, &[])), Ok(()));
}

#[test]
fn an_acl_denial_is_still_overridable_by_the_dac_capability() {
    let fs = mounted();
    // Mode 0o646 grants write through the OTHER class, so the refusal below can
    // only come from the ACL: the control for this test is that removing the
    // ACL consult turns the first assertion green.
    let acl = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R, 1000), e(ACL_GROUP_OBJ, R),
               e(ACL_MASK, R), e(ACL_OTHER, R | W)];
    let file = file_with_acl(&fs, "capped", 0o646, &acl);
    let mut cred = user(1000, 9, &[]);
    assert_eq!(file.permission(MAY_WRITE, &cred), Err(VfsError::Eacces),
               "the named entry refuses what the other-class mode bits grant");
    cred.cap_dac_override = true;
    assert_eq!(file.permission(MAY_WRITE, &cred), Ok(()),
               "the capability rungs run after the ACL, not instead of it");
}

#[test]
fn a_stored_record_that_cannot_be_decoded_refuses_rather_than_falling_back() {
    let fs = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("corrupt", 0o666, &CreateCtx::root()).unwrap();
    file.set_owner(100, 500).expect("owner");
    // A record the medium's own reader rejects, written past the boundary that
    // would have converted it.
    let node = super::F2fsOps::node(&file).unwrap();
    let junk: Vec<u8> = alloc::vec![1, 0, 0, 0, 9, 9];
    fs.volume_now().set_xattr(node.ino, crate::acl::name_access(), Some(&junk), false, false)
        .expect("store raw");
    // Mode 0o666 would grant every caller write; the unreadable ACL does not.
    assert!(matches!(file.permission(MAY_WRITE, &user(700, 9, &[])),
                     Err(VfsError::Einval) | Err(VfsError::Eio) | Err(VfsError::Euclean)),
            "an ACL that will not decode is reported, not ignored");
}

#[test]
fn a_write_to_the_acl_is_seen_by_the_next_check() {
    let fs = mounted();
    let acl = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R | W, 1000), e(ACL_GROUP_OBJ, R),
               e(ACL_MASK, R | W), e(ACL_OTHER, 0)];
    let file = file_with_acl(&fs, "recached", 0o660, &acl);
    let cred = user(1000, 9, &[]);
    assert_eq!(file.permission(MAY_WRITE, &cred), Ok(()));
    // Replace the ACL with one that refuses the same caller. The first check
    // above cached the old entries, so this only passes if the write dropped it.
    let tighter = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R, 1000), e(ACL_GROUP_OBJ, R),
                   e(ACL_MASK, R), e(ACL_OTHER, 0)];
    file.setxattr("system.posix_acl_access", to_xattr(&tighter), false, false).unwrap();
    assert_eq!(file.permission(MAY_WRITE, &cred), Err(VfsError::Eacces));
    // And removing it entirely hands the decision back to the mode bits, which
    // grant the owning group read and nothing to anyone else.
    file.removexattr("system.posix_acl_access").unwrap();
    assert_eq!(file.permission(MAY_READ, &user(700, 500, &[])), Ok(()));
    assert_eq!(file.get_inode_acl(AclType::Access).unwrap(), None);
}

#[test]
fn a_chmod_narrows_the_acl_and_not_only_the_mode_bits() {
    let fs = mounted();
    let acl = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R | W, 1000), e(ACL_GROUP_OBJ, R),
               e(ACL_MASK, R | W), e(ACL_OTHER, R)];
    let file = file_with_acl(&fs, "chmodded", 0o664, &acl);
    let cred = user(1000, 9, &[]);
    assert_eq!(file.permission(MAY_WRITE, &cred), Ok(()));
    // chmod 0o600: the group class loses everything, so the named user's rw is
    // masked to nothing. Without the ACL rewrite the entry would keep granting.
    let ia = Iattr { valid: ATTR_MODE, mode: 0o600, ..Iattr::default() };
    file.setattr(&vfs::IDENTITY, &ia).expect("chmod");
    assert_eq!(file.permission(MAY_WRITE, &cred), Err(VfsError::Eacces));
    assert_eq!(file.permission(MAY_READ, &cred), Err(VfsError::Eacces));
    // The stored ACL is what changed, not just the check: re-reading the medium
    // reports the narrowed mask.
    let got = file.getxattr("system.posix_acl_access").expect("acl still stored");
    let entries = vfs::posix_acl::from_xattr(&got).unwrap();
    assert_eq!(entries.iter().find(|x| x.tag == ACL_MASK).unwrap().perm, 0,
               "chmod 0600 leaves the mask granting nothing");
}

#[test]
fn a_chmod_drops_an_acl_the_mode_bits_can_express_on_their_own() {
    let fs = mounted();
    // No named entry and no mask: the three base entries say all of it.
    let acl = [e(ACL_USER_OBJ, R | W), e(ACL_GROUP_OBJ, R), e(ACL_OTHER, R)];
    let file = file_with_acl(&fs, "equiv", 0o644, &acl);
    let ia = Iattr { valid: ATTR_MODE, mode: 0o600, ..Iattr::default() };
    file.setattr(&vfs::IDENTITY, &ia).expect("chmod");
    assert_eq!(file.get_inode_acl(AclType::Access).unwrap(), None,
               "an equivalent ACL is removed rather than kept alongside the mode");
    assert_eq!(file.permission(MAY_READ, &user(700, 500, &[])), Err(VfsError::Eacces));
}

#[test]
fn an_inherited_acl_is_enforced_on_the_object_that_inherited_it() {
    let fs = mounted();
    let root = fs.root_inode().unwrap();
    let dir = root.mkdir("d", 0o777, &CreateCtx::root()).unwrap();
    // A default ACL naming uid 1000, so every file created under it carries an
    // access ACL that grants that one caller and nobody else.
    let default = [e(ACL_USER_OBJ, R | W), named(ACL_USER, R | W, 1000), e(ACL_GROUP_OBJ, 0),
                   e(ACL_MASK, R | W), e(ACL_OTHER, 0)];
    dir.setxattr("system.posix_acl_default", to_xattr(&default), false, false).unwrap();
    let file = dir.create_child("f", 0o666, &CreateCtx::root()).unwrap();
    file.set_owner(100, 500).expect("owner");
    assert_eq!(file.permission(MAY_WRITE, &user(1000, 9, &[])), Ok(()),
               "the create-time inheritance is enforced, not merely stored");
    assert_eq!(file.permission(MAY_READ, &user(1001, 9, &[])), Err(VfsError::Eacces));
}

#[test]
fn an_object_with_no_acl_is_decided_by_the_mode_bits_alone() {
    let fs = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("plain", 0o640, &CreateCtx::root()).unwrap();
    file.set_owner(100, 500).expect("owner");
    assert_eq!(file.get_inode_acl(AclType::Access).unwrap(), None);
    assert_eq!(file.permission(MAY_READ, &user(700, 500, &[])), Ok(()));
    assert_eq!(file.permission(MAY_WRITE, &user(700, 500, &[])), Err(VfsError::Eacces));
    assert_eq!(file.permission(MAY_READ, &user(700, 9, &[])), Err(VfsError::Eacces));
    assert_eq!(file.permission(MAY_EXEC, &user(100, 500, &[])), Err(VfsError::Eacces));
}
