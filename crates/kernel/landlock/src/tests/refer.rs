// Reparenting admission. A move that is refused for the wrong reason is as
// much of a bug as one that is allowed: a caller distinguishes "never
// possible" from "copy instead of move" purely by the errno.

use super::*;
use crate::abi::RulesetAttr;
use crate::domain::Domain;
use crate::ruleset::Ruleset;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder};

fn dir_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
                      default_inode_ops(), default_file_ops()).build()
}
fn reg_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), default_file_ops()).build()
}

fn path(dentry: Arc<Dentry>) -> VfsPath {
    let inode = dentry.inode().expect("test dentry inode");
    VfsPath { mnt_id: 1, dentry, inode, last_component: None }
}

fn target(d: &Arc<Dentry>) -> Target {
    Target { dentry: d.clone(), inode: d.inode().expect("test dentry inode") }
}

const ALL: AccessMask = ACCESS_FS_REFER | ACCESS_FS_MAKE_REG | ACCESS_FS_REMOVE_FILE;

fn dom(rules: &[(&Arc<Dentry>, AccessMask)], handled: AccessMask) -> Arc<Domain> {
    let rs = Ruleset::new(&RulesetAttr { handled_fs: handled, ..Default::default() });
    for (d, a) in rules { rs.add_fs(d.inode().unwrap(), true, *a, 0).unwrap(); }
    Domain::merge(None, &rs).unwrap()
}

/// `/a/f` and `/b`, with `f` a regular file.
fn tree() -> (Arc<Dentry>, Arc<Dentry>, Arc<Dentry>, Arc<Dentry>) {
    let root = Dentry::new_root(dir_inode(1));
    let a = vfs::d_add(&root, "a", dir_inode(2));
    let b = vfs::d_add(&root, "b", dir_inode(3));
    let f = vfs::d_add(&a, "f", reg_inode(4));
    (root, a, b, f)
}

#[test]
fn a_rename_within_one_directory_needs_no_reparenting_right() {
    // Nothing changes hierarchy, so a policy that never grants the reparenting
    // right must still allow it.
    let (_root, a, _b, f) = tree();
    let d = dom(&[(&a, ACCESS_FS_MAKE_REG | ACCESS_FS_REMOVE_FILE)],
                ACCESS_FS_MAKE_REG | ACCESS_FS_REMOVE_FILE);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(a), None, true, false), Ok(()));
}

#[test]
fn a_same_directory_rename_is_still_refused_without_the_creation_right() {
    let (_root, a, _b, f) = tree();
    let d = dom(&[(&a, ACCESS_FS_REMOVE_FILE)], ACCESS_FS_MAKE_REG | ACCESS_FS_REMOVE_FILE);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(a), None, true, false),
               Err(Errno::Eacces));
}

#[test]
fn moving_between_directories_needs_the_reparenting_right_on_both() {
    let (_root, a, b, f) = tree();
    // Both sides carry every needed right: allowed.
    let d = dom(&[(&a, ALL), (&b, ALL)], ALL);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(b.clone()), None, true, false),
               Ok(()));

    // The destination lacks the reparenting right: the hierarchies cannot be
    // compared, which is the cross-device answer, not a permission one.
    let d = dom(&[(&a, ALL), (&b, ACCESS_FS_MAKE_REG | ACCESS_FS_REMOVE_FILE)], ALL);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(b.clone()), None, true, false),
               Err(Errno::Exdev));
}

#[test]
fn a_missing_creation_right_on_the_destination_is_a_permission_error() {
    // Permission outranks the cross-device answer so the caller learns that
    // copying into the destination is impossible too.
    let (_root, a, b, f) = tree();
    let d = dom(&[(&a, ALL), (&b, ACCESS_FS_REFER)], ALL);
    assert_eq!(check(&d, &path(a), &target(&f), &path(b), None, true, false),
               Err(Errno::Eacces));
}

#[test]
fn a_missing_removal_right_on_the_source_is_a_permission_error() {
    let (_root, a, b, f) = tree();
    let d = dom(&[(&a, ACCESS_FS_REFER | ACCESS_FS_MAKE_REG), (&b, ALL)], ALL);
    assert_eq!(check(&d, &path(a), &target(&f), &path(b), None, true, false),
               Err(Errno::Eacces));
}

#[test]
fn linking_needs_creation_but_not_removal() {
    // A link leaves the source name in place, so the source directory is not
    // asked for the removal right.
    let (_root, a, b, f) = tree();
    let d = dom(&[(&a, ACCESS_FS_REFER), (&b, ACCESS_FS_REFER | ACCESS_FS_MAKE_REG)],
                ALL);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(b.clone()), None, false, false),
               Ok(()));
    // The same operation as a rename additionally needs removal on the source.
    assert_eq!(check(&d, &path(a), &target(&f), &path(b), None, true, false),
               Err(Errno::Eacces));
}

#[test]
fn the_creation_right_asked_for_follows_the_moved_object_type() {
    // Moving a directory asks for the directory-creation right, not the
    // regular-file one; granting the wrong one must not authorise the move.
    let root = Dentry::new_root(dir_inode(1));
    let a = vfs::d_add(&root, "a", dir_inode(2));
    let b = vfs::d_add(&root, "b", dir_inode(3));
    let sub = vfs::d_add(&a, "sub", dir_inode(4));
    let all_dir = ACCESS_FS_REFER | ACCESS_FS_MAKE_DIR | ACCESS_FS_REMOVE_DIR;
    let handled = all_dir | ACCESS_FS_MAKE_REG;
    let d = dom(&[(&a, all_dir), (&b, ACCESS_FS_REFER | ACCESS_FS_MAKE_REG)], handled);
    assert_eq!(check(&d, &path(a.clone()), &target(&sub), &path(b.clone()), None, true, false),
               Err(Errno::Eacces));
    let d = dom(&[(&a, all_dir), (&b, all_dir)], handled);
    assert_eq!(check(&d, &path(a), &target(&sub), &path(b), None, true, false), Ok(()));
}

#[test]
fn an_exchange_is_admitted_in_both_directions() {
    let (_root, a, b, f) = tree();
    let g = vfs::d_add(&b, "g", reg_inode(5));
    let d = dom(&[(&a, ALL), (&b, ALL)], ALL);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(b.clone()),
                     Some(&target(&g)), true, true), Ok(()));
    // Removing the destination's rights breaks the direction that moves g.
    let d = dom(&[(&a, ALL), (&b, ACCESS_FS_REFER)], ALL);
    assert_eq!(check(&d, &path(a), &target(&f), &path(b), Some(&target(&g)), true, true),
               Err(Errno::Eacces));
}

#[test]
fn any_domain_refuses_reparenting_until_it_explicitly_grants_it() {
    // Reparenting is the one right denied by default. A policy that never
    // mentions it — here a read-only filesystem policy — still forbids moving a
    // file between directories, because otherwise a hierarchy could be walked
    // out from under the policy that constrains it. The answer is the
    // cross-device error, which tells the caller to copy instead.
    let (root, a, b, f) = tree();
    let d = dom(&[(&root, ACCESS_FS_READ_FILE)], ACCESS_FS_READ_FILE);
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(b), None, true, false),
               Err(Errno::Exdev));
    // The same policy leaves a rename inside one directory alone.
    assert_eq!(check(&d, &path(a.clone()), &target(&f), &path(a), None, true, false), Ok(()));
}

#[test]
fn an_exchange_with_no_destination_object_is_refused_as_missing() {
    let (_root, a, b, f) = tree();
    let d = dom(&[(&a, ALL), (&b, ALL)], ALL);
    assert_eq!(check(&d, &path(a), &target(&f), &path(b), None, true, true),
               Err(Errno::Enoent));
}

#[test]
fn disconnected_source_and_saved_mount_root_rights_are_combined() {
    // `old_dir` has been moved out from under the bind mount represented by
    // `mount_root`: the two dentries deliberately belong to disjoint trees.
    // Removal is granted only on the disconnected filesystem ancestry, while
    // creation and REFER are granted only on the saved mount-root ancestry.
    // The operation is valid only when the real refer path evaluates both.
    let old_root = Dentry::new_root(dir_inode(10));
    let old_dir = vfs::d_add(&old_root, "outside", dir_inode(11));
    let file = vfs::d_add(&old_dir, "f", reg_inode(12));
    let mount_root = Dentry::new_root(dir_inode(20));
    let new_dir = vfs::d_add(&mount_root, "inside", dir_inode(21));

    let mount_rights = ACCESS_FS_REFER | ACCESS_FS_MAKE_REG;
    let d = dom(&[(&old_root, ACCESS_FS_REMOVE_FILE), (&mount_root, mount_rights)], ALL);
    assert_eq!(check(&d, &path(old_dir.clone()), &target(&file), &path(new_dir.clone()),
                     None, true, false), Ok(()));

    let d = dom(&[(&mount_root, mount_rights)], ALL);
    assert_eq!(check(&d, &path(old_dir.clone()), &target(&file), &path(new_dir.clone()),
                     None, true, false),
               Err(Errno::Eacces));

    let d = dom(&[(&old_root, ACCESS_FS_REMOVE_FILE)], ALL);
    assert_eq!(check(&d, &path(old_dir), &target(&file), &path(new_dir), None, true, false),
               Err(Errno::Eacces));
}
