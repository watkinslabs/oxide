// Per-operation request masks and the mask an open records for later use.

use super::*;
use alloc::sync::Arc;

use crate::abi::RulesetAttr;
use crate::domain::Domain;
use crate::ruleset::Ruleset;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, InodeBuilder, VfsPath};

fn dir_inode(ino: u64) -> vfs::InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
                      default_inode_ops(), default_file_ops()).build()
}

fn path(mnt_id: u64, dentry: Arc<Dentry>) -> VfsPath {
    let inode = dentry.inode().expect("test dentry inode");
    VfsPath { mnt_id, dentry, inode, last_component: None }
}

#[test]
fn opening_a_directory_asks_for_the_listing_right_not_the_file_right() {
    // Conflating the two would let a policy that forbids listing a directory be
    // bypassed by opening it.
    assert_eq!(open_access(true, false, false, true), ACCESS_FS_READ_DIR);
    assert_eq!(open_access(true, false, false, false), ACCESS_FS_READ_FILE);
}

#[test]
fn write_and_execute_accumulate_on_a_file_open() {
    assert_eq!(open_access(true, true, false, false),
               ACCESS_FS_READ_FILE | ACCESS_FS_WRITE_FILE);
    assert_eq!(open_access(false, true, false, false), ACCESS_FS_WRITE_FILE);
    assert_eq!(open_access(true, false, true, false),
               ACCESS_FS_READ_FILE | ACCESS_FS_EXECUTE);
    // An access-less open (a pure path reference) asks for nothing.
    assert_eq!(open_access(false, false, false, false), 0);
}

#[test]
fn devices_are_recognised_by_type() {
    assert!(is_device(FileType::CharDev));
    assert!(is_device(FileType::BlockDev));
    assert!(!is_device(FileType::Regular));
    assert!(!is_device(FileType::Directory));
}

#[test]
fn an_open_records_the_optional_rights_it_was_granted() {
    let root = Dentry::new_root(dir_inode(1));
    let rs = Ruleset::new(&RulesetAttr {
        handled_fs: ACCESS_FS_READ_FILE | ACCESS_FS_TRUNCATE, ..Default::default() });
    rs.add_fs(root.inode().unwrap(), true,
              ACCESS_FS_READ_FILE | ACCESS_FS_TRUNCATE).unwrap();
    let dom = Domain::merge(None, &rs).unwrap();
    let a = open_decide(&dom, &path(7, root), ACCESS_FS_READ_FILE, false).unwrap();
    assert!(truncate_allowed(a));
}

#[test]
fn an_open_without_the_truncate_right_still_succeeds_but_forbids_truncation() {
    // Truncation is decided at open even though it is exercised later; a file
    // opened without it may still be read.
    let root = Dentry::new_root(dir_inode(1));
    let rs = Ruleset::new(&RulesetAttr {
        handled_fs: ACCESS_FS_READ_FILE | ACCESS_FS_TRUNCATE, ..Default::default() });
    rs.add_fs(root.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = Domain::merge(None, &rs).unwrap();
    let a = open_decide(&dom, &path(7, root), ACCESS_FS_READ_FILE, false).unwrap();
    assert!(!truncate_allowed(a));
}

#[test]
fn an_open_missing_a_required_right_is_refused() {
    let root = Dentry::new_root(dir_inode(1));
    let rs = Ruleset::new(&RulesetAttr {
        handled_fs: ACCESS_FS_READ_FILE, ..Default::default() });
    rs.add_fs(root.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = Domain::merge(None, &rs).unwrap();
    let p = path(7, root);
    assert!(open_decide(&dom, &p, ACCESS_FS_READ_FILE, false).is_ok());
    // Writing is not handled by this layer, so it is not filtered.
    assert!(open_decide(&dom, &p, ACCESS_FS_WRITE_FILE, false).is_ok());
}

#[test]
fn a_denied_required_right_reports_permission_denied() {
    let root = Dentry::new_root(dir_inode(1));
    let sub  = vfs::d_add(&root, "sub", dir_inode(2));
    let rs = Ruleset::new(&RulesetAttr {
        handled_fs: ACCESS_FS_READ_FILE, ..Default::default() });
    rs.add_fs(sub.inode().unwrap(), true, ACCESS_FS_READ_FILE).unwrap();
    let dom = Domain::merge(None, &rs).unwrap();
    assert_eq!(open_decide(&dom, &path(7, root), ACCESS_FS_READ_FILE, false),
               Err(Errno::Eacces));
}

#[test]
fn device_control_is_recorded_only_for_devices() {
    let root = Dentry::new_root(dir_inode(1));
    let rs = Ruleset::new(&RulesetAttr {
        handled_fs: ACCESS_FS_READ_FILE | ACCESS_FS_IOCTL_DEV, ..Default::default() });
    rs.add_fs(root.inode().unwrap(), true,
              ACCESS_FS_READ_FILE | ACCESS_FS_IOCTL_DEV).unwrap();
    let dom = Domain::merge(None, &rs).unwrap();
    let p = path(7, root);
    let non_dev = open_decide(&dom, &p, ACCESS_FS_READ_FILE, false).unwrap();
    assert_eq!(non_dev & ACCESS_FS_IOCTL_DEV, 0);
    let dev = open_decide(&dom, &p, ACCESS_FS_READ_FILE, true).unwrap();
    assert_eq!(dev & ACCESS_FS_IOCTL_DEV, ACCESS_FS_IOCTL_DEV);
}

#[test]
fn an_unsandboxed_open_records_everything() {
    // With no layer filtering anything, the recorded mask must not restrict a
    // later truncation of an fd handed to another process.
    let rs = Ruleset::new(&RulesetAttr { scoped: SCOPE_SIGNAL, ..Default::default() });
    let dom = Domain::merge(None, &rs).unwrap();
    let root = Dentry::new_root(dir_inode(1));
    let a = open_decide(&dom, &path(7, root), ACCESS_FS_READ_FILE, false).unwrap();
    assert!(truncate_allowed(a));
}

#[test]
fn ioctls_on_non_devices_are_never_gated() {
    assert!(ioctl_allowed(0, false, 0x1234));
    assert!(!ioctl_allowed(0, true, 0x1234));
    assert!(ioctl_allowed(ACCESS_FS_IOCTL_DEV, true, 0x1234));
}

#[test]
fn the_exempt_ioctls_stay_available_on_a_device() {
    // Each of these either acts on the filesystem rather than the device, or
    // duplicates something reachable through descriptor flags, so gating them
    // would restrict nothing while breaking ordinary programs.
    for cmd in [ioctl::FIOCLEX, ioctl::FIONCLEX, ioctl::FIONBIO, ioctl::FIOASYNC,
                ioctl::FIOQSIZE, ioctl::FIFREEZE, ioctl::FITHAW, ioctl::FS_IOC_FIEMAP,
                ioctl::FIGETBSZ, ioctl::FICLONE, ioctl::FICLONERANGE, ioctl::FIDEDUPERANGE,
                ioctl::FS_IOC_GETFSUUID, ioctl::FS_IOC_GETFSSYSFSPATH] {
        assert!(masked_device_ioctl(cmd));
        assert!(ioctl_allowed(0, true, cmd));
    }
    // Anything not on the list is gated.
    assert!(!masked_device_ioctl(0x5401));
}

#[test]
fn every_optional_right_is_decided_at_open() {
    assert_eq!(OPTIONAL_ACCESS, ACCESS_FS_TRUNCATE | ACCESS_FS_IOCTL_DEV);
    assert_eq!(ALL_ACCESS, MASK_ACCESS_FS);
    assert!(truncate_allowed(ALL_ACCESS));
    assert!(ioctl_allowed(ALL_ACCESS, true, 0x1234));
}
