// The stored ACL record's layout and error contract, and the create-time
// inheritance decision. The record is version 1 with variable-length entries;
// the interchange blob is version 2 with fixed ones, so a byte-for-byte
// comparison of the two forms is the point of most of this.

use super::*;

const R: u16 = 4;
const W: u16 = 2;
const X: u16 = 1;

fn e(tag: u16, perm: u16) -> AclEntry { AclEntry { tag, perm, id: ACL_UNDEFINED_ID } }
fn named(tag: u16, perm: u16, id: u32) -> AclEntry { AclEntry { tag, perm, id } }

/// u::rwx g::r-x o::r-x, no named entry and no mask.
fn plain() -> Vec<AclEntry> {
    alloc::vec![e(ACL_USER_OBJ, R | W | X), e(ACL_GROUP_OBJ, R | X), e(ACL_OTHER, R | X)]
}

/// The same plus a named user, which forces a mask.
fn with_named() -> Vec<AclEntry> {
    alloc::vec![e(ACL_USER_OBJ, R | W | X), named(ACL_USER, R | W, 1000),
                e(ACL_GROUP_OBJ, R | X), e(ACL_MASK, R | W | X), e(ACL_OTHER, R | X)]
}

#[test]
fn the_stored_record_is_version_one_with_variable_length_entries() {
    let disk = to_disk(&plain()).unwrap();
    assert_eq!(disk.len(), 4 + 3 * 4, "three entries that name no id are four bytes each");
    assert_eq!(&disk[..4], &1u32.to_le_bytes(), "version 1, not the interchange version 2");
    assert_eq!(&disk[4..8], &[ACL_USER_OBJ as u8, 0, 7, 0]);
    assert_eq!(from_disk(&disk), Ok(plain()));

    let disk = to_disk(&with_named()).unwrap();
    assert_eq!(disk.len(), 4 + 4 * 4 + 8, "only the named entry carries the id word");
    assert_eq!(&disk[8..16], &[ACL_USER as u8, 0, 6, 0, 0xe8, 3, 0, 0], "id 1000 follows tag+perm");
    assert_eq!(from_disk(&disk), Ok(with_named()));
}

#[test]
fn the_stored_record_and_the_interchange_blob_are_not_the_same_bytes() {
    let wire = vfs::posix_acl::to_xattr(&with_named());
    let disk = to_disk(&with_named()).unwrap();
    assert_ne!(wire, disk, "storing the interchange blob verbatim would be the defect");
    assert_eq!(wire.len(), 4 + 5 * 8);
    // Each direction of the boundary conversion is the other's inverse.
    assert_eq!(disk_from_xattr(&wire), Ok(disk.clone()));
    assert_eq!(xattr_from_disk(&disk), Ok(wire));
    // A record written by this filesystem is not a legal interchange blob, and
    // an interchange blob is not a legal record.
    assert_eq!(vfs::posix_acl::from_xattr(&disk), Err(Errno::Eopnotsupp));
    assert_eq!(from_disk(&vfs::posix_acl::to_xattr(&plain())), Err(Errno::Einval));
}

#[test]
fn a_malformed_record_reports_argument_or_medium_by_which_field_is_wrong() {
    assert_eq!(from_disk(&[]), Err(Errno::Einval), "no header");
    assert_eq!(from_disk(&[1, 0, 0]), Err(Errno::Einval), "short header");
    assert_eq!(from_disk(&[2, 0, 0, 0]), Err(Errno::Einval), "interchange version");
    assert_eq!(from_disk(&[1, 0, 0, 0, 1, 0, 7]), Err(Errno::Einval), "not a whole number of records");
    assert_eq!(from_disk(&[1, 0, 0, 0]), Ok(alloc::vec![]), "an empty record is no ACL");
    // A named entry in the last four bytes claims an id word that is not there:
    // the size said four records, the tags need more than the region holds.
    assert_eq!(from_disk(&[1, 0, 0, 0, ACL_USER as u8, 0, 6, 0]), Err(Errno::Euclean));
    assert_eq!(from_disk(&[1, 0, 0, 0, 0x40, 0, 6, 0]), Err(Errno::Einval), "unknown tag");
    assert_eq!(to_disk(&[e(0x40, R)]), Err(Errno::Einval), "unknown tag on the write side");
}

#[test]
fn a_parent_without_a_default_acl_leaves_the_umask_to_decide() {
    let got = inherit(None, 0o777, 0o022, NewKind::Other, true).unwrap();
    assert_eq!(got, Inherited { mode: 0o755, access: None, default: None });
    // The mount option off is the same decision, default ACL or not.
    let d = to_disk(&plain()).unwrap();
    let got = inherit(Some(&d), 0o777, 0o022, NewKind::Other, false).unwrap();
    assert_eq!(got, Inherited { mode: 0o755, access: None, default: None },
               "noacl inherits nothing and takes the umask");
}

#[test]
fn a_parent_with_a_default_acl_decides_the_mode_instead_of_the_umask() {
    let d = to_disk(&plain()).unwrap();
    let got = inherit(Some(&d), 0o666, 0o777, NewKind::Other, true).unwrap();
    assert_eq!(got.mode, 0o644, "the umask never reaches a mode the default ACL decided");
    assert_eq!(got.access, None, "mode-equivalent: no record stored");
    assert_eq!(got.default, None, "a regular file inherits no default ACL");
}

#[test]
fn a_new_directory_inherits_the_default_acl_verbatim() {
    let d = to_disk(&with_named()).unwrap();
    let got = inherit(Some(&d), 0o2751, 0o022, NewKind::Dir, true).unwrap();
    assert_eq!(got.default.as_deref(), Some(&d[..]), "the template propagates unchanged");
    assert_eq!(got.mode, 0o2751, "the set-group-id bit survives the fold");
    let access = from_disk(got.access.as_deref().expect("a named user must be stored")).unwrap();
    assert_eq!(access[1], named(ACL_USER, R | W, 1000), "named entries are not narrowed");
    assert_eq!(access[3].perm, R | X, "the mask narrowed to the requested group bits");
    assert_eq!(access[4].perm, X, "OTHER narrowed to the requested other bits");
}

#[test]
fn a_new_symlink_inherits_nothing_and_keeps_its_mode() {
    let d = to_disk(&plain()).unwrap();
    let got = inherit(Some(&d), 0o777, 0o077, NewKind::Symlink, true).unwrap();
    assert_eq!(got, Inherited { mode: 0o777, access: None, default: None });
}

#[test]
fn a_parent_whose_record_cannot_be_read_fails_the_create() {
    assert_eq!(inherit(Some(&[1, 0, 0, 0, 0x40, 0, 6, 0]), 0o666, 0o022, NewKind::Other, true),
               Err(Errno::Einval), "a create must not silently fall back to the umask");
    // Nothing in the record can carry the group bits: the medium disagrees with
    // itself, which is EIO rather than a bad argument.
    let broken = to_disk(&[e(ACL_USER_OBJ, R), e(ACL_OTHER, R)]).unwrap();
    assert_eq!(inherit(Some(&broken), 0o666, 0o022, NewKind::Other, true), Err(Errno::Eio));
}

#[test]
fn the_two_acl_names_are_the_ones_the_index_table_registers() {
    assert_eq!(name_access(), "system.posix_acl_access");
    assert_eq!(name_default(), "system.posix_acl_default");
    assert!(is_acl_name(name_access()) && is_acl_name(name_default()));
    assert!(!is_acl_name("user.colour"));
}
