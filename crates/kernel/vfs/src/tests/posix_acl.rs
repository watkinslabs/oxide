// The externally-defined POSIX-ACL contract: the interchange codec, the entry
// sequence rule, the mode fold, and the create-time inheritance decision with
// its exact ordering (symlink exempt → no default ACL means umask → a default
// ACL means the umask is ignored and the masq decides both mode and stored ACL).

use super::*;

const R: u16 = 4;
const W: u16 = 2;
const X: u16 = 1;

fn e(tag: u16, perm: u16) -> AclEntry { AclEntry { tag, perm, id: ACL_UNDEFINED_ID } }
fn named(tag: u16, perm: u16, id: u32) -> AclEntry { AclEntry { tag, perm, id } }

/// u::rwx g::r-x o::r-x — the classic "no named entry, no mask" default ACL.
fn plain_default() -> alloc::vec::Vec<AclEntry> {
    alloc::vec![e(ACL_USER_OBJ, R | W | X), e(ACL_GROUP_OBJ, R | X), e(ACL_OTHER, R | X)]
}

#[test]
fn xattr_codec_round_trips_and_rejects_malformed_blobs() {
    let acl = alloc::vec![e(ACL_USER_OBJ, R | W), named(ACL_USER, R, 1000),
                          e(ACL_GROUP_OBJ, R), e(ACL_MASK, R | W), e(ACL_OTHER, 0)];
    let blob = to_xattr(&acl);
    assert_eq!(blob.len(), ACL_HDR_LEN + 5 * ACL_ENTRY_LEN);
    assert_eq!(&blob[..4], &ACL_XATTR_VERSION.to_le_bytes());
    assert_eq!(from_xattr(&blob), Ok(acl));
    // An empty entry list is a legal blob and decodes to Linux's NULL ACL.
    assert_eq!(from_xattr(&to_xattr(&[])), Ok(alloc::vec![]));
    assert_eq!(from_xattr(&[]), Err(Errno::Einval), "no header");
    assert_eq!(from_xattr(&[0, 0, 0]), Err(Errno::Einval), "short header");
    assert_eq!(from_xattr(&[1, 0, 0, 0]), Err(Errno::Eopnotsupp), "on-disk version 1 is not the wire version");
    assert_eq!(from_xattr(&[2, 0, 0, 0, 1, 0, 7, 0]), Err(Errno::Einval), "entry runs short");
}

#[test]
fn validate_enforces_the_entry_sequence_and_the_mandatory_mask() {
    assert_eq!(validate(&plain_default()), Ok(()));
    assert_eq!(validate(&[e(ACL_USER_OBJ, R), named(ACL_USER, R, 7), e(ACL_GROUP_OBJ, R),
                          e(ACL_MASK, R), e(ACL_OTHER, R)]), Ok(()));
    assert_eq!(validate(&[e(ACL_USER_OBJ, R), named(ACL_USER, R, 7), e(ACL_GROUP_OBJ, R),
                          e(ACL_OTHER, R)]), Err(Errno::Einval), "a named user demands a mask");
    assert_eq!(validate(&[e(ACL_GROUP_OBJ, R), e(ACL_USER_OBJ, R), e(ACL_OTHER, R)]),
               Err(Errno::Einval), "out of order");
    assert_eq!(validate(&plain_default()[..2]), Err(Errno::Einval), "OTHER is mandatory");
    assert_eq!(validate(&[e(ACL_USER_OBJ, 0o10), e(ACL_GROUP_OBJ, R), e(ACL_OTHER, R)]),
               Err(Errno::Einval), "perm bit outside rwx");
    assert_eq!(validate(&[e(0x40, R)]), Err(Errno::Einval), "unknown tag");
}

#[test]
fn equiv_mode_folds_base_entries_and_reports_what_the_mode_cannot_say() {
    let mut mode = 0o100_000u16 | 0o777;
    assert_eq!(equiv_mode(&plain_default(), &mut mode), Ok(false));
    assert_eq!(mode, 0o100_000 | 0o755, "file type survives the fold");
    // A mask REPLACES the group bits and makes the ACL non-equivalent.
    let mut mode = 0o777;
    assert_eq!(equiv_mode(&[e(ACL_USER_OBJ, R | W | X), named(ACL_USER, R, 1000),
                            e(ACL_GROUP_OBJ, R | X), e(ACL_MASK, R), e(ACL_OTHER, 0)],
                          &mut mode), Ok(true));
    assert_eq!(mode, 0o740);
    assert_eq!(equiv_mode(&[e(0x40, R)], &mut mode), Err(Errno::Einval));
}

#[test]
fn create_masq_intersects_the_requested_mode_with_the_inherited_acl() {
    // 0666 under u::rwx g::r-x o::r-x: the ACL keeps only what both allow, and
    // the mode comes back 0644 — the umask never enters this path.
    let mut acl = plain_default();
    let mut mode = 0o100_000u16 | 0o666;
    assert_eq!(create_masq(&mut acl, &mut mode), Ok(false), "no named entry and no mask: mode says it all");
    assert_eq!(mode, 0o100_000 | 0o644);
    assert_eq!(acl, alloc::vec![e(ACL_USER_OBJ, R | W), e(ACL_GROUP_OBJ, R), e(ACL_OTHER, R)]);

    // With a mask present the mask, not GROUP_OBJ, carries the group bits, and
    // GROUP_OBJ is left untouched.
    let mut acl = alloc::vec![e(ACL_USER_OBJ, R | W | X), named(ACL_USER, R | W | X, 1000),
                              e(ACL_GROUP_OBJ, R | W | X), e(ACL_MASK, R | W | X), e(ACL_OTHER, R | X)];
    let mut mode = 0o640u16;
    assert_eq!(create_masq(&mut acl, &mut mode), Ok(true), "a named user must be stored");
    assert_eq!(mode, 0o640);
    assert_eq!(acl[3], e(ACL_MASK, R), "mask narrowed to the requested group bits");
    assert_eq!(acl[2], e(ACL_GROUP_OBJ, R | W | X), "GROUP_OBJ untouched when a mask exists");
    assert_eq!(acl[4], e(ACL_OTHER, 0), "OTHER narrowed to the requested other bits");
}

#[test]
fn create_masq_reports_corruption_rather_than_a_bad_argument() {
    // Nothing can carry the group permission bits.
    let mut acl = alloc::vec![e(ACL_USER_OBJ, R), e(ACL_OTHER, R)];
    let mut mode = 0o777u16;
    assert_eq!(create_masq(&mut acl, &mut mode), Err(Errno::Eio));
    let mut acl = alloc::vec![e(0x40, R), e(ACL_GROUP_OBJ, R)];
    assert_eq!(create_masq(&mut acl, &mut mode), Err(Errno::Eio), "unknown tag on the inherit path");
}

#[test]
fn acl_create_without_a_default_acl_applies_the_umask() {
    for parent in [None, Some(&[][..])] {
        let got = acl_create(parent, 0o777, 0o022, NewKind::Other).unwrap();
        assert_eq!(got, NewAcls { mode: 0o755, access: None, default: None });
    }
    let got = acl_create(None, 0o40_777, 0o027, NewKind::Dir).unwrap();
    assert_eq!(got.mode, 0o40_750);
}

#[test]
fn acl_create_with_a_default_acl_ignores_the_umask() {
    let d = plain_default();
    // umask 0777 would leave 0; the default ACL decides instead.
    let got = acl_create(Some(&d), 0o666, 0o777, NewKind::Other).unwrap();
    assert_eq!(got.mode, 0o644, "the umask does not reach a mode a default ACL decided");
    assert_eq!(got.access, None, "mode-equivalent: nothing stored");
    assert_eq!(got.default, None, "only a directory inherits the default ACL");
}

#[test]
fn only_a_directory_inherits_the_default_acl_itself() {
    let d = alloc::vec![e(ACL_USER_OBJ, R | W | X), named(ACL_USER, R | W | X, 1000),
                        e(ACL_GROUP_OBJ, R | X), e(ACL_MASK, R | W | X), e(ACL_OTHER, R | X)];
    let dir = acl_create(Some(&d), 0o40_777, 0o022, NewKind::Dir).unwrap();
    assert_eq!(dir.default.as_deref(), Some(&d[..]), "verbatim, not masqued");
    assert!(dir.access.is_some(), "a named user survives into the access ACL");
    let file = acl_create(Some(&d), 0o666, 0o022, NewKind::Other).unwrap();
    assert_eq!(file.default, None);
    assert!(file.access.is_some());
}

#[test]
fn a_symlink_takes_neither_the_umask_nor_an_inherited_acl() {
    let d = plain_default();
    let got = acl_create(Some(&d), 0o777, 0o077, NewKind::Symlink).unwrap();
    assert_eq!(got, NewAcls { mode: 0o777, access: None, default: None });
}
