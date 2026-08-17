// The access decision an ACL makes, and the rewrite a chmod does to it.
//
// These pin ORDER, not just outcome: which class a caller lands in, that the
// class it lands in is FINAL, and that the mask narrows a matched entry rather
// than sending the walk on to the next one.

use super::*;

extern crate alloc;
use alloc::vec::Vec;

const R: u16 = 4;
const W: u16 = 2;
const X: u16 = 1;

fn e(tag: u16, perm: u16, id: u32) -> AclEntry { AclEntry { tag, perm, id } }

/// owner 100, group 500. USER 1000 rw, GROUP 2000 rw, MASK rw, OTHER r.
fn fixture() -> Vec<AclEntry> {
    alloc::vec![
        e(ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
        e(ACL_USER, R | W, 1000),
        e(ACL_GROUP_OBJ, R, ACL_UNDEFINED_ID),
        e(ACL_GROUP, R | W, 2000),
        e(ACL_MASK, R | W, ACL_UNDEFINED_ID),
        e(ACL_OTHER, R, ACL_UNDEFINED_ID),
    ]
}

/// Caller in exactly the groups listed.
fn member_of(gids: &'static [u32]) -> impl Fn(u32) -> bool { move |g| gids.contains(&g) }

fn decide(acl: &[AclEntry], uid: u32, gids: &'static [u32], want: u16) -> Result<(), Errno> {
    permission(acl, uid, 100, 500, want, member_of(gids))
}

#[test] fn the_owner_entry_is_not_narrowed_by_the_mask() {
    // USER_OBJ carries rwx and the mask only rw; the owner still gets exec.
    assert_eq!(decide(&fixture(), 100, &[], X), Ok(()));
}

#[test] fn a_named_user_is_narrowed_by_the_mask() {
    assert_eq!(decide(&fixture(), 1000, &[], W), Ok(()));
    assert_eq!(decide(&fixture(), 1000, &[], X), Err(Errno::Eacces));
}

#[test] fn a_named_user_the_mask_strips_is_refused_not_passed_on() {
    // USER 1000 carries rwx but the mask allows rw: exec is refused HERE, and
    // the walk does not continue to OTHER (which grants r) or anywhere else.
    let mut acl = fixture();
    acl[1].perm = R | W | X;
    assert_eq!(decide(&acl, 1000, &[], X), Err(Errno::Eacces));
    assert_eq!(decide(&acl, 1000, &[], R), Ok(()));
}

#[test] fn a_matched_group_that_does_not_grant_never_falls_to_other() {
    // OTHER grants r; a caller in group 2000 asking for exec is DENIED, because
    // matching a group class settles which class decides.
    assert_eq!(decide(&fixture(), 3000, &[2000], R), Ok(()));
    assert_eq!(decide(&fixture(), 3000, &[2000], X), Err(Errno::Eacces));
    // The owning group is a match for the same purpose.
    assert_eq!(decide(&fixture(), 3000, &[500], W), Err(Errno::Eacces));
}

#[test] fn the_first_group_entry_whose_own_bits_cover_the_request_decides_it() {
    // Two group entries the caller belongs to: 2000 carries rw but the mask
    // allows only r, 3000 carries rw and would grant. The FIRST is tested
    // against its own bits, matches, and is then narrowed to a refusal — the
    // walk does not go on to the second.
    let mut acl = fixture();
    acl[4].perm = R;
    acl.insert(4, e(ACL_GROUP, R | W, 3000));
    assert_eq!(decide(&acl, 9, &[2000, 3000], W), Err(Errno::Eacces));
    // Reversing which entry comes first reverses nothing: both are masked to r.
    assert_eq!(decide(&acl, 9, &[2000, 3000], R), Ok(()));
}

#[test] fn a_caller_in_no_named_class_lands_on_other() {
    assert_eq!(decide(&fixture(), 3000, &[3000], R), Ok(()));
    assert_eq!(decide(&fixture(), 3000, &[3000], W), Err(Errno::Eacces));
}

#[test] fn without_a_mask_a_named_entry_keeps_its_own_bits() {
    let acl = alloc::vec![
        e(ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
        e(ACL_GROUP_OBJ, R | W, ACL_UNDEFINED_ID),
        e(ACL_OTHER, 0, ACL_UNDEFINED_ID),
    ];
    assert_eq!(decide(&acl, 9, &[500], W), Ok(()));
    assert_eq!(decide(&acl, 9, &[500], X), Err(Errno::Eacces));
}

#[test] fn an_empty_request_is_granted_by_any_class() {
    assert_eq!(decide(&fixture(), 3000, &[3000], 0), Ok(()));
}

#[test] fn bits_outside_rwx_are_dropped_from_the_request() {
    // Only r/w/x are ACL permissions; a caller asking for more is asking for
    // those three.
    assert_eq!(decide(&fixture(), 3000, &[3000], R | 0o70), Ok(()));
}

#[test] fn a_malformed_acl_is_a_medium_error_not_a_fall_through() {
    // An unknown tag.
    let acl = alloc::vec![e(ACL_USER_OBJ, 7, ACL_UNDEFINED_ID), e(0x40, 7, 0)];
    assert_eq!(decide(&acl, 9, &[], R), Err(Errno::Eio));
    // A sequence that never reaches OTHER, so no class ever decides.
    let acl = alloc::vec![e(ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
                          e(ACL_GROUP_OBJ, 7, ACL_UNDEFINED_ID)];
    assert_eq!(decide(&acl, 9, &[], R), Err(Errno::Eio));
    // No entries at all.
    assert_eq!(decide(&[], 9, &[], R), Err(Errno::Eio));
}

#[test] fn chmod_puts_the_group_bits_on_the_mask_when_there_is_one() {
    let mut acl = fixture();
    assert_eq!(chmod_masq(&mut acl, 0o750), Ok(()));
    assert_eq!(acl[0].perm, 7, "owner bits land on USER_OBJ");
    assert_eq!(acl[1].perm, R | W, "a named entry is left alone");
    assert_eq!(acl[2].perm, R, "GROUP_OBJ is left alone when a mask exists");
    assert_eq!(acl[4].perm, R | X, "the group bits land on the MASK");
    assert_eq!(acl[5].perm, 0, "other bits land on OTHER");
    // And the narrowed mask is what the next decision uses: the named user's rw
    // no longer grants write.
    assert_eq!(decide(&acl, 1000, &[], W), Err(Errno::Eacces));
}

#[test] fn chmod_puts_the_group_bits_on_group_obj_without_a_mask() {
    let mut acl = alloc::vec![
        e(ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
        e(ACL_GROUP_OBJ, 7, ACL_UNDEFINED_ID),
        e(ACL_OTHER, 7, ACL_UNDEFINED_ID),
    ];
    assert_eq!(chmod_masq(&mut acl, 0o640), Ok(()));
    assert_eq!((acl[0].perm, acl[1].perm, acl[2].perm), (R | W, R, 0));
}

#[test] fn chmod_of_an_acl_that_cannot_carry_group_bits_is_a_medium_error() {
    let mut acl = alloc::vec![e(ACL_USER_OBJ, 7, ACL_UNDEFINED_ID),
                              e(ACL_OTHER, 7, ACL_UNDEFINED_ID)];
    assert_eq!(chmod_masq(&mut acl, 0o644), Err(Errno::Eio));
    let mut acl = alloc::vec![e(0x40, 7, 0)];
    assert_eq!(chmod_masq(&mut acl, 0o644), Err(Errno::Eio));
}

#[test] fn an_acl_and_its_mode_agree_after_a_chmod() {
    // What `equiv_mode` folds out has to be what `chmod_masq` folded in.
    let mut acl = fixture();
    chmod_masq(&mut acl, 0o751).unwrap();
    let mut mode = 0o100000u16;
    equiv_mode(&acl, &mut mode).unwrap();
    assert_eq!(mode & 0o777, 0o751);
}
