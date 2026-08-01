// The `key_task_permission` chokepoint: every keyctl op must deny a caller
// the `perm` byte doesn't grant, and must select the byte the way Linux does.

use super::*;
use super::super::ops::*;

// READ: the owner-possessor can, a different uid (falling to the zero "other"
// byte) cannot.
#[test]
fn read_denied_to_other_uid_owner_can() {
    let owner = ctx(3001, 6001);
    let stranger = ctx(3002, 6002);
    let serial = add_key_core(&owner, "user", "read-test", alloc::vec![1, 2, 3], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(read_core(&stranger, serial, 0), Err(eacces()),
        "other-uid READ denied by the zero other-byte");
    assert_eq!(read_core(&owner, serial, 0), Ok(alloc::vec![1, 2, 3]),
        "owner READ succeeds via the possessor byte");
}

// DESCRIBE requires KEY_NEED_VIEW: the owner can, a stranger (zero other-byte)
// cannot, even though DESCRIBE only reveals metadata, not the payload.
#[test]
fn describe_requires_view() {
    let owner = ctx(3006, 6006);
    let stranger = ctx(3007, 6007);
    let serial = add_key_core(&owner, "user", "describe-test", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(describe_core(&stranger, serial), Err(eacces()), "DESCRIBE denied without VIEW");
    assert!(describe_core(&owner, serial).expect("owner has VIEW").contains("describe-test"));
}

// Possessor bits are additive (Linux `key_task_permission`): a non-owner who
// possesses the key (it is linked into one of their own keyrings) gains access
// through the possessor byte even though uid/gid don't match and the key's own
// other-byte is zero.
#[test]
fn possessor_byte_grants_access_to_non_owner() {
    let owner = ctx(3010, 6010);
    let holder = ctx(3011, 6011);
    let serial = add_key_core(&owner, "user", "possessed-test", alloc::vec![7, 7], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let holder_session = get_keyring_id(&holder, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(read_core(&holder, serial, 0), Err(eacces()), "holder doesn't possess the key yet");
    force_perm(holder_session, KEY_PERM_VALID);
    assert_eq!(link_core(&owner, serial, holder_session), 0);
    assert_eq!(read_core(&holder, serial, 0), Ok(alloc::vec![7, 7]), "possessor byte grants READ");
}

// add_key requires KEY_NEED_WRITE on the destination keyring.
#[test]
fn add_key_denied_into_foreign_ring_without_write() {
    let owner = ctx(3012, 6012);
    let stranger = ctx(3013, 6013);
    let owner_ring = get_keyring_id(&owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(add_key_core(&stranger, "user", "into-foreign-ring", alloc::vec![7u8], true, owner_ring),
        eacces(), "add_key into a foreign ring without WRITE is refused");
}

// LINK requires KEY_NEED_LINK on the child AND KEY_NEED_WRITE on the ring.
#[test]
fn link_denied_without_link_and_write() {
    let owner = ctx(3014, 6014);
    let stranger = ctx(3015, 6015);
    let serial = add_key_core(&owner, "user", "link-denied-test", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let stranger_session = get_keyring_id(&stranger, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(link_core(&stranger, serial, stranger_session), eacces(),
        "stranger lacks KEY_NEED_LINK on someone else's key");
}

// Ownership is the FILESYSTEM uid, not the effective uid — `key_alloc` stores
// `cred->fsuid` and `key_task_permission` compares against `cred->fsuid`. A
// process that called `setfsuid()` sees a different key world, and checking
// euid instead silently gave it the wrong one.
#[test]
fn ownership_follows_fsuid_not_euid() {
    let mut owner = ctx(3016, 6016);
    owner.t.fsuid = 6017;
    let serial = add_key_core(&owner, "user", "fsuid-owned", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(STORE.lock().keys[&serial].uid, 6017, "the key is owned by the fsuid");
    // Both readers are separate tasks, so neither possesses the key: only the
    // uid byte can grant anything.
    force_perm(serial, KEY_USR_ALL);
    let mut same_fsuid = ctx(3017, 9999);
    same_fsuid.t.fsuid = 6017;
    assert_eq!(read_core(&same_fsuid, serial, 0), Ok(alloc::vec![1]),
        "a matching fsuid takes the user byte");
    let mut other_fsuid = ctx(3018, 6017);
    other_fsuid.t.fsuid = 9999;
    assert_eq!(read_core(&other_fsuid, serial, 0), Err(eacces()),
        "a non-matching fsuid falls to the zero other byte");
}

// The group byte is consulted only when the key HAS group bits
// (`key->perm & KEY_GRP_ALL`). With an all-zero group byte and a permissive
// other byte, a gid match must NOT trap the caller in the empty group byte —
// Linux falls through to the other byte, which is more permissive.
#[test]
fn empty_group_byte_falls_through_to_the_other_byte() {
    let owner = ctx(3019, 6018);
    let serial = add_key_core(&owner, "user", "grp-fallthrough", alloc::vec![2], true, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(serial, KEY_OTH_ALL);
    STORE.lock().keys.get_mut(&serial).expect("key exists").gid = 7000;
    let mut member = ctx(3020, 6019);
    member.t.fsgid = 7000;
    assert_eq!(read_core(&member, serial, 0), Ok(alloc::vec![2]),
        "no group bits set -> use the other byte, not the empty group byte");
}

// Group membership is the full supplementary list (`groups_search`), not just
// the fsgid: a caller whose SUPPLEMENTARY groups contain the key's gid gets
// the group byte.
#[test]
fn supplementary_groups_select_the_group_byte() {
    let owner = ctx(3021, 6020);
    let serial = add_key_core(&owner, "user", "grp-supplementary", alloc::vec![3], true, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(serial, KEY_NEED_READ << KEY_PERM_GRP_SHIFT);
    STORE.lock().keys.get_mut(&serial).expect("key exists").gid = 7001;
    let mut outsider = ctx(3022, 6021);
    outsider.t.fsgid = 5;
    assert_eq!(read_core(&outsider, serial, 0), Err(eacces()), "not in the group");
    let mut member = ctx(3023, 6022);
    member.t.fsgid = 5;
    member.t.groups = alloc::vec![42, 7001];
    assert_eq!(read_core(&member, serial, 0), Ok(alloc::vec![3]),
        "the supplementary group list selects the group byte");
}

// A key owned with `INVALID_GID` (the user and user-session keyrings) never
// matches the group byte, whatever the caller's fsgid.
#[test]
fn invalid_gid_never_matches_the_group_byte() {
    let t = ctx(3024, 6023);
    let user_ring = get_keyring_id(&t, KEY_SPEC_USER_KEYRING, true) as i32;
    assert_eq!(STORE.lock().keys[&user_ring].gid, GID_INVALID);
    let mut impostor = ctx(3025, 6024);
    impostor.t.fsgid = GID_INVALID;
    assert_eq!(read_core(&impostor, user_ring, 0), Err(eacces()),
        "an fsgid of INVALID_GID must not match the key's INVALID_GID");
}

// A key the caller cannot SEARCH does not satisfy a search, and KEYCTL_SEARCH
// reports EACCES rather than ENOKEY: the skip reason is what the search
// returns, and only "nothing matched at all" becomes ENOKEY. Reporting ENOKEY
// here would tell a caller a key is absent when it is merely out of reach, so
// it would keep asking for one that is already there.
#[test]
fn a_key_the_caller_cannot_search_is_denied_not_reported_missing() {
    let owner = ctx(3008, 6008);
    let stranger = ctx(3009, 6009);
    // A shared keyring the stranger may SEARCH, but which is NOT one of their
    // cred keyrings — so walking it confers no possession, and the key's own
    // zero other-byte is the only thing left to grant access.
    let shared = add_key_core(&owner, "keyring", "shared-search-ring", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(shared, KEY_PERM_VALID);
    let serial = add_key_core(&owner, "user", "search-test-desc", alloc::vec![7u8], true, shared) as i32;
    assert_eq!(search_core(&stranger, shared, "user", "search-test-desc", 0), eacces(),
        "no KEY_NEED_SEARCH on the key -> denied, distinct from absent");
    assert_eq!(search_core(&stranger, shared, "user", "no-such-key-at-all", 0), enokey(),
        "a name that matches nothing is ENOKEY");
    let owner_ring = get_keyring_id(&owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(search_core(&owner, owner_ring, "user", "search-test-desc", 0), serial as i64);
}
