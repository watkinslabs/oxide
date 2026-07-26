// Hosted tests for the permission chokepoint (B1411): every keyctl op must
// deny a caller the `perm` byte doesn't grant. Drives the `ops::*_core`
// functions directly with distinct `TaskIds` per caller — no `current()`, no
// user memory. STORE is a process-global static shared across tests, so each
// test mints keys under a UNIQUE uid pair to avoid cross-test interference.

use super::*;

fn ids(tid: u32, uid: u32) -> TaskIds { TaskIds { tid, tgid: tid, uid, gid: uid } }
fn eacces() -> i64 { -(Errno::Eacces.as_i32() as i64) }
fn enokey() -> i64 { -(ENOKEY as i64) }

// A freshly minted key defaults to `perm = 0x3f3f0000` (possessor=all,
// user=all, group=0, other=0) — matching Linux `add_key()`'s default. A
// caller who is neither owner, group, nor possessor gets the all-zero other
// byte: every KEY_NEED_* bit is denied.

// READ: owner can, a different uid (falling to the zero "other" byte) cannot.
#[test]
fn read_denied_to_other_uid_owner_can() {
    let owner = ids(3001, 6001);
    let stranger = ids(3002, 6002);
    let serial = add_key_core(owner, "user", "read-test", alloc::vec![1, 2, 3], 0) as i32;

    assert_eq!(read_core(stranger, serial), Err(eacces()), "other-uid READ denied by the zero other-byte");
    assert_eq!(read_core(owner, serial), Ok(alloc::vec![1, 2, 3]), "owner READ succeeds via the user byte");
}

// SETPERM: a non-owner without CAP_SYS_ADMIN is refused (the zero other-byte
// denies SETATTR); CAP_SYS_ADMIN bypasses the denial regardless of the byte.
#[test]
fn setperm_refused_to_non_owner_admin_bypasses() {
    let owner = ids(3003, 6003);
    let stranger = ids(3004, 6004);
    let serial = add_key_core(owner, "user", "setperm-test", alloc::vec![9], 0) as i32;

    assert_eq!(setperm_core(stranger, serial, 0x3f3f3f3f, false), eacces(),
        "SETPERM by a non-owner without CAP_SYS_ADMIN is refused");
    assert_eq!(setperm_core(stranger, serial, 0x3f3f3f3f, true), 0,
        "CAP_SYS_ADMIN bypasses the SETATTR denial");
    // The bypassed call actually took effect (now other=0x3f, so a THIRD
    // stranger can read it).
    let third = ids(3005, 6005);
    assert_eq!(read_core(third, serial), Ok(alloc::vec![9]), "widened other-byte now grants READ");
}

// DESCRIBE requires KEY_NEED_VIEW: owner can, a stranger (zero other-byte)
// cannot, even though DESCRIBE only reveals metadata, not the payload.
#[test]
fn describe_requires_view() {
    let owner = ids(3006, 6006);
    let stranger = ids(3007, 6007);
    let serial = add_key_core(owner, "user", "describe-test", alloc::vec![], 0) as i32;

    assert_eq!(describe_core(stranger, serial), Err(eacces()), "DESCRIBE denied without VIEW");
    let desc = describe_core(owner, serial).expect("owner has VIEW via the user byte");
    assert!(desc.contains("describe-test"), "descriptor carries the description: {desc}");
}

// A permission-less key is invisible to KEYCTL_SEARCH/request_key: a stranger
// gets ENOKEY (not EACCES) — Linux hides existence from keyring search,
// unlike a direct-serial op which reveals the key exists but denies it.
#[test]
fn permissionless_key_invisible_to_search() {
    let owner = ids(3008, 6008);
    let stranger = ids(3009, 6009);
    let serial = add_key_core(owner, "user", "search-test-desc", alloc::vec![], 0) as i32;

    assert_eq!(search_core(stranger, "user", "search-test-desc"), enokey(),
        "no KEY_NEED_SEARCH on the zero other-byte -> invisible, not just denied");
    assert_eq!(search_core(owner, "user", "search-test-desc"), serial as i64,
        "owner's own key is found via the user byte's SEARCH bit");
}

// Possessor bits are additive (Linux `key_task_permission`): a non-owner who
// possesses the key (it is linked into one of their own keyrings) gains
// access via the possessor byte even though uid/gid don't match and the
// key's own other-byte is zero.
#[test]
fn possessor_byte_grants_access_to_non_owner() {
    let owner = ids(3010, 6010);
    let holder = ids(3011, 6011);
    let serial = add_key_core(owner, "user", "possessed-test", alloc::vec![7, 7], 0) as i32;
    let holder_session = get_keyring_id(holder, KEY_SPEC_SESSION_KEYRING, true) as i32;

    assert_eq!(read_core(holder, serial), Err(eacces()), "holder doesn't possess the key yet");
    // Widen holder's own session ring so the LINK op's KEY_NEED_WRITE check
    // (owner isn't holder's owner/group/possessor) passes — mirrors a
    // shared/system keyring being configured to accept external links.
    assert_eq!(setperm_core(holder, holder_session, 0x3f3f3f3fu32, false), 0);
    assert_eq!(link_core(owner, serial, holder_session), 0,
        "owner holds LINK on their own key (user byte) and now WRITE on holder's widened ring");
    // `holder` now possesses `serial` (member of their own session ring):
    // possessor byte (0x3f, includes READ) is OR'd in even though holder is
    // neither owner nor group and the key's own other-byte is 0.
    assert_eq!(read_core(holder, serial), Ok(alloc::vec![7, 7]), "possessor byte grants READ");
}

// add_key requires KEY_NEED_WRITE on the destination keyring: a caller cannot
// add_key into a keyring they don't own/possess and that denies WRITE.
#[test]
fn add_key_denied_into_foreign_ring_without_write() {
    let owner = ids(3012, 6012);
    let stranger = ids(3013, 6013);
    let owner_ring = get_keyring_id(owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    // Default ring perm (other=0) denies WRITE to a non-owner/non-possessor.
    let rv = add_key_core(stranger, "user", "into-foreign-ring", alloc::vec![], owner_ring);
    assert_eq!(rv, eacces(), "add_key into a foreign ring without WRITE is refused");
}

// LINK requires KEY_NEED_LINK on the child AND KEY_NEED_WRITE on the ring;
// a stranger with neither is refused even though the ring resolves fine.
#[test]
fn link_denied_without_link_and_write() {
    let owner = ids(3014, 6014);
    let stranger = ids(3015, 6015);
    let serial = add_key_core(owner, "user", "link-denied-test", alloc::vec![], 0) as i32;
    let stranger_session = get_keyring_id(stranger, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let rv = link_core(stranger, serial, stranger_session);
    assert_eq!(rv, eacces(), "stranger lacks KEY_NEED_LINK on someone else's key");
}
