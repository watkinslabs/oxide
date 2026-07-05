// Hosted tests for the real keyring hierarchy. These drive the testable cores
// (`join_session`/`get_keyring_id`/`add_key_core`/`members_of`/`inherit_session`)
// which don't touch user memory or `current()`. The STORE is a process-global
// static shared across tests, so each test uses a UNIQUE tid/uid so the
// per-task/per-uid keyring maps never collide between tests.

use super::*;

fn ids(tid: u32, uid: u32) -> TaskIds { TaskIds { tid, tgid: tid, uid, gid: uid } }

// THE fix: JOIN_SESSION_KEYRING mints a FRESH keyring each call — a unique
// serial, NOT the old constant `1`.
#[test]
fn join_mints_fresh_unique_serials() {
    let t = ids(1001, 1001);
    let a = join_session(t, None);
    let b = join_session(t, None);
    assert_ne!(a, b, "each anonymous JOIN creates a new session keyring");
    assert!(a >= FIRST_SERIAL && b >= FIRST_SERIAL, "serials are real, not the legacy sentinel 1");
    assert_ne!(a, 1);
    assert_ne!(b, 1);
}

// After JOIN, GET_KEYRING_ID(@s) returns the just-joined keyring (the caller's
// session keyring actually changed).
#[test]
fn get_session_reflects_join() {
    let t = ids(1002, 1002);
    let joined = join_session(t, None);
    let got = get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, true);
    assert_eq!(got, joined as i64);
}

// A NAMED join rejoins the same keyring (Linux: same-named session keyring is
// shared), while a different name is a different keyring.
#[test]
fn named_join_is_stable_by_name() {
    let t = ids(1003, 1003);
    let x1 = join_session(t, Some("keyring-test-alpha"));
    let x2 = join_session(t, Some("keyring-test-alpha"));
    let y  = join_session(t, Some("keyring-test-beta"));
    assert_eq!(x1, x2, "same name rejoins one keyring");
    assert_ne!(x1, y,  "different name is a different keyring");
}

// The five special keyrings resolve to DISTINCT real keyrings for a task (not
// all folded to one sentinel like the old stub).
#[test]
fn special_keyrings_are_distinct() {
    let t = ids(1004, 1004);
    let s = get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, true);
    let u = get_keyring_id(t, KEY_SPEC_USER_KEYRING, true);
    let th = get_keyring_id(t, KEY_SPEC_THREAD_KEYRING, true);
    let p = get_keyring_id(t, KEY_SPEC_PROCESS_KEYRING, true);
    let mut all = [s, u, th, p];
    all.sort();
    for w in all.windows(2) { assert_ne!(w[0], w[1], "special keyrings are distinct: {all:?}"); }
    assert!(all.iter().all(|&x| x >= FIRST_SERIAL as i64));
}

// GET_KEYRING_ID(create=false) on a never-referenced keyring is ENOKEY (no
// silent lazy-create when the caller said don't).
#[test]
fn get_no_create_is_enokey() {
    let t = ids(1005, 1005);
    assert_eq!(get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, false), -(ENOKEY as i64));
    // After it exists, create=false succeeds.
    let _ = get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, true);
    assert!(get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, false) >= FIRST_SERIAL as i64);
}

// add_key links the new key into the session keyring; READ-back of the keyring
// (members) contains its serial (real linkage, not a flat global bag).
#[test]
fn add_key_links_into_session_keyring() {
    let t = ids(1006, 1006);
    let sess = join_session(t, None);
    let k = add_key_core(t, "user", "my-secret", alloc::vec![1, 2, 3], 0) as i32;
    let members = members_of(sess).expect("session is a keyring");
    assert!(members.contains(&k), "added key linked into the session keyring: {members:?}");
}

// A forked child shares the parent's session keyring (Linux copy_creds).
#[test]
fn fork_inherits_session_keyring() {
    let parent = ids(1007, 1007);
    let child  = ids(1008, 1007);
    let ps = join_session(parent, None);
    inherit_session(parent.tid, child.tid);
    assert_eq!(get_keyring_id(child, KEY_SPEC_SESSION_KEYRING, true), ps as i64);
}
