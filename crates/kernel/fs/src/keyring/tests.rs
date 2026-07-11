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

// Key descriptions are user C strings, not UTF-8 text. Preserve raw byte
// identity through the same reversible path codec used at the syscall boundary.
#[test]
fn non_utf8_description_keeps_exact_identity() {
    let t = ids(1011, 1011);
    let desc = key_string_from_bytes(b"raw-\xff");
    let lossy = String::from("raw-\u{fffd}");
    assert_ne!(desc, lossy, "invalid byte must not collapse to replacement char");
    let serial = add_key_core(t, "user", &desc, alloc::vec![9], 0) as i32;
    let g = STORE.lock();
    let k = g.keys.get(&serial).expect("added key exists");
    assert_eq!(k.description, desc);
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

// THE 1.1 fix: KEYCTL_LINK must resolve the CHILD special id, not just the ring.
// pam_keyinit does keyctl(LINK, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING);
// passing the raw special id (-4) as the child made link() ENOKEY (gdm logged
// "Failed to link user keyring into session keyring: Required key not available").
#[test]
fn link_resolves_special_child_into_session() {
    let t = ids(1009, 1009);
    let sess = get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, true);
    let user = get_keyring_id(t, KEY_SPEC_USER_KEYRING, true);
    // The pam_keyinit call, verbatim by special id — must succeed (0), not ENOKEY.
    assert_eq!(link_core(t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), 0,
        "link(user→session) by special id resolves both ends");
    let members = members_of(sess as i32).expect("session is a keyring");
    assert!(members.contains(&(user as i32)),
        "the resolved user keyring serial is now a session member: {members:?}");
}

// UNLINK likewise resolves the child special id and removes it.
#[test]
fn unlink_resolves_special_child() {
    let t = ids(1010, 1010);
    let sess = get_keyring_id(t, KEY_SPEC_SESSION_KEYRING, true);
    let user = get_keyring_id(t, KEY_SPEC_USER_KEYRING, true);
    assert_eq!(link_core(t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), 0);
    assert_eq!(unlink_core(t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), 0,
        "unlink by special id resolves + removes the member");
    let members = members_of(sess as i32).expect("session is a keyring");
    assert!(!members.contains(&(user as i32)), "user keyring unlinked: {members:?}");
    // Unlinking again is ENOKEY (no longer a member).
    assert_eq!(unlink_core(t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), -(ENOKEY as i64));
}
