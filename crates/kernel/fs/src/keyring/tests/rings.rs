// Keyring lifecycle: JOIN_SESSION_KEYRING, GET_KEYRING_ID, GET_PERSISTENT,
// SET_REQKEY_KEYRING, fork inheritance.

use super::*;
use super::super::ops::*;

// JOIN_SESSION_KEYRING mints a FRESH keyring each call — a unique serial, NOT
// the old constant `1`.
#[test]
fn join_mints_fresh_unique_serials() {
    let t = ctx(1001, 1001);
    let a = join_session(&t, None);
    let b = join_session(&t, None);
    assert_ne!(a, b, "each anonymous JOIN creates a new session keyring");
    assert!(a >= FIRST_SERIAL as i64 && b >= FIRST_SERIAL as i64,
        "serials are real, not the legacy sentinel 1");
}

// After JOIN, GET_KEYRING_ID(@s) returns the just-joined keyring (the caller's
// session keyring actually changed).
#[test]
fn get_session_reflects_join() {
    let t = ctx(1002, 1002);
    let joined = join_session(&t, None);
    assert_eq!(get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true), joined);
}

// A NAMED join rejoins the same keyring (Linux: same-named session keyring is
// shared), while a different name is a different keyring.
#[test]
fn named_join_is_stable_by_name() {
    let t = ctx(1003, 1003);
    let x1 = join_session(&t, Some("keyring-test-alpha"));
    let x2 = join_session(&t, Some("keyring-test-alpha"));
    let y  = join_session(&t, Some("keyring-test-beta"));
    assert_eq!(x1, x2, "same name rejoins one keyring");
    assert_ne!(x1, y,  "different name is a different keyring");
}

// The special keyrings resolve to DISTINCT real keyrings for a task.
#[test]
fn special_keyrings_are_distinct() {
    let t = ctx(1004, 1004);
    let mut all = [
        get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true),
        get_keyring_id(&t, KEY_SPEC_USER_KEYRING, true),
        get_keyring_id(&t, KEY_SPEC_THREAD_KEYRING, true),
        get_keyring_id(&t, KEY_SPEC_PROCESS_KEYRING, true),
        get_keyring_id(&t, KEY_SPEC_USER_SESSION_KEYRING, true),
    ];
    all.sort();
    for w in all.windows(2) { assert_ne!(w[0], w[1], "special keyrings are distinct: {all:?}"); }
    assert!(all.iter().all(|&x| x >= FIRST_SERIAL as i64));
}

// `KEY_SPEC_USER_SESSION_KEYRING` and `KEY_SPEC_GROUP_KEYRING` are NOT the
// same ring: Linux never implemented group keyrings, so `-6` resolves to
// nothing at all — group keyrings were never implemented, so the id resolver
// answers EINVAL — while `-5` is the real user-session keyring. Folding `-6`
// onto `-5` handed callers a keyring that does not exist; answering ENOKEY
// instead would say the facility exists but is empty.
#[test]
fn group_keyring_is_not_the_user_session_keyring() {
    let t = ctx(1024, 1024);
    assert!(get_keyring_id(&t, KEY_SPEC_USER_SESSION_KEYRING, true) >= FIRST_SERIAL as i64);
    assert_eq!(get_keyring_id(&t, KEY_SPEC_GROUP_KEYRING, true), einval(),
        "group keyrings were never implemented");
}

// Every id the resolver does NOT define is EINVAL, and the two
// authorisation-key ids are ENOKEY — they name objects that exist only inside
// a `request_key` upcall. An id of 0 is EINVAL, NOT a shorthand for the
// session keyring: a caller's uninitialised keyring argument must be refused,
// not quietly turned into a successful insertion.
#[test]
fn undefined_keyring_ids_are_einval_and_authkey_ids_are_enokey() {
    let t = ctx(1044, 1044);
    assert_eq!(get_keyring_id(&t, 0, true), einval(), "id 0 is not the session keyring");
    assert_eq!(get_keyring_id(&t, -9, true), einval());
    assert_eq!(get_keyring_id(&t, i32::MIN, true), einval());
    assert_eq!(get_keyring_id(&t, KEY_SPEC_REQKEY_AUTH_KEY, true), enokey(),
        "no upcall in flight, so no authorisation key exists");
    assert_eq!(get_keyring_id(&t, KEY_SPEC_REQUESTOR_KEYRING, true), enokey());
    assert_eq!(add_key_core(&t, "user", "no-dest", alloc::vec![1], true, 0), einval(),
        "add_key's destination keyring is mandatory");
}

// GET_KEYRING_ID(create=false) on a never-referenced keyring is ENOKEY (no
// silent lazy-create when the caller said don't).
#[test]
fn get_no_create_is_enokey() {
    let t = ctx(1005, 1005);
    assert_eq!(get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, false), enokey());
    let _ = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true);
    assert!(get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, false) >= FIRST_SERIAL as i64);
}

// A concrete serial still passes through `KEY_NEED_SEARCH`, so GET_KEYRING_ID
// is not an oracle for another task's keyring serials.
#[test]
fn get_keyring_id_by_serial_needs_search_permission() {
    let owner = ctx(1012, 6100);
    let stranger = ctx(1013, 6101);
    let ring = get_keyring_id(&owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(get_keyring_id(&stranger, ring, true), eacces());
    assert_eq!(get_keyring_id(&owner, ring, true), ring as i64);
}

// A forked child shares the parent's session keyring (Linux copy_creds).
#[test]
fn fork_inherits_session_keyring() {
    let parent = ctx(1007, 1007);
    let child  = ctx(1008, 1007);
    let ps = join_session(&parent, None);
    inherit_session(parent.t.tid, child.t.tid);
    assert_eq!(get_keyring_id(&child, KEY_SPEC_SESSION_KEYRING, true), ps);
}

// SET_REQKEY_KEYRING returns the PREVIOUS setting and actually stores the new
// one; returning a bare 0 told `request-key` its default had been installed
// when nothing had changed. The default before any call is
// KEY_REQKEY_DEFL_THREAD_KEYRING.
#[test]
fn set_reqkey_keyring_returns_the_previous_setting() {
    let t = ctx(1014, 1014);
    assert_eq!(set_reqkey_keyring(&t, KEY_REQKEY_DEFL_NO_CHANGE),
        KEY_REQKEY_DEFL_THREAD_KEYRING as i64, "boot default is the thread keyring");
    assert_eq!(set_reqkey_keyring(&t, KEY_REQKEY_DEFL_SESSION_KEYRING),
        KEY_REQKEY_DEFL_THREAD_KEYRING as i64, "returns the OLD setting, not 0");
    assert_eq!(set_reqkey_keyring(&t, KEY_REQKEY_DEFL_NO_CHANGE),
        KEY_REQKEY_DEFL_SESSION_KEYRING as i64, "the new setting was actually stored");
}

// KEY_REQKEY_DEFL_GROUP_KEYRING and anything out of range are EINVAL, and a
// rejected value leaves the setting alone.
#[test]
fn set_reqkey_keyring_rejects_group_and_out_of_range() {
    let t = ctx(1015, 1015);
    assert_eq!(set_reqkey_keyring(&t, KEY_REQKEY_DEFL_GROUP_KEYRING), einval());
    assert_eq!(set_reqkey_keyring(&t, 99), einval());
    assert_eq!(set_reqkey_keyring(&t, -7), einval());
    assert_eq!(set_reqkey_keyring(&t, KEY_REQKEY_DEFL_NO_CHANGE),
        KEY_REQKEY_DEFL_THREAD_KEYRING as i64, "a rejected value changed nothing");
}

// Naming the thread/process keyring installs it, so a following
// GET_KEYRING_ID(create=false) finds it (Linux `install_thread_keyring_to_cred`).
#[test]
fn set_reqkey_keyring_installs_the_named_keyring() {
    let t = ctx(1016, 1016);
    assert_eq!(get_keyring_id(&t, KEY_SPEC_PROCESS_KEYRING, false), enokey());
    assert_eq!(set_reqkey_keyring(&t, KEY_REQKEY_DEFL_PROCESS_KEYRING),
        KEY_REQKEY_DEFL_THREAD_KEYRING as i64);
    assert!(get_keyring_id(&t, KEY_SPEC_PROCESS_KEYRING, false) >= FIRST_SERIAL as i64,
        "the process keyring was installed, not just recorded");
}

// GET_PERSISTENT for another uid without CAP_SYS_ADMIN is EPERM; `-1` means
// "my own" and always works.
#[test]
fn get_persistent_refuses_another_uid() {
    let t = ctx(1017, 6102);
    assert!(get_persistent(&t, -1, 0) >= FIRST_SERIAL as i64);
    assert_eq!(get_persistent(&t, 6103, 0), eperm());
    let a = admin_ctx(1018, 6102);
    assert!(get_persistent(&a, 6103, 0) >= FIRST_SERIAL as i64, "CAP_SYS_ADMIN may ask for another uid");
}

// GET_PERSISTENT links the ring into the destination keyring when one is given.
#[test]
fn get_persistent_links_into_the_destination() {
    let t = ctx(1019, 6104);
    let sess = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let ring = get_persistent(&t, -1, KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(members_of(sess).expect("session is a keyring").contains(&ring));
}
