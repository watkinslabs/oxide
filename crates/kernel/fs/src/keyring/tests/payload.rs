// Per-type payload contracts (`preparse`) and the type table's update/read
// methods: what each registered type accepts as a payload, and which commands
// a type without an `update` or `read` method refuses.

use super::*;
use super::super::ops::*;
use super::super::types::{self, BIG_PAYLOAD_MAX, USER_PAYLOAD_MAX};

fn eopnotsupp() -> i64 { err(Errno::Eopnotsupp) }

// A `user`/`logon` payload is 1..=32767 bytes. An EMPTY payload is EINVAL —
// not an empty key — and so is one past the ceiling, both before the key is
// minted.
#[test]
fn user_payloads_are_bounded_and_never_empty() {
    // uid 0, so the 32767-byte at-ceiling payload is not itself refused by the
    // far smaller general BYTE quota.
    let t = ctx(4101, 0);
    assert_eq!(add_key_core(&t, "user", "empty", alloc::vec![], true, KEY_SPEC_SESSION_KEYRING), einval(),
        "a zero-length payload is EINVAL, not an empty key");
    assert_eq!(add_key_core(&t, "user", "toobig", alloc::vec![0u8; USER_PAYLOAD_MAX as usize + 1], true, KEY_SPEC_SESSION_KEYRING),
        einval());
    assert!(add_key_core(&t, "user", "atmax", alloc::vec![0u8; USER_PAYLOAD_MAX as usize], true, KEY_SPEC_SESSION_KEYRING) > 0);
    assert_eq!(add_key_core(&t, "logon", "sub:empty", alloc::vec![], true, KEY_SPEC_SESSION_KEYRING), einval());
}

// A NULL payload POINTER is EINVAL for the user-defined types, distinct from a
// pointer to zero bytes: the preparser tests the pointer, so it cannot be
// papered over as an empty payload.
#[test]
fn a_null_payload_pointer_is_einval() {
    let t = ctx(4102, 7102);
    assert_eq!(add_key_core(&t, "user", "nullptr", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING), einval());
    assert_eq!(add_key_core(&t, "big_key", "nullptr", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING), einval());
}

// A keyring carries NO payload: its content is its links. A non-empty payload
// is EINVAL.
#[test]
fn a_keyring_takes_no_payload() {
    let t = ctx(4103, 7103);
    assert_eq!(add_key_core(&t, "keyring", "with-payload", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING), einval());
    assert!(add_key_core(&t, "keyring", "no-payload", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) > 0);
}

// `big_key` is registered and takes up to 1 MiB — far past what a `user` key
// accepts — and reads back byte-for-byte.
#[test]
fn big_key_accepts_payloads_past_the_user_ceiling() {
    let t = ctx(4104, 0);
    let len = USER_PAYLOAD_MAX as usize + 1;
    let payload = alloc::vec![0xABu8; len];
    let k = add_key_core(&t, "big_key", "large", payload.clone(), true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(k > 0, "big_key must accept what user rejects, got {}", k);
    assert_eq!(read_core(&t, k, 0), Ok(payload));
    assert_eq!(add_key_core(&t, "big_key", "empty", alloc::vec![], true, KEY_SPEC_SESSION_KEYRING), einval());
    assert_eq!(add_key_core(&t, "big_key", "past-max",
        alloc::vec![0u8; BIG_PAYLOAD_MAX as usize + 1], true, KEY_SPEC_SESSION_KEYRING), einval());
}

// A `big_key` is charged a FLAT byte quota regardless of payload size — a
// megabyte payload does not exhaust a 20000-byte quota — because the payload
// is held outside the key.
#[test]
fn big_key_charges_a_flat_quota() {
    let t = ctx(4105, 7105);
    let before = STORE.lock().key_user(7105).nbytes;
    let k = add_key_core(&t, "big_key", "flat", alloc::vec![0u8; 100_000], true, KEY_SPEC_SESSION_KEYRING);
    assert!(k > 0);
    let charged = STORE.lock().key_user(7105).nbytes - before;
    assert!(charged < 100, "a big_key charges a flat quota, charged {}", charged);
}

// The `keyring` type has NO update method: KEYCTL_UPDATE on one is
// EOPNOTSUPP, and adding a keyring of the same name twice mints TWO distinct
// keyrings rather than updating the first.
#[test]
fn keyrings_have_no_update_method() {
    let t = ctx(4106, 7106);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let a = add_key_core(&t, "keyring", "dup", alloc::vec![], false, ring) as i32;
    let b = add_key_core(&t, "keyring", "dup", alloc::vec![], false, ring) as i32;
    assert!(a > 0 && b > 0);
    assert_ne!(a, b, "a keyring is never updated in place; a second add mints a new one");
    assert_eq!(update_core(&t, a, alloc::vec![], false), eopnotsupp());
}

// An updatable type IS updated in place: the same serial comes back and the
// payload is replaced.
#[test]
fn user_keys_are_updated_in_place() {
    let t = ctx(4107, 7107);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let a = add_key_core(&t, "user", "same", alloc::vec![1], true, ring) as i32;
    let b = add_key_core(&t, "user", "same", alloc::vec![2], true, ring) as i32;
    assert_eq!(a, b, "add_key is create-OR-update for a type with an update method");
    assert_eq!(read_core(&t, a, 0), Ok(alloc::vec![2]));
}

// KEYCTL_UPDATE applies the SAME payload contract as add_key: an empty
// payload for a user key is EINVAL rather than a silent truncation to nothing.
#[test]
fn update_applies_the_types_payload_contract() {
    let t = ctx(4108, 7108);
    let k = add_key_core(&t, "user", "contract", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(update_core(&t, k, alloc::vec![], false), einval());
    assert_eq!(update_core(&t, k, alloc::vec![0u8; USER_PAYLOAD_MAX as usize + 1], true), einval());
    assert_eq!(read_core(&t, k, 0), Ok(alloc::vec![1]), "a refused update changes nothing");
}

// The registered type set, and each type's read method. `logon` has none, so
// its payload is write-only.
#[test]
fn the_registered_type_table_matches_its_methods() {
    for (name, readable, updatable) in
        [("keyring", true, false), ("user", true, true), ("logon", false, true), ("big_key", true, true),
         // An asymmetric key has neither method: its material never comes back
         // out, and swapping it under a caller that already queried it would
         // let a signature be checked against a different key.
         ("asymmetric", false, false)]
    {
        let t = types::lookup(name).expect("registered");
        assert_eq!(t.readable, readable, "{} read method", name);
        assert_eq!(t.updatable, updatable, "{} update method", name);
    }
    // The types needing hardware this kernel has no driver for stay
    // unregistered, and an unregistered name is ENODEV out of `add_key`.
    assert!(types::lookup("encrypted").is_none());
    assert!(types::lookup("trusted").is_none());
}

// A `logon` payload is write-only: reading it is EOPNOTSUPP even for the
// owner-possessor, and the refusal comes only AFTER access is granted, so a
// caller with no access gets EACCES instead.
#[test]
fn logon_payloads_are_write_only() {
    let owner = ctx(4109, 7109);
    let stranger = ctx(4110, 7110);
    let k = add_key_core(&owner, "logon", "sub:secret", alloc::vec![1, 2], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(read_core(&owner, k, 0), Err(eopnotsupp()));
    assert_eq!(read_core(&stranger, k, 0), Err(eacces()),
        "denied access is reported before the type's missing read method");
}

// A keyring reads out as an array of 4-byte serials, so a buffer length that
// cannot hold a whole number of them is EINVAL. A NULL buffer is a length
// query and carries no alignment requirement.
#[test]
fn keyring_reads_require_a_serial_aligned_buffer() {
    let t = ctx(4111, 7111);
    let ring = add_key_core(&t, "keyring", "aligned", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let member = add_key_core(&t, "user", "m", alloc::vec![1], true, ring) as i32;
    assert_eq!(read_core(&t, ring, 3), Err(einval()));
    assert_eq!(read_core(&t, ring, 5), Err(einval()));
    assert_eq!(read_core(&t, ring, 0), Ok(member.to_ne_bytes().to_vec()),
        "a length query needs no alignment");
    assert_eq!(read_core(&t, ring, 4), Ok(member.to_ne_bytes().to_vec()));
    // A non-keyring payload has no such requirement.
    assert_eq!(read_core(&t, member, 3), Ok(alloc::vec![1]));
}
