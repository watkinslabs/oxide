// Single-key ops: add_key admission + create-or-update, UPDATE, REVOKE,
// INVALIDATE, CHOWN, SETPERM, SET_TIMEOUT, READ, DESCRIBE.

use super::*;
use super::super::ops::*;

// add_key links the new key into the session keyring; the keyring's members
// contain its serial (real linkage, not a flat global bag).
#[test]
fn add_key_links_into_session_keyring() {
    let t = ctx(1006, 1006);
    let sess = join_session(&t, None) as i32;
    let k = add_key_core(&t, "user", "my-secret", alloc::vec![1, 2, 3], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let members = members_of(sess).expect("session is a keyring");
    assert!(members.contains(&k), "added key linked into the session keyring: {members:?}");
}

// Key descriptions are user C strings, not UTF-8 text. Preserve raw byte
// identity through the same reversible path codec used at the syscall boundary.
#[test]
fn non_utf8_description_keeps_exact_identity() {
    let t = ctx(1011, 1011);
    let desc = key_string_from_bytes(b"raw-\xff");
    assert_ne!(desc, String::from("raw-\u{fffd}"), "invalid byte must not collapse to replacement char");
    let serial = add_key_core(&t, "user", &desc, alloc::vec![9], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(STORE.lock().keys.get(&serial).expect("added key exists").description, desc);
}

// `add_key` is create-OR-UPDATE (`key_create_or_update`): re-adding the same
// type+description into the same keyring returns the SAME serial with the new
// payload. Minting a second key each time makes a daemon that refreshes its
// key accumulate duplicates that shadow each other in every later search.
#[test]
fn add_key_updates_an_existing_key_in_place() {
    let t = ctx(1020, 6200);
    let sess = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let a = add_key_core(&t, "user", "refresh-me", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let b = add_key_core(&t, "user", "refresh-me", alloc::vec![2, 2], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(a, b, "same type+description in the same ring updates in place");
    assert_eq!(read_core(&t, a, 0), Ok(alloc::vec![2, 2]), "the payload was replaced");
    let members = members_of(sess).expect("session is a keyring");
    assert_eq!(members.iter().filter(|&&m| m == a).count(), 1, "linked exactly once: {members:?}");
}

// An unregistered key type is ENODEV out of `key_create_or_update`, not a
// silently accepted key of a type nothing can ever read back.
#[test]
fn add_key_unknown_type_is_enodev() {
    let t = ctx(1021, 6201);
    assert_eq!(add_key_core(&t, "not-a-real-type", "x", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING), err(Errno::Enodev));
}

// An empty description is EINVAL (the create path's `!index_key.description`
// test). A NULL description pointer reaches the core the same way, as an empty
// string, so it is EINVAL and NOT EFAULT: the argument is optional at the ABI.
#[test]
fn add_key_rejects_empty_description() {
    let t = ctx(1022, 6202);
    assert_eq!(add_key_core(&t, "user", "", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING), einval());
    assert!(add_key_core(&t, "keyring", "visible", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) >= FIRST_SERIAL as i64);
}

// A `.`-prefixed description names a kernel-internal keyring and is EPERM.
// The rule is a PREFIX test on the type name, and it is applied at the syscall
// entry ahead of the payload copy so a bad payload pointer cannot mask it.
#[test]
fn dotted_keyring_descriptions_are_reserved() {
    assert!(super::super::types::dot_reserved("keyring", ".hidden"));
    assert!(super::super::types::dot_reserved("keyringfoo", ".hidden"),
        "the type test is a prefix test, not an exact match");
    assert!(!super::super::types::dot_reserved("keyring", "visible"));
    assert!(!super::super::types::dot_reserved("user", ".dotted"),
        "only the keyring type reserves the dot prefix");
}

// `logon_vet_description` requires a QUALIFIED description: a `:` that is not
// the first character. It does NOT require a non-empty suffix — `"trailing:"`
// is a valid logon description, and rejecting it turns away callers Linux
// accepts.
#[test]
fn logon_descriptions_must_carry_a_subsystem_prefix() {
    let t = ctx(1023, 6203);
    assert_eq!(add_key_core(&t, "logon", "nocolon", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING), einval());
    assert_eq!(add_key_core(&t, "logon", ":leading", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING), einval());
    assert!(add_key_core(&t, "logon", "trailing:", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) >= FIRST_SERIAL as i64,
        "an empty suffix is accepted; only a missing or leading colon is EINVAL");
    assert!(add_key_core(&t, "logon", "sub:key", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) >= FIRST_SERIAL as i64);
}

// `key_type_logon` deliberately has no `.read` method: its payload is
// write-only, so KEYCTL_READ is EOPNOTSUPP even for the owner-possessor.
#[test]
fn logon_payload_is_not_readable() {
    let t = ctx(1025, 6204);
    let k = add_key_core(&t, "logon", "sub:secret", alloc::vec![7, 7], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(read_core(&t, k, 0), Err(err(Errno::Eopnotsupp)),
        "a logon key's payload can never be read back");
    assert!(describe_core(&t, k).is_ok(), "...but its metadata still describes");
}

// REVOKE takes effect: the key is EKEYREVOKED at the chokepoint afterwards,
// and a second REVOKE reports EKEYREVOKED rather than succeeding twice.
#[test]
fn revoke_makes_later_ops_ekeyrevoked() {
    let t = ctx(1026, 6205);
    let k = add_key_core(&t, "user", "revoke-me", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(revoke_core(&t, k), 0);
    // READ collapses every lookup failure to ENOKEY, so a revoked key reads
    // as ENOKEY even though every OTHER command reports EKEYREVOKED.
    assert_eq!(read_core(&t, k, 0), Err(enokey()));
    assert_eq!(update_core(&t, k, alloc::vec![2], true), err(Errno::Ekeyrevoked));
    assert_eq!(revoke_core(&t, k), err(Errno::Ekeyrevoked));
    // DESCRIBE uses a PARTIAL lookup, so a revoked key can still be described.
    assert!(describe_core(&t, k).is_ok());
}

// INVALIDATE is distinct from REVOKE: the key becomes ENOKEY (gone), and it is
// unlinked from every keyring it was a member of.
#[test]
fn invalidate_removes_the_key_from_every_keyring() {
    let t = ctx(1027, 6206);
    let sess = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let k = add_key_core(&t, "user", "invalidate-me", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(members_of(sess).expect("keyring").contains(&k));
    assert_eq!(invalidate_core(&t, k), 0);
    assert_eq!(read_core(&t, k, 0), Err(enokey()), "invalidated is ENOKEY, not EKEYREVOKED");
    assert!(!members_of(sess).expect("keyring").contains(&k), "unlinked by the gc");
}

// SET_TIMEOUT actually expires the key: once the clock passes the deadline
// every full lookup is EKEYEXPIRED. Recording an expiry that never fires is
// an accept-and-ignore.
#[test]
fn set_timeout_expires_the_key() {
    let t = ctx(1028, 6207);
    let k = add_key_core(&t, "user", "expire-me", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(set_timeout_core(&t, k, 60), 0);
    assert_eq!(read_core(&t, k, 0), Ok(alloc::vec![1]), "still live before the deadline");
    let mut later = ctx(1028, 6207);
    later.now_ns = 61 * 1_000_000_000;
    // READ reports the expired key as ENOKEY; UPDATE, which does not collapse
    // its lookup errors, reports EKEYEXPIRED.
    assert_eq!(read_core(&later, k, 0), Err(enokey()));
    assert_eq!(update_core(&later, k, alloc::vec![9], true), err(Errno::Ekeyexpired));
    // Clearing the timeout brings it back (`secs == 0` → no expiry).
    assert_eq!(set_timeout_core(&later, k, 0), 0);
    assert_eq!(read_core(&later, k, 0), Ok(alloc::vec![1]));
}

// SET_TIMEOUT has NO CAP_SYS_ADMIN bypass in Linux: `keyctl_set_timeout`
// looks the key up with KEY_NEED_SETATTR and its only alternative path is an
// instantiation authorisation token. Letting CAP_SYS_ADMIN through let a
// privileged process expire a key it had no SETATTR permission on.
#[test]
fn set_timeout_has_no_sysadmin_bypass() {
    let owner = ctx(1029, 6208);
    let admin = admin_ctx(1030, 6209);
    let k = add_key_core(&owner, "user", "timeout-perm", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(set_timeout_core(&admin, k, 10), eacces(),
        "CAP_SYS_ADMIN does not grant KEY_NEED_SETATTR");
}

// SETPERM rejects any bit outside the four 6-bit bytes BEFORE looking the key
// up (`keyctl_setperm_key`'s first test).
#[test]
fn setperm_rejects_bits_outside_the_four_bytes() {
    let t = ctx(1031, 6210);
    let k = add_key_core(&t, "user", "setperm-bits", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(setperm_core(&t, k, 0x4000_0000), einval(), "bit 30 is not a perm bit");
    assert_eq!(setperm_core(&t, k, 0x0000_0040), einval(), "bit 6 of the other byte is not one either");
    assert_eq!(setperm_core(&t, k, KEY_PERM_VALID), 0);
}

// After the KEY_NEED_SETATTR check passes, Linux applies a SECOND gate: only
// the key's owner (by fsuid) or CAP_SYS_ADMIN may actually write the perms.
#[test]
fn setperm_needs_owner_or_sysadmin_even_with_setattr() {
    let owner = ctx(1032, 6211);
    let stranger = ctx(1033, 6212);
    let k = add_key_core(&owner, "user", "setperm-owner", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    // Grant the stranger SETATTR through the other byte — Linux still refuses.
    force_perm(k, KEY_PERM_VALID);
    assert_eq!(setperm_core(&stranger, k, KEY_USR_ALL), eacces(),
        "SETATTR permission alone does not make a non-owner able to set perms");
    let admin = admin_ctx(1034, 6212);
    assert_eq!(setperm_core(&admin, k, KEY_USR_ALL), 0, "CAP_SYS_ADMIN passes the owner gate");
}

// CHOWN: `(uid_t)-1` leaves an id alone, giving the key to another uid needs
// CAP_SYS_ADMIN, and setting a gid the caller subscribes to does not.
#[test]
fn chown_privileged_transfers_need_sysadmin() {
    let owner = ctx(1035, 6213);
    let k = add_key_core(&owner, "user", "chown-me", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(chown_core(&owner, k, u32::MAX, u32::MAX), 0, "both -1 is a no-op success");
    assert_eq!(chown_core(&owner, k, 6214, u32::MAX), eacces(),
        "giving the key away needs CAP_SYS_ADMIN");
    assert_eq!(chown_core(&owner, k, u32::MAX, 6213), 0,
        "setting the gid to a group the caller is in is unprivileged");
    // The privileged transfer still needs KEY_NEED_SETATTR first, so the
    // CAP_SYS_ADMIN caller here is the same possessing task.
    let admin = admin_ctx(1035, 6213);
    assert_eq!(chown_core(&admin, k, 6214, u32::MAX), 0);
    assert_eq!(STORE.lock().keys[&k].uid, 6214, "the transfer took effect");
}

// DESCRIBE renders Linux's `type;uid;gid;perm;description` with a trailing NUL.
#[test]
fn describe_matches_the_linux_descriptor_format() {
    let t = ctx(1037, 6215);
    let k = add_key_core(&t, "user", "describe-fmt", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let perm = STORE.lock().keys[&k].perm;
    let d = describe_core(&t, k).expect("owner-possessor has VIEW");
    assert_eq!(d, alloc::format!("user;6215;6215;{perm:08x};describe-fmt\0"));
}

// A `user` key's DEFAULT perm is Linux's computed mask, not "possessor and
// user get everything": the user byte is KEY_USR_VIEW alone. The owner still
// reads it because they POSSESS it (it is in their session keyring).
#[test]
fn default_perm_matches_key_create_or_update() {
    let t = ctx(1038, 6216);
    let k = add_key_core(&t, "user", "default-perm", alloc::vec![4], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let perm = STORE.lock().keys[&k].perm;
    assert_eq!(perm, KEY_POS_ALL | KEY_USR_VIEW,
        "user type is readable and updatable, so every possessor bit is set");
    assert_eq!(perm & KEY_USR_ALL, KEY_USR_VIEW, "the user byte grants VIEW only");
    assert_eq!(read_core(&t, k, 0), Ok(alloc::vec![4]), "the owner reads it by possession");
}

// A `logon` key has no read method, so KEY_POS_READ is absent from its default.
#[test]
fn default_perm_drops_pos_read_for_an_unreadable_type() {
    let t = ctx(1039, 6217);
    let k = add_key_core(&t, "logon", "sub:noread", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let perm = STORE.lock().keys[&k].perm;
    assert_eq!(perm & KEY_POS_READ, 0, "no `type->read` means no KEY_POS_READ");
    assert_eq!(perm & KEY_POS_WRITE, KEY_POS_WRITE, "`type->update` still grants KEY_POS_WRITE");
}

// REVOKE retries the lookup with SETATTR when WRITE is denied: revoking is an
// attribute change as much as a write, and a key whose mask grants Setattr but
// not Write is still revocable. Without the retry a holder cannot withdraw its
// own key.
#[test]
fn revoke_falls_back_to_setattr_permission() {
    let owner = ctx(3101, 7101);
    let ring = get_keyring_id(&owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let k = add_key_core(&owner, "user", "revoke-setattr", alloc::vec![1], true, ring) as i32;
    let peer = ctx(3102, 7102);
    // Setattr for everyone, Write for nobody.
    force_perm(k, KEY_NEED_SETATTR | KEY_NEED_VIEW);
    assert_eq!(revoke_core(&peer, k), 0, "SETATTR alone is enough to revoke");
    assert!(STORE.lock().keys[&k].revoked);
}

// With neither Write nor Setattr the retry does not paper over the denial.
#[test]
fn revoke_without_write_or_setattr_is_denied() {
    let owner = ctx(3103, 7103);
    let ring = get_keyring_id(&owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let k = add_key_core(&owner, "user", "revoke-denied", alloc::vec![1], true, ring) as i32;
    let peer = ctx(3104, 7104);
    force_perm(k, KEY_NEED_VIEW);
    assert_eq!(revoke_core(&peer, k), eacces());
}

// Re-revoking reports EKEYREVOKED, not EACCES: the full lookup validates the
// key BEFORE the permission check, so a caller learns the key is already gone
// rather than that it lacks access to it.
#[test]
fn revoking_twice_reports_the_key_is_already_revoked() {
    let t = ctx(3105, 7105);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let k = add_key_core(&t, "user", "revoke-twice", alloc::vec![1], true, ring) as i32;
    assert_eq!(revoke_core(&t, k), 0);
    assert_eq!(revoke_core(&t, k), err(Errno::Ekeyrevoked));
}

// A helper holding the key's authorisation token may set a timeout on it even
// though it has no permission on a key it does not yet own — it has to be able
// to bound the lifetime of what it is about to build.
#[test]
fn set_timeout_accepts_the_authorisation_token_instead_of_setattr() {
    let requester = ctx(3106, 7106);
    let ring = get_keyring_id(&requester, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let helper = ctx(3107, 7107);
    let hring = get_keyring_id(&helper, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let (key, _auth) = {
        let mut g = STORE.lock();
        let user = super::super::types::lookup("user").expect("user type");
        let key = g.mint_uninstantiated(user, "timeout-authtoken", 7106, 7106, 0, 0).expect("mint");
        let auth = super::super::auth::request_key_auth_new(&mut g, key, "create", b"", ring,
            &requester.t).expect("token");
        g.link(hring, auth).expect("hand the token to the helper");
        (key, auth)
    };
    // The key's mask grants nothing at all, so this is the token's doing.
    let stranger = ctx(3108, 7108);
    assert_eq!(set_timeout_core(&stranger, key, 30), eacces(),
        "a task without the token is denied");
    assert_eq!(set_timeout_core(&helper, key, 30), 0,
        "the token holder may bound the key it was asked to build");
    assert!(STORE.lock().keys[&key].expiry_ns > 0);
}
