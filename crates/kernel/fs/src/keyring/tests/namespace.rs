// The namespace dimensions of the key store, which `KEYCTL_CAPABILITIES`
// reports as `KEYCTL_CAPS1_NS_KEYRING_NAME` and `KEYCTL_CAPS1_NS_KEY_TAG`.
//
// Two independent scopings, and they are independent on purpose:
//   * a keyring NAME, and the per-uid keyrings and the persistent register that
//     are looked up by one, belong to a USER namespace. Without this, one
//     container joining `_ses` by name lands in another container's session
//     keyring, and `@u` for uid 1000 is the same object for every container on
//     the box.
//   * a key of a NETWORK-scoped type belongs to a NETWORK namespace, through
//     the index key's domain tag. Without this a cached answer that is only
//     true on one network is handed to a task on another.
//
// Each test names the state that must NOT be shared, so a regression that
// flattens either dimension shows up as two ids that became equal.

use super::*;
use super::super::ops::*;
use super::super::store::STORE;

/// Namespace identities used below. Any non-zero value names a namespace that
/// is not the boot one; the numbers themselves carry no meaning.
const NS_A: u64 = 0x1940_0001;
const NS_B: u64 = 0x1940_0002;
const NET_A: u64 = 0x1940_1001;
const NET_B: u64 = 0x1940_1002;

/// `find_keyring_by_name` walks the CALLER'S namespace's name list. Two tasks
/// in different user namespaces asking to join the same name get two different
/// keyrings, and neither can reach the other's.
#[test]
fn a_session_keyring_name_is_scoped_to_the_user_namespace() {
    let map = identity_map(u32::MAX);
    let owner = ns_ctx(7401, 7400, NS_A, &map);
    let ring = join_session(&owner, Some("shared-name")) as i32;
    assert!(ring > 0, "created: {ring}");
    // A named session keyring is created without Search in its user byte, so
    // joining it from another task is refused until its owner widens the perms.
    // Widened here, because what this test is about is the NAME lookup, not the
    // permission that gates it.
    force_perm(ring, KEY_POS_ALL | KEY_USR_ALL);
    // Same namespace, same uid: the name resolves to the keyring already there.
    let same = ns_ctx(7402, 7400, NS_A, &map);
    assert_eq!(join_session(&same, Some("shared-name")), ring as i64,
        "inside one namespace the name still resolves");
    // Another namespace: not a candidate, so a fresh keyring of that name is
    // created instead and the two are different objects.
    let other = ns_ctx(7403, 7400, NS_B, &map);
    let fresh = join_session(&other, Some("shared-name"));
    assert!(fresh > 0);
    assert_ne!(fresh, ring as i64, "the same name in two user namespaces is two keyrings");
}

/// `kuid_has_mapping`: a candidate whose owner uid the caller's namespace
/// cannot name is skipped, and a fresh keyring is created instead. A namespace
/// with no map written can name nothing.
#[test]
fn a_keyring_owned_by_an_unmapped_uid_is_not_a_candidate() {
    let map = identity_map(u32::MAX);
    let owner = ns_ctx(7405, 4242, NS_A, &map);
    let ring = join_session(&owner, Some("unmapped-owner")) as i32;
    assert!(ring > 0);
    force_perm(ring, KEY_POS_ALL | KEY_USR_ALL | KEY_OTH_ALL);
    // A caller of the same namespace that CAN name uid 4242 finds it.
    let wide = ns_ctx(7406, 4242, NS_A, &map);
    assert_eq!(join_session(&wide, Some("unmapped-owner")), ring as i64);
    // Same namespace and the same widened perms, but this caller's map covers
    // uids 0..8 only, so it cannot name uid 4242 and must not find that keyring.
    let narrow = identity_map(8);
    let blind = ns_ctx(7407, 0, NS_A, &narrow);
    let fresh = join_session(&blind, Some("unmapped-owner"));
    assert!(fresh > 0);
    assert_ne!(fresh, ring as i64, "a candidate whose owner uid is unmapped is skipped");
}

/// `look_up_user_keyrings` searches the namespace's own `.user_reg` register,
/// so the same uid has a different user and user-session keyring in each user
/// namespace.
#[test]
fn the_per_uid_keyrings_are_per_user_namespace() {
    let map = identity_map(u32::MAX);
    let a = ns_ctx(7409, 5150, NS_A, &map);
    let b = ns_ctx(7410, 5150, NS_B, &map);
    let user_a = get_keyring_id(&a, KEY_SPEC_USER_KEYRING, true);
    let user_b = get_keyring_id(&b, KEY_SPEC_USER_KEYRING, true);
    let sess_a = get_keyring_id(&a, KEY_SPEC_USER_SESSION_KEYRING, true);
    let sess_b = get_keyring_id(&b, KEY_SPEC_USER_SESSION_KEYRING, true);
    assert!(user_a > 0 && user_b > 0 && sess_a > 0 && sess_b > 0);
    assert_ne!(user_a, user_b, "uid 5150's user keyring is per user namespace");
    assert_ne!(sess_a, sess_b, "and so is its user-session keyring");
    // A second task of the same uid in the same namespace gets the SAME ones.
    let again = ns_ctx(7411, 5150, NS_A, &map);
    assert_eq!(get_keyring_id(&again, KEY_SPEC_USER_KEYRING, false), user_a);
}

/// A key added to one namespace's user keyring is invisible to the same uid in
/// another namespace — the consequence that makes the split matter.
#[test]
fn a_key_in_one_namespaces_user_keyring_is_invisible_in_another() {
    let map = identity_map(u32::MAX);
    let a = ns_ctx(7413, 5151, NS_A, &map);
    let b = ns_ctx(7414, 5151, NS_B, &map);
    let key = add_key_core(&a, "user", "ns-scoped-secret", alloc::vec![1u8], true,
        KEY_SPEC_USER_KEYRING);
    assert!(key > 0, "added: {key}");
    assert_eq!(search_core(&b, KEY_SPEC_USER_KEYRING, "user", "ns-scoped-secret", 0), enokey(),
        "the same uid in another user namespace sees nothing of it");
    assert_eq!(search_core(&a, KEY_SPEC_USER_KEYRING, "user", "ns-scoped-secret", 0), key);
}

/// `ns->persistent_keyring_register`: one register per user namespace, so a
/// uid's persistent keyring is a different object in each.
#[test]
fn the_persistent_register_is_per_user_namespace() {
    let map = identity_map(u32::MAX);
    let mut a = ns_ctx(7417, 0, NS_A, &map);
    a.set_uid = true;
    let mut b = ns_ctx(7418, 0, NS_B, &map);
    b.set_uid = true;
    let dest_a = join_session(&a, None) as i32;
    let dest_b = join_session(&b, None) as i32;
    let ring_a = get_persistent(&a, 6001, dest_a);
    let ring_b = get_persistent(&b, 6001, dest_b);
    assert!(ring_a > 0 && ring_b > 0, "{ring_a} {ring_b}");
    assert_ne!(ring_a, ring_b, "uid 6001's persistent keyring is per user namespace");
    let g = STORE.lock();
    let reg_a = g.persistent_register.get(&NS_A).copied().expect("namespace A has a register");
    let reg_b = g.persistent_register.get(&NS_B).copied().expect("namespace B has a register");
    assert_ne!(reg_a, reg_b, "and so is the register holding it");
}

/// The domain tag. A network-scoped type's keys are indexed under the creating
/// task's network namespace, so the same description in two of them is two
/// keys and a search in one never finds the other's.
#[test]
fn a_network_scoped_key_type_is_indexed_per_network_namespace() {
    let a = net_ctx(7421, 7421, NET_A);
    let b = net_ctx(7422, 7421, NET_B);
    let ring_a = join_session(&a, None) as i32;
    let ring_b = join_session(&b, None) as i32;
    let key_a = add_key_core(&a, DNS_RESOLVER_KEY_TYPE, "example.test", b"10.0.0.1".to_vec(), true,
        ring_a);
    let key_b = add_key_core(&b, DNS_RESOLVER_KEY_TYPE, "example.test", b"10.0.0.2".to_vec(), true,
        ring_b);
    assert!(key_a > 0 && key_b > 0, "{key_a} {key_b}");
    assert_ne!(key_a, key_b, "one description, two networks, two keys");
    // And each network only finds its own answer. Both keyrings are linked into
    // the same store, so this is the domain tag doing the work.
    let mut both = net_ctx(7423, 7421, NET_A);
    STORE.lock().session.insert(both.t.tid, ring_a);
    assert_eq!(search_core(&both, ring_a, DNS_RESOLVER_KEY_TYPE, "example.test", 0), key_a);
    both.t.net_ns = NET_B;
    assert_eq!(search_core(&both, ring_a, DNS_RESOLVER_KEY_TYPE, "example.test", 0), enokey(),
        "the other network's search does not match this network's cached answer");
}

/// ... and every type that is NOT network-scoped shares the single default
/// domain, so the network namespace changes nothing for it. Without this
/// clause the tag would silently partition every key in the system.
#[test]
fn an_ordinary_key_type_ignores_the_network_namespace() {
    let a = net_ctx(7425, 7425, NET_A);
    let ring = join_session(&a, None) as i32;
    let key = add_key_core(&a, "user", "net-agnostic", alloc::vec![9u8], true, ring);
    assert!(key > 0);
    let mut b = net_ctx(7426, 7425, NET_B);
    STORE.lock().session.insert(b.t.tid, ring);
    assert_eq!(search_core(&b, ring, "user", "net-agnostic", 0), key,
        "a `user` key is one key kernel-wide, whatever network its reader is on");
    b.t.net_ns = NET_A;
    assert_eq!(search_core(&b, ring, "user", "net-agnostic", 0), key);
}
