// Keyring membership and search scope: LINK, UNLINK, MOVE, CLEAR, RESTRICT,
// KEYCTL_SEARCH and the `request_key` cred-keyring search.

use super::*;
use super::super::ops::*;

// KEYCTL_LINK must resolve the CHILD special id, not just the ring.
// pam_keyinit does keyctl(LINK, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING);
// passing the raw special id (-4) as the child made link() ENOKEY (gdm logged
// "Failed to link user keyring into session keyring: Required key not available").
#[test]
fn link_resolves_special_child_into_session() {
    let t = ctx(1009, 1009);
    let sess = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let user = get_keyring_id(&t, KEY_SPEC_USER_KEYRING, true) as i32;
    assert_eq!(link_core(&t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), 0);
    assert!(members_of(sess).expect("session is a keyring").contains(&user));
}

// UNLINK likewise resolves the child special id and removes it. Removing a
// key that is not a member is ENOENT (Linux `key_unlink`), not ENOKEY.
#[test]
fn unlink_resolves_special_child() {
    let t = ctx(1010, 1010);
    let sess = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let user = get_keyring_id(&t, KEY_SPEC_USER_KEYRING, true) as i32;
    assert_eq!(link_core(&t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), 0);
    assert_eq!(unlink_core(&t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), 0);
    assert!(!members_of(sess).expect("session is a keyring").contains(&user));
    assert_eq!(unlink_core(&t, KEY_SPEC_USER_KEYRING, KEY_SPEC_SESSION_KEYRING), err(Errno::Enoent));
}

// A keyring cannot contain itself, directly or through a nesting chain —
// Linux `keyring_detect_cycle` answers EDEADLK, and without the test the
// possession walk and the search walk would both loop.
#[test]
fn linking_a_cycle_is_edeadlk() {
    let t = ctx(1040, 6300);
    let a = add_key_core(&t, "keyring", "cycle-a", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let b = add_key_core(&t, "keyring", "cycle-b", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(link_core(&t, a, a), err(Errno::Edeadlk), "self-link");
    assert_eq!(link_core(&t, b, a), 0);
    assert_eq!(link_core(&t, a, b), err(Errno::Edeadlk), "a -> b -> a");
}

// MOVE unlinks from the source and links into the destination in one step.
#[test]
fn move_transfers_membership() {
    let t = ctx(1041, 6301);
    let from = add_key_core(&t, "keyring", "move-from", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let to   = add_key_core(&t, "keyring", "move-to", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k    = add_key_core(&t, "user", "moving-key", alloc::vec![1], true, from) as i32;
    assert_eq!(move_core(&t, k, from, to, 0), 0);
    assert!(!members_of(from).expect("keyring").contains(&k));
    assert!(members_of(to).expect("keyring").contains(&k));
}

// KEYCTL_MOVE_EXCL refuses to displace a same-typed, same-described key in the
// destination; without the flag the move proceeds.
#[test]
fn move_excl_refuses_a_colliding_destination() {
    let t = ctx(1042, 6302);
    let from = add_key_core(&t, "keyring", "excl-from", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let to   = add_key_core(&t, "keyring", "excl-to", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let a = add_key_core(&t, "user", "collide", alloc::vec![1], true, from) as i32;
    let _b = add_key_core(&t, "user", "collide", alloc::vec![2], true, to) as i32;
    assert_eq!(move_core(&t, a, from, to, KEYCTL_MOVE_EXCL), err(Errno::Eexist));
    assert_eq!(move_core(&t, a, from, to, 0), 0);
    // An undefined flag bit is EINVAL.
    assert_eq!(move_core(&t, a, to, from, 0x8000_0000), einval());
}

// CLEAR empties a keyring; a non-keyring target is ENOTDIR.
#[test]
fn clear_empties_a_keyring_and_rejects_a_plain_key() {
    let t = ctx(1043, 6303);
    let ring = add_key_core(&t, "keyring", "clear-me", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k = add_key_core(&t, "user", "clear-member", alloc::vec![7u8], true, ring) as i32;
    assert!(members_of(ring).expect("keyring").contains(&k));
    assert_eq!(clear_core(&t, k), err(Errno::Enotdir), "a plain key is not a keyring");
    assert_eq!(clear_core(&t, ring), 0);
    assert!(members_of(ring).expect("keyring").is_empty());
}

// RESTRICT_KEYRING with a NULL type installs `restrict_link_reject`: every
// later link into the ring is EPERM, and a second restriction is EEXIST.
#[test]
fn restrict_reject_blocks_further_links() {
    let t = ctx(1044, 6304);
    let ring = add_key_core(&t, "keyring", "restricted", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k = add_key_core(&t, "user", "restrict-child", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(restrict_core(&t, ring, None, None), 0);
    assert_eq!(link_core(&t, k, ring), eperm(), "restrict_link_reject refuses every link");
    assert_eq!(restrict_core(&t, ring, None, None), err(Errno::Eexist));
}

// A named restriction type needs its type-specific parser. `asymmetric` owns
// one; another registered type remains ENOENT and an unknown name is ENOKEY.
#[test]
fn restrict_named_type_is_enoent_and_unknown_is_enokey() {
    let t = ctx(1045, 6305);
    let ring = add_key_core(&t, "keyring", "restrict-named", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(restrict_core(&t, ring, Some("keyring"), Some("builtin_trusted")), err(Errno::Enoent));
    assert_eq!(restrict_core(&t, ring, Some("no-such-type"), Some("builtin_trusted")), enokey());
    let k = add_key_core(&t, "user", "restrict-nonring", alloc::vec![7u8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(restrict_core(&t, k, None, None), err(Errno::Enotdir));
}

#[test]
fn asymmetric_key_or_keyring_restriction_verifies_the_issuer_signature() {
    let t = ctx(1048, 6308);
    let trust = add_key_core(&t, "asymmetric", "trust", super::pkey::certificate_payload(), true,
        KEY_SPEC_SESSION_KEYRING) as i32;
    let ring = add_key_core(&t, "keyring", "signature-restricted", alloc::vec![], false,
        KEY_SPEC_SESSION_KEYRING) as i32;
    let spec = alloc::format!("key_or_keyring:{trust}");
    assert_eq!(restrict_core(&t, ring, Some("asymmetric"), Some(&spec)), 0);
    assert!(add_key_core(&t, "asymmetric", "verified", super::pkey::certificate_payload(), true, ring) > 0);
    let mut altered = super::pkey::certificate_payload();
    let at = altered.windows(b"pkey vector".len()).rposition(|w| w == b"pkey vector")
        .expect("subject appears after issuer in the certificate");
    altered[at] ^= 1;
    assert_eq!(add_key_core(&t, "asymmetric", "bad-signature", altered, true, ring),
        err(Errno::Ekeyrejected));
}

#[test]
fn asymmetric_chain_restriction_uses_existing_destination_certificates() {
    let t = ctx(1049, 6309);
    let ring = add_key_core(&t, "keyring", "chain-restricted", alloc::vec![], false,
        KEY_SPEC_SESSION_KEYRING) as i32;
    assert!(add_key_core(&t, "asymmetric", "chain-anchor", super::pkey::certificate_payload(), true, ring) > 0);
    assert_eq!(restrict_core(&t, ring, Some("asymmetric"), Some("key_or_keyring:0:chain")), 0);
    assert!(add_key_core(&t, "asymmetric", "chain-child", super::pkey::certificate_payload(), true, ring) > 0);
}

// KEYCTL_SEARCH searches the NAMED keyring's tree, not the global key store:
// a key that exists in another task's keyring is not found even when its perm
// byte would allow the caller to use it once found.
#[test]
fn search_is_scoped_to_the_named_keyring_tree() {
    let owner = ctx(1046, 6306);
    let stranger = ctx(1047, 6307);
    let k = add_key_core(&owner, "user", "scoped-search", alloc::vec![5], true, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(k, KEY_PERM_VALID);
    let stranger_ring = get_keyring_id(&stranger, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(search_core(&stranger, stranger_ring, "user", "scoped-search", 0), enokey(),
        "a globally-permissive key in someone else's ring is still not in MY ring");
    let owner_ring = get_keyring_id(&owner, KEY_SPEC_SESSION_KEYRING, true) as i32;
    assert_eq!(search_core(&owner, owner_ring, "user", "scoped-search", 0), k as i64);
}

// The search descends into nested keyrings (KEYRING_SEARCH_RECURSE).
#[test]
fn search_descends_into_nested_keyrings() {
    let t = ctx(1048, 6308);
    let outer = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let inner = add_key_core(&t, "keyring", "nested-ring", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k = add_key_core(&t, "user", "nested-key", alloc::vec![6], true, inner) as i32;
    assert_eq!(search_core(&t, outer, "user", "nested-key", 0), k as i64);
}

// KEYCTL_SEARCH links the hit into the destination keyring when one is given.
#[test]
fn search_links_the_hit_into_the_destination() {
    let t = ctx(1049, 6309);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let dest = add_key_core(&t, "keyring", "search-dest", alloc::vec![], false, KEY_SPEC_SESSION_KEYRING) as i32;
    let k = add_key_core(&t, "user", "search-linked", alloc::vec![7], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(search_core(&t, ring, "user", "search-linked", dest), k as i64);
    assert!(members_of(dest).expect("keyring").contains(&k));
}

// `request_key` searches the CALLER'S thread/process/session keyrings, in that
// order — never the whole store. A key only reachable from another task is
// ENOKEY, and one in the caller's own thread keyring is found.
#[test]
fn request_key_searches_only_the_callers_cred_keyrings() {
    let owner = ctx(1050, 6310);
    let stranger = ctx(1051, 6311);
    let k = add_key_core(&owner, "user", "reqkey-scope", alloc::vec![8], true, KEY_SPEC_SESSION_KEYRING) as i32;
    force_perm(k, KEY_PERM_VALID);
    assert_eq!(request_key_core(&stranger, "user", "reqkey-scope", None, 0), enokey());
    assert_eq!(request_key_core(&owner, "user", "reqkey-scope", None, 0), k as i64);
    let thread_key = add_key_core(&owner, "user", "reqkey-thread", alloc::vec![9], true, KEY_SPEC_THREAD_KEYRING) as i32;
    assert_eq!(request_key_core(&owner, "user", "reqkey-thread", None, 0), thread_key as i64);
}

// An unregistered type is ENOKEY out of `key_type_lookup` for both search
// paths, and a miss is ENOKEY (there is no `/sbin/request-key` upcall).
#[test]
fn request_key_miss_and_unknown_type_are_enokey() {
    let t = ctx(1052, 6312);
    assert_eq!(request_key_core(&t, "user", "never-added", None, 0), enokey());
    assert_eq!(request_key_core(&t, "no-such-type", "x", None, 0), enokey());
}

// A revoked or expired key never SATISFIES a search, and KEYCTL_SEARCH reports
// WHY. Only "the keyrings were searchable and held no match" is turned into
// ENOKEY; a candidate skipped for being revoked or stale surfaces as
// EKEYREVOKED/EKEYEXPIRED, because a caller naming a specific key needs to tell
// "gone" from "never there" — it decides whether to re-fetch or to give up.
#[test]
fn a_revoked_or_expired_key_does_not_satisfy_a_search_and_says_why() {
    let t = ctx(1053, 6313);
    let ring = get_keyring_id(&t, KEY_SPEC_SESSION_KEYRING, true) as i32;
    let a = add_key_core(&t, "user", "search-revoked", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    let b = add_key_core(&t, "user", "search-expired", alloc::vec![1], true, KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(search_core(&t, ring, "user", "search-revoked", 0), a as i64);
    assert_eq!(revoke_core(&t, a), 0);
    assert_eq!(search_core(&t, ring, "user", "search-revoked", 0), err(Errno::Ekeyrevoked));
    assert_eq!(set_timeout_core(&t, b, 1), 0);
    let mut later = ctx(1053, 6313);
    later.now_ns = 2 * 1_000_000_000;
    assert_eq!(search_core(&later, ring, "user", "search-expired", 0), err(Errno::Ekeyexpired));
    // The state check runs BEFORE the description is compared, so a revoked key
    // of the same TYPE colours the answer even for an unrelated name. A name
    // that matches nothing in a keyring holding no dead keys is plain ENOKEY.
    let clean = add_key_core(&t, "keyring", "search-clean-ring", alloc::vec![], false,
        KEY_SPEC_SESSION_KEYRING) as i32;
    assert_eq!(search_core(&t, clean, "user", "search-never-added", 0), enokey());
}
