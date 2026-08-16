// SID table tests.
//
// The contract these pin: a SID names exactly one context and one context
// yields exactly one SID, decided on the whole context and never on a subset
// of its fields. The partial-key cases below (differ only in MLS high level /
// only in categories / only in role / only in user) are the positive control
// for that — each must produce a DIFFERENT SID.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::context::ValidContext;
use crate::ebitmap::Ebitmap;
use crate::mls::{Level, Range};

/// Context with the given triple and no categories.
fn ctx(user: u32, role: u32, ty: u32) -> Context {
    Context::Valid(ValidContext { user, role, ty, range: Range::default() })
}

/// Context with an explicit sensitivity range and category set on the high level.
fn ctx_mls(user: u32, role: u32, ty: u32, low: u32, high: u32, cats: &[u32]) -> Context {
    let mut cat = Ebitmap::new();
    for c in cats { cat.set(*c, true); }
    let range = Range {
        low: Level { sens: low, cat: Ebitmap::new() },
        high: Level { sens: high, cat },
    };
    Context::Valid(ValidContext { user, role, ty, range })
}

fn unmapped(s: &str) -> Context { Context::Unmapped(String::from(s)) }

/// Table with the initial SIDs this crate names installed.
fn seeded() -> Sidtab {
    let mut t = Sidtab::new();
    t.set_initial(InitSid::Kernel.sid(), ctx(1, 1, 1)).unwrap();
    t.set_initial(InitSid::Unlabeled.sid(), ctx(1, 1, 2)).unwrap();
    t.set_initial(InitSid::File.sid(), ctx(1, 1, 3)).unwrap();
    t
}

#[test]
fn initial_sids_round_trip() {
    let t = seeded();
    assert_eq!(t.lookup(InitSid::Kernel.sid()), Some(&ctx(1, 1, 1)));
    assert_eq!(t.lookup(InitSid::File.sid()), Some(&ctx(1, 1, 3)));
    assert_eq!(t.count(), 0);
}

#[test]
fn null_sid_has_no_entry_but_searches_to_unlabeled() {
    let t = seeded();
    assert_eq!(t.lookup(SECSID_NULL), None);
    assert_eq!(t.search(SECSID_NULL), Some(&ctx(1, 1, 2)));
    assert_eq!(t.lookup(SECSID_WILD), None);
    assert_eq!(t.search(SECSID_WILD), Some(&ctx(1, 1, 2)));
}

#[test]
fn unset_initial_sid_searches_to_unlabeled() {
    let t = seeded();
    assert_eq!(t.lookup(InitSid::Port.sid()), None);
    assert_eq!(t.search(InitSid::Port.sid()), Some(&ctx(1, 1, 2)));
}

#[test]
fn set_initial_rejects_reserved_numbers() {
    let mut t = Sidtab::new();
    assert_eq!(t.set_initial(SECSID_NULL, ctx(1, 1, 1)), Err(Error::UnknownSid));
    assert_eq!(t.set_initial(SECINITSID_NUM + 1, ctx(1, 1, 1)), Err(Error::UnknownSid));
    assert!(t.set_initial(SECINITSID_NUM, ctx(1, 1, 1)).is_ok());
}

#[test]
fn allocation_is_dense_and_starts_after_initial_sids() {
    let mut t = seeded();
    let a = t.context_to_sid(ctx(2, 2, 10)).unwrap();
    let b = t.context_to_sid(ctx(2, 2, 11)).unwrap();
    let c = t.context_to_sid(ctx(2, 2, 12)).unwrap();
    assert_eq!((a, b, c), (28, 29, 30));
    assert_eq!(FIRST_DYNAMIC_SID, 28);
    assert_eq!(t.count(), 3);
}

#[test]
fn equal_context_returns_same_sid() {
    let mut t = seeded();
    let a = t.context_to_sid(ctx_mls(2, 3, 4, 0, 5, &[1, 7])).unwrap();
    let b = t.context_to_sid(ctx_mls(2, 3, 4, 0, 5, &[1, 7])).unwrap();
    assert_eq!(a, b);
    assert_eq!(t.count(), 1);
}

#[test]
fn context_matching_an_initial_sid_resolves_to_that_initial_sid() {
    let mut t = seeded();
    assert_eq!(t.context_to_sid(ctx(1, 1, 3)).unwrap(), InitSid::File.sid());
    assert_eq!(t.count(), 0);
}

/// Reverse-index bucket a context falls in.
fn bucket_of(c: &Context) -> usize { (context_hash(c) as usize) & HASH_MASK }

/// A context from `make` that differs from `base` yet shares its bucket.
///
/// Sharing the bucket is what makes the four tests below real controls: a
/// varied context that merely hashes elsewhere would get its own SID even
/// under a comparison that ignores the field being varied, so it would prove
/// nothing about the comparison.
fn colliding<F: Fn(u32) -> Context>(base: &Context, make: F) -> Context {
    let want = bucket_of(base);
    for v in 0..100_000u32 {
        let c = make(v);
        if c != *base && bucket_of(&c) == want { return c; }
    }
    panic!("no context colliding with the base was found");
}

/// Both contexts must occupy distinct SIDs even though they share a bucket.
fn assert_distinct_sids(base: Context, other: Context) {
    assert_eq!(bucket_of(&base), bucket_of(&other));
    let mut t = seeded();
    let a = t.context_to_sid(base).unwrap();
    let b = t.context_to_sid(other).unwrap();
    assert_ne!(a, b);
    assert_eq!(t.count(), 2);
}

#[test]
fn differing_only_in_mls_high_level_gets_a_different_sid() {
    let base = ctx_mls(2, 3, 4, 0, 5, &[]);
    let other = colliding(&base, |v| ctx_mls(2, 3, 4, 0, v, &[]));
    assert_distinct_sids(base, other);
}

#[test]
fn differing_only_in_categories_gets_a_different_sid() {
    let base = ctx_mls(2, 3, 4, 0, 5, &[1]);
    let other = colliding(&base, |v| ctx_mls(2, 3, 4, 0, 5, &[1, v]));
    assert_distinct_sids(base, other);
}

#[test]
fn differing_only_in_role_gets_a_different_sid() {
    let base = ctx(2, 3, 4);
    let other = colliding(&base, |v| ctx(2, v, 4));
    assert_distinct_sids(base, other);
}

#[test]
fn differing_only_in_user_gets_a_different_sid() {
    let base = ctx(2, 3, 4);
    let other = colliding(&base, |v| ctx(v, 3, 4));
    assert_distinct_sids(base, other);
}

#[test]
fn unmapped_entry_keeps_its_sid_and_hides_from_search() {
    let mut t = seeded();
    let sid = t.context_to_sid(unmapped("sysadm_u:sysadm_r:gone_t")).unwrap();
    assert_eq!(t.context_to_sid(unmapped("sysadm_u:sysadm_r:gone_t")).unwrap(), sid);
    assert_eq!(t.lookup(sid), Some(&unmapped("sysadm_u:sysadm_r:gone_t")));
    // Invisible to the ordinary path, so callers see it as unlabeled...
    assert_eq!(t.search(sid), Some(&ctx(1, 1, 2)));
    // ...but retained verbatim, so a later policy can re-validate it.
    assert_eq!(t.search_force(sid), Some(&unmapped("sysadm_u:sysadm_r:gone_t")));
}

#[test]
fn unmapped_contexts_are_distinguished_by_their_string() {
    let mut t = seeded();
    let a = t.context_to_sid(unmapped("a:b:c")).unwrap();
    let b = t.context_to_sid(unmapped("a:b:d")).unwrap();
    assert_ne!(a, b);
}

#[test]
fn freeze_refuses_new_contexts_but_still_answers_lookups() {
    let mut t = seeded();
    let sid = t.context_to_sid(ctx(2, 3, 4)).unwrap();
    t.freeze();
    assert!(t.is_frozen());
    assert_eq!(t.context_to_sid(ctx(5, 6, 7)), Err(Error::Stale));
    assert_eq!(t.lookup(sid), Some(&ctx(2, 3, 4)));
    // A context already present needs no allocation, so it still resolves.
    assert_eq!(t.context_to_sid(ctx(2, 3, 4)).unwrap(), sid);
    assert_eq!(t.count(), 1);
}

#[test]
fn entries_are_ascending_and_gapless() {
    let mut t = seeded();
    for i in 0..64 { t.context_to_sid(ctx(2, 3, i)).unwrap(); }
    let got: Vec<Sid> = t.entries().map(|(s, _)| s).collect();
    let want: Vec<Sid> = (0..64).map(|i| FIRST_DYNAMIC_SID + i).collect();
    assert_eq!(got, want);
    for (sid, c) in t.entries() { assert_eq!(t.lookup(sid), Some(c)); }
}

#[test]
fn hash_stats_account_for_every_entry() {
    let mut t = Sidtab::new();
    for i in 0..300 { t.context_to_sid(ctx(2, 3, i)).unwrap(); }
    let st = t.hash_stats();
    assert_eq!(st.entries, t.count());
    assert_eq!(st.buckets, HASH_BUCKETS as u32);
    assert!(st.used_buckets > 0 && st.used_buckets <= st.buckets);
    assert!(st.longest_chain >= 1);
}

#[test]
fn many_distinct_contexts_all_round_trip() {
    const N: u32 = 5000;
    let mut t = seeded();
    let mut sids = Vec::new();
    for i in 0..N {
        let c = ctx_mls(i % 7, i % 11, i, 0, i % 5, &[i % 64, 100 + i % 3]);
        sids.push(t.context_to_sid(c).unwrap());
    }
    assert_eq!(t.count(), N);
    let mut sorted = sids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), N as usize, "SIDs must be distinct");
    for (i, sid) in sids.iter().enumerate() {
        let i = i as u32;
        let c = ctx_mls(i % 7, i % 11, i, 0, i % 5, &[i % 64, 100 + i % 3]);
        assert_eq!(t.lookup(*sid), Some(&c));
        assert_eq!(t.context_to_sid(c).unwrap(), *sid);
    }
    assert_eq!(t.count(), N, "re-insertion must not allocate");
    // The three initial SIDs share the reverse index with the dynamic ones.
    assert_eq!(t.hash_stats().entries, N + 3);
}

#[test]
fn unmapped_strings_of_every_length_hash_distinctly() {
    let mut t = Sidtab::new();
    let mut sids = Vec::new();
    for i in 0..512 { sids.push(t.context_to_sid(unmapped(&format!("u:r:t{i}"))).unwrap()); }
    sids.sort_unstable();
    sids.dedup();
    assert_eq!(sids.len(), 512);
}
