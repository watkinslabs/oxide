// Hosted proof of the `capget`/`capset` admission policy against Linux's
// own capability and commoncap logic.

use super::*;

const SETPCAP: u64 = 1 << 8;
const NET_RAW: u64 = 1 << 13;
const SYS_ADMIN: u64 = 1 << 21;

fn old(effective: u64, permitted: u64, inheritable: u64, bounding: u64) -> CapsetOld {
    CapsetOld { effective, permitted, inheritable, bounding, ambient: 0 }
}

/// libcap's opening move is `capget(&hdr, NULL)` with whatever magic it was
/// built against. Linux answers 0 and rewrites the header to the version it
/// speaks. We answered EINVAL, so the probe failed at the first call — and
/// this runs on every service spawn at the CAPABILITIES step.
#[test]
fn null_dataptr_probe_with_bad_magic_succeeds() {
    assert_eq!(capget_early(0xdead_beef, 0), CapgetEarly::RewriteVersion(0));
}

/// The same bad magic WITH a real data pointer is a genuine request and
/// must still fail — the header is rewritten either way.
#[test]
fn bad_magic_with_dataptr_is_einval() {
    assert_eq!(
        capget_early(0xdead_beef, 0x1000),
        CapgetEarly::RewriteVersion(-(Errno::Einval.as_i32() as i64))
    );
}

/// A NULL dataptr returns BEFORE `cap_get_target_pid`, so the pid in the
/// header is never resolved. Loading the target first made a probe that
/// named a dead pid fail with ESRCH.
#[test]
fn null_dataptr_never_consults_the_target() {
    for ver in [CAPV1, CAPV2, CAPV3] {
        assert_eq!(capget_early(ver, 0), CapgetEarly::Ok);
    }
}

/// v1 carries one 32-bit block; v2 and v3 carry two (v3 is otherwise
/// identical to v2 — Linux falls through between them).
#[test]
fn block_counts_match_linux_versions() {
    assert_eq!(capget_early(CAPV1, 0x1000), CapgetEarly::Proceed(1));
    assert_eq!(capget_early(CAPV2, 0x1000), CapgetEarly::Proceed(2));
    assert_eq!(capget_early(CAPV3, 0x1000), CapgetEarly::Proceed(2));
}

/// `CAP_LAST_CAP` is `CAP_CHECKPOINT_RESTORE`; the mask must cover exactly
/// bits 0..=40 and nothing above.
#[test]
fn valid_mask_covers_cap_last_cap_and_no_more() {
    assert_eq!(CAP_LAST_CAP, crate::cap::CHECKPOINT_RESTORE);
    assert_eq!(SETPCAP_BIT, crate::cap::SETPCAP);
    assert_eq!(CAP_VALID_MASK, 0x0000_01ff_ffff_ffff);
    assert_eq!(CAP_VALID_MASK & (1 << CAP_LAST_CAP), 1 << CAP_LAST_CAP);
    assert_eq!(CAP_VALID_MASK & (1 << (CAP_LAST_CAP + 1)), 0);
}

/// Linux `mk_kernel_cap` masks the incoming u32 pair with `CAP_VALID_MASK`
/// BEFORE any subset test. A full-capability root task writing `~0` into all
/// three sets therefore succeeds; we used to compare the unmasked value
/// against `old->permitted` and hand back EPERM.
#[test]
fn undefined_high_bits_are_masked_not_rejected() {
    let o = old(CAP_VALID_MASK, CAP_VALID_MASK, 0, CAP_VALID_MASK);
    let n = capset_check(o, u64::MAX, u64::MAX, u64::MAX).expect("root may set every valid cap");
    assert_eq!(n.permitted, CAP_VALID_MASK);
    assert_eq!(n.effective, CAP_VALID_MASK);
    assert_eq!(n.inheritable, CAP_VALID_MASK);
}

/// New permitted must be a subset of OLD permitted — capabilities can only be
/// dropped, never conjured.
#[test]
fn raising_permitted_beyond_old_permitted_is_eperm() {
    let o = old(NET_RAW, NET_RAW, 0, CAP_VALID_MASK);
    assert_eq!(capset_check(o, 0, NET_RAW | SYS_ADMIN, 0), Err(Errno::Eperm));
    assert!(capset_check(o, 0, NET_RAW, 0).is_ok());
}

/// New effective must be a subset of the NEW permitted set, not the old one.
#[test]
fn effective_must_be_subset_of_new_permitted() {
    let o = old(NET_RAW | SYS_ADMIN, NET_RAW | SYS_ADMIN, 0, CAP_VALID_MASK);
    assert_eq!(capset_check(o, SYS_ADMIN, NET_RAW, 0), Err(Errno::Eperm));
    assert!(capset_check(o, NET_RAW, NET_RAW, 0).is_ok());
}

/// Without `CAP_SETPCAP` in effect, `cap_inh_is_capped()` is true and a new
/// inheritable bit must already be in `old->I | old->P`.
#[test]
fn without_setpcap_inheritable_is_capped_by_old_permitted() {
    let o = old(NET_RAW, NET_RAW, 0, CAP_VALID_MASK);
    assert_eq!(capset_check(o, 0, NET_RAW, SYS_ADMIN), Err(Errno::Eperm));
    assert!(capset_check(o, 0, NET_RAW, NET_RAW).is_ok());
}

/// With `CAP_SETPCAP` in EFFECT, Linux skips the `old->I | old->P` test
/// entirely: such a task may raise any inheritable bit that is still in the
/// bounding set, even one it does not hold permitted. We enforced the capped
/// rule unconditionally and refused it.
#[test]
fn setpcap_lifts_the_inheritable_cap() {
    let o = old(SETPCAP, SETPCAP, 0, CAP_VALID_MASK);
    assert!(capset_check(o, 0, SETPCAP, SYS_ADMIN).is_ok(),
        "CAP_SETPCAP holder may raise pI outside old pP");
    // ...but never outside the bounding set.
    let capped = old(SETPCAP, SETPCAP, 0, CAP_VALID_MASK & !SYS_ADMIN);
    assert_eq!(capset_check(capped, 0, SETPCAP, SYS_ADMIN), Err(Errno::Eperm));
}

/// The bounding test is `I ⊆ old->I | old->bset`, NOT `I ⊆ (…) & bset`. An
/// inheritable bit the task ALREADY holds survives a later
/// `PR_CAPBSET_DROP` of that bit, so a capget/modify/capset round-trip after
/// a bounding-set drop still works. Intersecting with the bounding set made
/// that round-trip EPERM.
#[test]
fn inheritable_already_held_survives_a_bounding_set_drop() {
    let o = old(NET_RAW, NET_RAW, NET_RAW, CAP_VALID_MASK & !NET_RAW);
    assert!(capset_check(o, 0, NET_RAW, NET_RAW).is_ok(),
        "already-inheritable bit outside the bounding set must be retainable");
}

/// A bit in neither `old->I` nor the bounding set is refused even though it
/// IS in `old->P` — the second test has no `CAP_SETPCAP` escape.
#[test]
fn inheritable_outside_bounding_set_is_eperm_even_when_permitted() {
    let o = old(NET_RAW, NET_RAW, 0, CAP_VALID_MASK & !NET_RAW);
    assert_eq!(capset_check(o, 0, NET_RAW, NET_RAW), Err(Errno::Eperm));
}

/// Ambient bits that stop being both permitted and inheritable are dropped
/// (`cap_intersect(ambient, cap_intersect(P, I))`).
#[test]
fn ambient_is_masked_to_new_permitted_and_inheritable() {
    let mut o = old(NET_RAW | SYS_ADMIN, NET_RAW | SYS_ADMIN, NET_RAW | SYS_ADMIN, CAP_VALID_MASK);
    o.ambient = NET_RAW | SYS_ADMIN;
    let n = capset_check(o, 0, NET_RAW, NET_RAW).expect("dropping to pP=pI=NET_RAW is allowed");
    assert_eq!(n.ambient, NET_RAW);
}
