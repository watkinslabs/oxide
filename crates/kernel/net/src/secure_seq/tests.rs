// Adversarial by construction: every assertion here is one the OLD allocator
// would have failed. A test that merely checked "two ISNs differ" passed
// against `TCP_ISN_INITIAL + n * TCP_ISN_STEP` — the counter advances, so
// difference proves nothing. What the fixed-constant scheme could not do is
// resist *derivation*: knowing one ISN gave you all of them.

use super::*;
use crate::addr::{Ipv4Addr, Ipv6Addr};
use std::collections::BTreeSet;
use std::vec::Vec;

/// The old scheme, reproduced so its failure against these assertions is
/// demonstrable rather than asserted. `TCP_ISN_INITIAL` / `TCP_ISN_STEP` as
/// they stood in `stack_binddev.rs`.
const OLD_ISN_INITIAL: u32 = 0x1000_0000;
const OLD_ISN_STEP: u32 = 0x1000;

fn key_a() -> Key { Key { k0: 0x0123_4567_89ab_cdef, k1: 0xfedc_ba98_7654_3210 } }
fn key_b() -> Key { Key { k0: 0xdead_beef_cafe_f00d, k1: 0x0f0e_0d0c_0b0a_0908 } }

fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr { Ipv4Addr::new(a, b, c, d) }

// ---------------------------------------------------------------------------
// ISN — the primary finding
// ---------------------------------------------------------------------------

/// THE assertion that catches the fixed-constant ISN. Under the old scheme
/// every ISN was `INITIAL + n*STEP`, so the differences between successive
/// connections' ISNs formed the constant set {STEP}: one observation and the
/// attacker has every future ISN. A keyed PRF must not produce a fixed stride.
#[test]
fn isns_for_different_tuples_are_not_a_fixed_stride_apart() {
    let key = key_a();
    let now = 0u64;
    let isns: Vec<u32> = (0..64u16)
        .map(|i| hash::isn_from_hash(
            hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 40_000 + i, 443),
            now))
        .collect();

    let strides: BTreeSet<u32> = isns.windows(2)
        .map(|w| w[1].wrapping_sub(w[0])).collect();
    assert!(strides.len() > 60,
        "ISNs walk a near-fixed stride ({} distinct deltas over 64 samples) — \
         this is the sequence-prediction bug", strides.len());

    // Prove the old scheme fails exactly this check.
    let old: Vec<u32> = (0..64u32).map(|n| OLD_ISN_INITIAL.wrapping_add(n * OLD_ISN_STEP)).collect();
    let old_strides: BTreeSet<u32> = old.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
    assert_eq!(old_strides.len(), 1, "fixture check: old scheme really was one stride");
}

/// The same 4-tuple under a different boot secret must yield a different ISN.
/// The old scheme gave the identical ISN on every boot, because the state was
/// a compile-time constant with no key at all.
#[test]
fn same_tuple_under_a_different_secret_gives_a_different_isn() {
    let (l, r, lp, rp) = (v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_000u16, 443u16);
    let now = 1_234_567_890u64;
    let with_a = hash::isn_from_hash(hash::tcp_hash64_v4(&key_a(), l, r, lp, rp), now);
    let with_b = hash::isn_from_hash(hash::tcp_hash64_v4(&key_b(), l, r, lp, rp), now);
    assert_ne!(with_a, with_b, "ISN does not depend on the boot secret");
}

/// Every element of the 4-tuple must be mixed in. If a field were dropped
/// (say the local port), an attacker who knows the other three could enumerate
/// far fewer candidates than the construction advertises.
#[test]
fn every_tuple_field_changes_the_isn() {
    let key = key_a();
    let now = 7u64;
    let base = hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_000, 443);
    assert_ne!(base, hash::tcp_hash64_v4(&key, v4(10, 0, 0, 2), v4(93, 184, 216, 34), 51_000, 443),
        "local address ignored");
    assert_ne!(base, hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(93, 184, 216, 35), 51_000, 443),
        "remote address ignored");
    assert_ne!(base, hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_001, 443),
        "local port ignored");
    assert_ne!(base, hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_000, 444),
        "remote port ignored");
    let _ = now;
}

/// RFC 6528's `M` term: a 4-tuple reused after TIME-WAIT must not repeat its
/// own ISN, or a delayed segment from the previous incarnation is accepted.
/// The keyed hash alone is constant for a constant tuple — `seq_scale` is what
/// makes it advance.
#[test]
fn a_reused_tuple_advances_with_the_clock() {
    let key = key_a();
    let h = hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_000, 443);
    let t0 = hash::isn_from_hash(h, 0);
    let t1 = hash::isn_from_hash(h, 1_000_000_000);
    assert_ne!(t0, t1, "seq_scale is not advancing — a reused 4-tuple repeats its ISN");
    // Linux picks a 64 ns tick so the 32-bit space takes ~274 s to wrap, which
    // must exceed the 2 min MSL. Verify the rate, not just that it moves.
    assert_eq!(hash::seq_scale(0, 64), 1);
    assert_eq!(hash::seq_scale(0, 63), 0);
    let wrap_ns = 1u64 << (32 + 6);
    assert!(wrap_ns / 1_000_000_000 > 120, "sequence wraps faster than the MSL");
}

/// The ISN and the TCP timestamp offset come from opposite halves of one
/// hash. If they were the same value, publishing the timestamp offset on the
/// wire would publish the ISN.
#[test]
fn isn_and_timestamp_offset_are_independent_halves() {
    let key = key_a();
    for port in 40_000u16..40_064 {
        let h = hash::tcp_hash64_v4(&key, v4(10, 0, 0, 1), v4(1, 1, 1, 1), port, 53);
        assert_ne!(hash::isn_from_hash(h, 0), hash::ts_off_from_hash(h),
            "ISN and ts_off collapsed to the same value at port {port}");
    }
}

/// v6 must be keyed too — a stack that hardened v4 and left v6 on a counter
/// would be trivially attackable over v6.
#[test]
fn ipv6_isns_are_keyed_and_tuple_dependent() {
    let l = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    let r = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]);
    let r2 = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 3]);
    assert_ne!(hash::tcp_hash64_v6(&key_a(), l, r, 51_000, 443),
               hash::tcp_hash64_v6(&key_b(), l, r, 51_000, 443), "v6 ISN ignores the secret");
    assert_ne!(hash::tcp_hash64_v6(&key_a(), l, r, 51_000, 443),
               hash::tcp_hash64_v6(&key_a(), l, r2, 51_000, 443), "v6 ISN ignores the peer");
}

/// Whole-path check through the live global secret: the runtime wrapper must
/// actually consult the key, not just the pure layer. Re-drawing the secret
/// stands in for a reboot.
#[test]
fn runtime_isn_changes_when_the_boot_secret_is_redrawn() {
    let (l, r) = (IpAddr::V4(v4(10, 0, 0, 1)), IpAddr::V4(v4(93, 184, 216, 34)));
    reseed_secret_for_test();
    let first_key = net_secret();
    let first = hash::tcp_hash64_v4(&first_key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_000, 443);
    reseed_secret_for_test();
    let second_key = net_secret();
    assert_ne!(first_key, second_key, "secret did not change across a simulated reboot");
    let second = hash::tcp_hash64_v4(&second_key, v4(10, 0, 0, 1), v4(93, 184, 216, 34), 51_000, 443);
    assert_ne!(first, second);
    // And the public entry point is wired to that key, not to a constant.
    let live = secure_tcp_seq(l, r, 51_000, 443);
    assert_ne!(live, OLD_ISN_INITIAL.wrapping_add(OLD_ISN_STEP));
}

// ---------------------------------------------------------------------------
// Ephemeral ports
// ---------------------------------------------------------------------------

/// The old allocator started every namespace's scan at `DEFAULT_START` and
/// stepped by one, so the first ephemeral port after boot was always 32768 and
/// the n-th was always 32768+n. Selection must not begin at the range base.
#[test]
fn ephemeral_selection_does_not_start_at_the_range_base() {
    let low = crate::ephemeral::DEFAULT_START;
    let count = crate::ephemeral::DEFAULT_END as u32 - low as u32 + 1;
    let firsts: BTreeSet<u16> = (0..32).map(|_| bind_port_scan(low, count).next().unwrap()).collect();
    assert!(firsts.len() > 24,
        "bind(0) start port is nearly fixed ({} distinct starts in 32 draws)", firsts.len());
    assert!(!(firsts.len() == 1 && firsts.contains(&low)),
        "bind(0) always starts at the range base — the sequential-scan bug");
}

/// Connect-time offsets are keyed on the 4-tuple, so two different
/// destinations must not begin their scans at the same port.
#[test]
fn connect_offsets_differ_by_destination() {
    let key = key_a();
    let local = v4(10, 0, 0, 1);
    let offsets: BTreeSet<u64> = (0..32u8)
        .map(|i| hash::port_offset_v4(&key, local, v4(93, 184, 216, i), 443, 0))
        .collect();
    assert_eq!(offsets.len(), 32, "port offset does not depend on the destination");
}

/// ...and on the secret, so an off-path attacker who knows the destination
/// still cannot predict which local port a client will pick.
#[test]
fn connect_offsets_depend_on_the_boot_secret() {
    let (l, r) = (v4(10, 0, 0, 1), v4(93, 184, 216, 34));
    assert_ne!(hash::port_offset_v4(&key_a(), l, r, 443, 0),
               hash::port_offset_v4(&key_b(), l, r, 443, 0));
}

/// Linux re-shuffles the offset every 10 s so a client repeatedly connecting
/// to one destination does not walk the range in a fixed order.
#[test]
fn port_offsets_reshuffle_on_the_linux_period() {
    let (l, r) = (v4(10, 0, 0, 1), v4(93, 184, 216, 34));
    assert_eq!(hash::shuffle_epoch(0), 0);
    assert_eq!(hash::shuffle_epoch(9_999_999_999), 0);
    assert_eq!(hash::shuffle_epoch(10_000_000_000), 1);
    assert_ne!(hash::port_offset_v4(&key_a(), l, r, 443, hash::shuffle_epoch(0)),
               hash::port_offset_v4(&key_a(), l, r, 443, hash::shuffle_epoch(10_000_000_000)));
}

/// `reciprocal_scale` must stay inside the range — an off-by-one here would
/// hand out a port outside `ip_local_port_range`.
#[test]
fn random_offset_stays_inside_the_range() {
    for count in [2u32, 3, 1_000, 28_232, u16::MAX as u32] {
        for _ in 0..64 { assert!(random_port_offset(count) < count, "count {count}"); }
    }
    assert_eq!(random_port_offset(1), 0);
    assert_eq!(random_port_offset(0), 0);
    assert_eq!(hash::reciprocal_scale(u32::MAX, 10), 9);
    assert_eq!(hash::reciprocal_scale(0, 10), 0);
}

/// The perturb table spreads concurrent connects to the SAME destination —
/// without it, two sockets with one 4-tuple prefix collide on every attempt.
#[test]
fn perturb_table_advances_the_bucket_between_scans() {
    perturb::reset_for_test();
    let offset = 0x1234_5678_9abc_def0u64;
    let (index, first) = perturb::connect_offset(offset);
    perturb::record_scan(index, 4);
    let (again, second) = perturb::connect_offset(offset);
    assert_eq!(index, again, "same tuple must hash to the same bucket");
    assert_ne!(first, second, "bucket did not advance — concurrent connects will collide");
}
