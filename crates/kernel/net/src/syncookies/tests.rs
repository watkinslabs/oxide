// The contract a SYN cookie has to keep, asserted against the pure layer so
// none of it needs a kernel, a listener or a boot.

use super::cookie::{self, Secret, COOKIEMASK, MAX_SYNCOOKIE_AGE, MSSTAB_V4, MSSTAB_V6};
use super::decide::{self, Admit, ALWAYS, NEVER, OFF, SYNCOOKIE_PERIOD_NS,
    SYNCOOKIE_VALID_NS, WHEN_FULL};
use super::tsopt::{self, Permitted, TS_OPT_ECN, TS_OPT_SACK, TS_OPT_WSCALE_MASK};
use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};

fn secret() -> Secret {
    Secret::from_bytes(&[
        0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15, 0xf3, 0x9c, 0xc0, 0x60, 0x5c, 0xed, 0xc8, 0x34,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01,
    ])
}

fn other_secret() -> Secret {
    Secret::from_bytes(&[0x5a; 32])
}

const SRC: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const DST: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
const SPORT: u16 = 45_123;
const DPORT: u16 = 443;
const SYN_SEQ: u32 = 0xdead_0000;

/// The cookie a SYN produces, and the acknowledgement fields the peer would
/// return for it: it acknowledges the cookie, and its own sequence has
/// advanced past the SYN.
fn round_trip(mss: u16, count: u32) -> (u32, u16, u32, u32) {
    let (cookie, encoded) = cookie::init_sequence(
        &secret(), SRC, DST, SPORT, DPORT, SYN_SEQ, count, false, mss);
    (cookie, encoded, SYN_SEQ.wrapping_add(1), cookie.wrapping_add(1))
}

#[test]
fn a_minted_cookie_returns_the_mss_it_encoded() {
    // The whole point: no request was stored, so the acknowledgement alone has
    // to say what segment size the peer announced.
    for mss in [536u16, 600, 1300, 1400, 1440, 1460, 9000] {
        let (_, encoded, seq, ack) = round_trip(mss, 100);
        assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT, seq, ack, 100, false),
                   Some(encoded), "mss {mss}");
    }
}

#[test]
fn the_encoded_mss_never_exceeds_what_the_peer_announced() {
    // Rounding UP would make the connection send segments the peer said it
    // would not accept.
    for mss in 500u16..=1600 {
        let (_, encoded, _, _) = round_trip(mss, 7);
        assert!(encoded <= mss.max(MSSTAB_V4[0]), "mss {mss} encoded {encoded}");
    }
}

#[test]
fn an_mss_below_the_floor_takes_the_floor() {
    let (_, encoded, _, _) = round_trip(200, 7);
    assert_eq!(encoded, MSSTAB_V4[0]);
}

#[test]
fn every_table_entry_round_trips_to_itself() {
    for (family, tab) in [(false, &MSSTAB_V4), (true, &MSSTAB_V6)] {
        for &entry in tab.iter() {
            let (cookie, encoded) = cookie::init_sequence(
                &secret(), SRC, DST, SPORT, DPORT, SYN_SEQ, 3, family, entry);
            assert_eq!(encoded, entry);
            assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT,
                                        SYN_SEQ.wrapping_add(1), cookie.wrapping_add(1),
                                        3, family), Some(entry));
        }
    }
}

#[test]
fn a_tampered_cookie_is_rejected() {
    // POSITIVE CONTROL for this test lives in the module comment of
    // `syncookies::cookie::check`: weakening the check to skip the second hash
    // term (returning `stripped & COOKIEMASK`) makes this assertion fail for
    // the flipped-bit cases, which is what proves the assertion is load
    // bearing rather than vacuous.
    let (cookie, _, seq, _) = round_trip(1460, 42);
    let mut rejected = 0;
    let mut accepted_wrong = 0;
    for bit in 0..32 {
        let forged = (cookie ^ (1 << bit)).wrapping_add(1);
        match cookie::validate(&secret(), SRC, DST, SPORT, DPORT, seq, forged, 42, false) {
            None => rejected += 1,
            Some(_) => accepted_wrong += 1,
        }
    }
    // Flipping a bit inside the eight-bit counter field can land on a counter
    // that is still inside the two-minute window, and the 24-bit payload can
    // then decode into the four-entry table by chance. Everything else must
    // be refused outright.
    assert!(rejected >= 28, "only {rejected} of 32 single-bit forgeries refused");
    assert!(accepted_wrong <= 4, "{accepted_wrong} single-bit forgeries accepted");
}

#[test]
fn a_cookie_minted_for_another_tuple_is_rejected() {
    let (_, _, seq, ack) = round_trip(1460, 9);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
    assert_eq!(cookie::validate(&secret(), elsewhere, DST, SPORT, DPORT, seq, ack, 9, false), None);
    assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT + 1, DPORT, seq, ack, 9, false), None);
    assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT + 1, seq, ack, 9, false), None);
}

#[test]
fn a_cookie_replayed_with_another_peer_sequence_is_rejected() {
    let (_, _, _, ack) = round_trip(1460, 9);
    assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT,
                                SYN_SEQ.wrapping_add(99), ack, 9, false), None);
}

#[test]
fn another_hosts_secret_does_not_validate() {
    let (_, _, seq, ack) = round_trip(1460, 9);
    assert_eq!(cookie::validate(&other_secret(), SRC, DST, SPORT, DPORT, seq, ack, 9, false), None);
}

#[test]
fn a_cookie_expires_once_the_counter_has_moved_far_enough() {
    let (_, encoded, seq, ack) = round_trip(1460, 1_000);
    // Inside the window it still validates; the counter it was minted under is
    // recovered from the cookie itself.
    for age in 0..MAX_SYNCOOKIE_AGE {
        assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT, seq, ack,
                                    1_000 + age, false), Some(encoded), "age {age}");
    }
    // At the age limit the cookie is refused however well it hashes.
    for age in MAX_SYNCOOKIE_AGE..8 {
        assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT, seq, ack,
                                    1_000 + age, false), None, "age {age}");
    }
}

#[test]
fn a_cookie_from_the_future_is_rejected() {
    // A counter that has not been reached yet cannot have minted anything.
    let (_, _, seq, ack) = round_trip(1460, 1_000);
    assert_eq!(cookie::validate(&secret(), SRC, DST, SPORT, DPORT, seq, ack, 999, false), None);
}

#[test]
fn ipv6_cookies_are_not_ipv4_cookies() {
    // The two families keep separate tables and separate hash records, so an
    // index minted under one must not decode under the other.
    let src6 = IpAddr::V6(Ipv6Addr::from_v4_mapped(Ipv4Addr::new(198, 51, 100, 7)));
    let dst6 = IpAddr::V6(Ipv6Addr::from_v4_mapped(Ipv4Addr::new(203, 0, 113, 9)));
    let (cookie6, encoded6) = cookie::init_sequence(
        &secret(), src6, dst6, SPORT, DPORT, SYN_SEQ, 5, true, 1440);
    assert_eq!(encoded6, 1440);
    assert_eq!(cookie::validate(&secret(), src6, dst6, SPORT, DPORT,
                                SYN_SEQ.wrapping_add(1), cookie6.wrapping_add(1), 5, true),
               Some(encoded6));
    // The v4 record over the same numbers is a different hash entirely.
    assert_ne!(cookie6, cookie::init_sequence(
        &secret(), SRC, DST, SPORT, DPORT, SYN_SEQ, 5, false, 1440).0);
}

#[test]
fn the_payload_is_concealed_by_the_second_key() {
    // Without the second hash the low 24 bits would be the index plus a term
    // an observer already knows, so anyone could mint a cookie.
    let s = secret();
    let a = cookie::mint(&s, SRC, DST, SPORT, DPORT, SYN_SEQ, 11, 0);
    let b = cookie::mint(&s, SRC, DST, SPORT, DPORT, SYN_SEQ, 11, 1);
    assert_eq!(b.wrapping_sub(a) & COOKIEMASK, 1);
    // ... but neither low half is the index itself.
    assert_ne!(a & COOKIEMASK, 0);
}

#[test]
fn the_sysctl_has_three_states_not_two() {
    // 0 refuses rather than falling back; 1 falls back only once full; 2 never
    // consults the queue at all.
    assert_eq!(decide::admit(OFF, false), Admit::Queue);
    assert_eq!(decide::admit(OFF, true), Admit::Drop);
    assert_eq!(decide::admit(WHEN_FULL, false), Admit::Queue);
    assert_eq!(decide::admit(WHEN_FULL, true), Admit::Cookie);
    assert_eq!(decide::admit(ALWAYS, false), Admit::Cookie);
    assert_eq!(decide::admit(ALWAYS, true), Admit::Cookie);
}

#[test]
fn the_minute_counter_advances_once_a_minute() {
    assert_eq!(decide::cookie_time(0), 0);
    assert_eq!(decide::cookie_time(SYNCOOKIE_PERIOD_NS - 1), 0);
    assert_eq!(decide::cookie_time(SYNCOOKIE_PERIOD_NS), 1);
    assert_eq!(decide::cookie_time(SYNCOOKIE_PERIOD_NS * 121), 121);
}

#[test]
fn a_listener_that_never_overflowed_believes_no_cookie() {
    // Otherwise every listener in the system would hash every stray
    // acknowledgement, and hand an off-path attacker an unlimited oracle.
    assert!(decide::no_recent_overflow(NEVER, 0));
    assert!(decide::no_recent_overflow(NEVER, u64::MAX / 2));
}

#[test]
fn the_overflow_window_closes_after_two_minutes() {
    let stamped = 500 * SYNCOOKIE_PERIOD_NS;
    assert!(!decide::no_recent_overflow(stamped, stamped));
    assert!(!decide::no_recent_overflow(stamped, stamped + SYNCOOKIE_VALID_NS));
    assert!(decide::no_recent_overflow(stamped, stamped + SYNCOOKIE_VALID_NS + 1));
    // Slack on the low edge: a concurrent overflow may stamp after the clock
    // was read, and refusing a valid cookie over that race is the worse error.
    assert!(!decide::no_recent_overflow(stamped, stamped - 1));
}

#[test]
fn the_overflow_stamp_is_rewritten_at_most_once_a_second() {
    assert!(decide::restamp_overflow(NEVER, 0));
    assert!(!decide::restamp_overflow(1_000, 1_001));
    assert!(!decide::restamp_overflow(1_000, 1_000_000_999));
    assert!(decide::restamp_overflow(1_000, 1_000_001_001));
}

#[test]
fn the_timestamp_carries_the_options_the_cookie_cannot() {
    let ts = tsopt::init_timestamp(0x1234_5678, Some(7), true, true);
    let decoded = tsopt::decode(true, ts, Permitted::ALL).expect("permitted");
    assert_eq!(decoded.wscale, Some(7));
    assert!(decoded.sack_ok);
    assert!(decoded.ecn_ok);
    assert!(decoded.tstamp_ok);
}

#[test]
fn every_option_combination_survives_the_echo() {
    for wscale in [None, Some(0), Some(1), Some(7), Some(14)] {
        for sack in [false, true] {
            for ecn in [false, true] {
                let ts = tsopt::init_timestamp(0x0102_0304, wscale, sack, ecn);
                let decoded = tsopt::decode(true, ts, Permitted::ALL).expect("permitted");
                assert_eq!(decoded.wscale, wscale, "{wscale:?} {sack} {ecn}");
                assert_eq!(decoded.sack_ok, sack);
                assert_eq!(decoded.ecn_ok, ecn);
            }
        }
    }
}

#[test]
fn an_absent_window_scale_is_the_illegal_scale() {
    // 15 is not a legal scale, which is what makes it usable as the sentinel.
    let ts = tsopt::init_timestamp(0x0102_0304, None, false, false);
    assert_eq!(ts & TS_OPT_WSCALE_MASK, TS_OPT_WSCALE_MASK);
    assert_eq!(ts & TS_OPT_SACK, 0);
    assert_eq!(ts & TS_OPT_ECN, 0);
}

#[test]
fn the_cookie_timestamp_never_runs_ahead_of_the_clock() {
    // The connection's later timestamps come from the ordinary clock, so one
    // built ahead of it would appear to go backwards. The clock is a wrapping
    // 32-bit millisecond counter, so "not ahead" is the modular statement: the
    // value sits within one option tick BEHIND the clock.
    for now in [0u32, 1, 63, 64, 65, 0x1000_003f, 0xffff_ffff] {
        for wscale in [None, Some(0), Some(14)] {
            let ts = tsopt::init_timestamp(now, wscale, true, true);
            assert!(now.wrapping_sub(ts) < (1 << tsopt::TSBITS), "now {now:#x} ts {ts:#x}");
        }
    }
}

#[test]
fn an_acknowledgement_without_a_timestamp_negotiates_nothing() {
    let decoded = tsopt::decode(false, 0xffff_ffff, Permitted::ALL).expect("no options");
    assert_eq!(decoded, tsopt::Decoded::default());
    assert!(decoded.wscale.is_none());
    assert!(!decoded.sack_ok);
}

#[test]
fn an_option_the_host_forbids_refuses_the_whole_acknowledgement() {
    let ts = tsopt::init_timestamp(0x0102_0304, Some(7), true, false);
    assert!(tsopt::decode(true, ts, Permitted { timestamps: false, ..Permitted::ALL }).is_none());
    assert!(tsopt::decode(true, ts, Permitted { sack: false, ..Permitted::ALL }).is_none());
    assert!(tsopt::decode(true, ts, Permitted { window_scaling: false, ..Permitted::ALL }).is_none());
    // One with no window scaling offered is unaffected by the scaling knob.
    let none = tsopt::init_timestamp(0x0102_0304, None, false, false);
    assert!(tsopt::decode(true, none, Permitted { window_scaling: false, ..Permitted::ALL }).is_some());
}
