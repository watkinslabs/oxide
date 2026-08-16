//! The security decision: a channel asking for more than its link provides is
//! never admitted, at any level and with any key.

use super::*;
use crate::hci::conn::{Conn, PeerId};
use crate::uapi::bt::{BdAddr, BDADDR_LE_PUBLIC, BT_SECURITY_HIGH, BT_SECURITY_MEDIUM, BT_SECURITY_SDP};

fn link(level: u8, encrypted: bool, key: u8) -> LinkSecurity {
    LinkSecurity { level, encrypted, authenticated: level >= BT_SECURITY_HIGH, enc_key_size: key }
}

#[test]
fn a_link_at_or_above_the_required_level_is_sufficient() {
    for required in [BT_SECURITY_SDP, BT_SECURITY_LOW, BT_SECURITY_MEDIUM, BT_SECURITY_HIGH, BT_SECURITY_FIPS] {
        for provided in [BT_SECURITY_SDP, BT_SECURITY_LOW, BT_SECURITY_MEDIUM, BT_SECURITY_HIGH, BT_SECURITY_FIPS] {
            let expect = required <= BT_SECURITY_LOW || provided >= required;
            assert_eq!(level_sufficient(required, provided), expect,
                       "required {required} provided {provided}");
        }
    }
}

#[test]
fn a_channel_asking_for_more_than_the_link_provides_is_not_admitted() {
    let l = link(BT_SECURITY_MEDIUM, true, u::MIN_ENC_KEY_SIZE);
    assert_eq!(admissible(BT_SECURITY_MEDIUM, &l), Verdict::Sufficient);
    assert_eq!(admissible(BT_SECURITY_HIGH, &l), Verdict::Insufficient);
    assert_eq!(admissible(BT_SECURITY_FIPS, &l), Verdict::Insufficient);
}

#[test]
fn an_unpaired_link_admits_only_the_levels_that_ask_for_nothing() {
    let l = link(BT_SECURITY_LOW, false, 0);
    assert_eq!(admissible(BT_SECURITY_SDP, &l), Verdict::Sufficient);
    assert_eq!(admissible(BT_SECURITY_LOW, &l), Verdict::Sufficient);
    assert_eq!(admissible(BT_SECURITY_MEDIUM, &l), Verdict::Insufficient);
    assert_eq!(admissible(BT_SECURITY_HIGH, &l), Verdict::Insufficient);
}

#[test]
fn a_short_key_is_refused_even_when_the_level_matches() {
    let l = link(BT_SECURITY_MEDIUM, true, u::MIN_ENC_KEY_SIZE - 1);
    assert_eq!(admissible(BT_SECURITY_MEDIUM, &l), Verdict::KeySizeTooSmall);
    let ok = link(BT_SECURITY_MEDIUM, true, u::MIN_ENC_KEY_SIZE);
    assert_eq!(admissible(BT_SECURITY_MEDIUM, &ok), Verdict::Sufficient);
}

#[test]
fn the_highest_level_requires_a_full_width_key() {
    assert_eq!(min_key_size(BT_SECURITY_FIPS), u::FIPS_ENC_KEY_SIZE);
    assert_eq!(min_key_size(BT_SECURITY_HIGH), u::MIN_ENC_KEY_SIZE);
    let l = link(BT_SECURITY_FIPS, true, u::FIPS_ENC_KEY_SIZE - 1);
    assert_eq!(admissible(BT_SECURITY_FIPS, &l), Verdict::KeySizeTooSmall);
    let ok = link(BT_SECURITY_FIPS, true, u::FIPS_ENC_KEY_SIZE);
    assert_eq!(admissible(BT_SECURITY_FIPS, &ok), Verdict::Sufficient);
}

#[test]
fn a_link_with_no_encryption_has_no_key_size_to_check() {
    let l = link(BT_SECURITY_LOW, false, 0);
    assert!(key_size_sufficient(BT_SECURITY_LOW, &l));
    assert!(key_size_sufficient(BT_SECURITY_FIPS, &l));
}

#[test]
fn the_level_shortfall_is_reported_as_the_thing_that_is_missing() {
    assert_eq!(le_refusal_result(Verdict::Insufficient, BT_SECURITY_MEDIUM), u::CR_LE_ENCRYPTION);
    assert_eq!(le_refusal_result(Verdict::Insufficient, BT_SECURITY_HIGH), u::CR_LE_AUTHENTICATION);
    assert_eq!(le_refusal_result(Verdict::Insufficient, BT_SECURITY_FIPS), u::CR_LE_AUTHENTICATION);
    assert_eq!(le_refusal_result(Verdict::KeySizeTooSmall, BT_SECURITY_HIGH), u::CR_LE_BAD_KEY_SIZE);
    assert_eq!(le_refusal_result(Verdict::Sufficient, BT_SECURITY_HIGH), u::CR_LE_SUCCESS);
    assert_eq!(bredr_refusal_result(Verdict::Insufficient), u::CR_SEC_BLOCK);
    assert_eq!(bredr_refusal_result(Verdict::KeySizeTooSmall), u::CR_SEC_BLOCK);
    assert_eq!(bredr_refusal_result(Verdict::Sufficient), u::CR_SUCCESS);
}

#[test]
fn the_security_a_tracked_link_provides_is_read_off_the_link() {
    let mut conn = Conn::new(0x0010, PeerId::new(BdAddr([1, 2, 3, 4, 5, 6]), BDADDR_LE_PUBLIC),
                             crate::uapi::hci::LE_LINK, true);
    conn.sec_level = BT_SECURITY_HIGH;
    conn.encrypted = true;
    conn.enc_key_size = u::FIPS_ENC_KEY_SIZE;
    let l = LinkSecurity::from_conn(&conn);
    assert_eq!(l.level, BT_SECURITY_HIGH);
    assert_eq!(admissible(BT_SECURITY_HIGH, &l), Verdict::Sufficient);
    assert_eq!(admissible(BT_SECURITY_FIPS, &l), Verdict::Insufficient);
}

#[test]
fn the_legacy_link_mode_bits_map_both_ways() {
    assert_eq!(level_from_link_mode(u::LM_AUTH), Some(BT_SECURITY_LOW));
    assert_eq!(level_from_link_mode(u::LM_AUTH | u::LM_ENCRYPT), Some(BT_SECURITY_MEDIUM));
    assert_eq!(level_from_link_mode(u::LM_AUTH | u::LM_ENCRYPT | u::LM_SECURE), Some(BT_SECURITY_HIGH));
    // The highest level cannot be asked for through the legacy option.
    assert_eq!(level_from_link_mode(u::LM_FIPS), None);
    assert_eq!(link_mode_from_level(BT_SECURITY_FIPS) & u::LM_FIPS, u::LM_FIPS);
    assert_eq!(link_mode_from_level(BT_SECURITY_LOW), u::LM_AUTH);
}
