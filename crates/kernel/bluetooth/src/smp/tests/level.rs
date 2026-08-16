//! Requirement and key-level mappings, key-size bounds and sufficiency.

use crate::uapi::bt::{
    BT_SECURITY_FIPS, BT_SECURITY_HIGH, BT_SECURITY_LOW, BT_SECURITY_MEDIUM, BT_SECURITY_SDP,
};
use crate::uapi::smp::*;
use crate::smp::level::*;

#[test]
fn requirements_map_to_levels() {
    assert_eq!(authreq_to_seclevel(SMP_AUTH_NONE), BT_SECURITY_MEDIUM);
    assert_eq!(authreq_to_seclevel(SMP_AUTH_BONDING), BT_SECURITY_MEDIUM);
    assert_eq!(authreq_to_seclevel(SMP_AUTH_SC), BT_SECURITY_MEDIUM);
    assert_eq!(authreq_to_seclevel(SMP_AUTH_MITM), BT_SECURITY_HIGH);
    assert_eq!(authreq_to_seclevel(SMP_AUTH_MITM | SMP_AUTH_BONDING), BT_SECURITY_HIGH);
    assert_eq!(authreq_to_seclevel(SMP_AUTH_MITM | SMP_AUTH_SC), BT_SECURITY_FIPS);
    // The reserved bits must not move the answer.
    assert_eq!(authreq_to_seclevel(SMP_AUTH_KEYPRESS | SMP_AUTH_CT2), BT_SECURITY_MEDIUM);
}

#[test]
fn levels_map_back_to_requirements() {
    assert_eq!(seclevel_to_authreq(BT_SECURITY_FIPS), SMP_AUTH_MITM | SMP_AUTH_BONDING);
    assert_eq!(seclevel_to_authreq(BT_SECURITY_HIGH), SMP_AUTH_MITM | SMP_AUTH_BONDING);
    assert_eq!(seclevel_to_authreq(BT_SECURITY_MEDIUM), SMP_AUTH_BONDING);
    assert_eq!(seclevel_to_authreq(BT_SECURITY_LOW), SMP_AUTH_NONE);
    assert_eq!(seclevel_to_authreq(BT_SECURITY_SDP), SMP_AUTH_NONE);
    // Asking for the highest level does not itself claim secure connections,
    // which is negotiated rather than requested.
    assert_eq!(seclevel_to_authreq(BT_SECURITY_FIPS) & SMP_AUTH_SC, 0);
}

#[test]
fn key_types_carry_their_provenance() {
    assert!(!ltk_is_sc(SMP_STK));
    assert!(!ltk_is_sc(SMP_LTK));
    assert!(!ltk_is_sc(SMP_LTK_RESPONDER));
    assert!(ltk_is_sc(SMP_LTK_P256));
    assert!(ltk_is_sc(SMP_LTK_P256_DEBUG));
}

#[test]
fn every_key_type_and_authentication_pair_maps_to_a_level() {
    let cases: [(u8, bool, u8); 10] = [
        (SMP_STK, false, BT_SECURITY_MEDIUM),
        (SMP_STK, true, BT_SECURITY_HIGH),
        (SMP_LTK, false, BT_SECURITY_MEDIUM),
        (SMP_LTK, true, BT_SECURITY_HIGH),
        (SMP_LTK_RESPONDER, false, BT_SECURITY_MEDIUM),
        (SMP_LTK_RESPONDER, true, BT_SECURITY_HIGH),
        (SMP_LTK_P256, false, BT_SECURITY_MEDIUM),
        (SMP_LTK_P256, true, BT_SECURITY_FIPS),
        (SMP_LTK_P256_DEBUG, false, BT_SECURITY_MEDIUM),
        (SMP_LTK_P256_DEBUG, true, BT_SECURITY_FIPS),
    ];
    for (t, auth, want) in cases {
        assert_eq!(ltk_sec_level(t, auth), want, "type {} auth {}", t, auth);
    }
}

#[test]
fn an_unauthenticated_key_never_reaches_the_upper_levels() {
    for t in [SMP_STK, SMP_LTK, SMP_LTK_RESPONDER, SMP_LTK_P256, SMP_LTK_P256_DEBUG] {
        assert!(ltk_sec_level(t, false) < BT_SECURITY_HIGH, "type {}", t);
    }
}

#[test]
fn a_non_secure_connections_key_never_reaches_the_highest_level() {
    for t in [SMP_STK, SMP_LTK, SMP_LTK_RESPONDER] {
        assert!(ltk_sec_level(t, true) < BT_SECURITY_FIPS, "type {}", t);
    }
}

#[test]
fn key_size_bounds() {
    let full = SMP_MAX_ENC_KEY_SIZE;
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 7, full), Ok(7));
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 16, full), Ok(16));
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 6, full), Err(SMP_ENC_KEY_SIZE));
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 17, full), Err(SMP_ENC_KEY_SIZE));
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 0, full), Err(SMP_ENC_KEY_SIZE));
}

#[test]
fn the_highest_level_demands_a_full_width_key() {
    let full = SMP_MAX_ENC_KEY_SIZE;
    assert_eq!(check_enc_key_size(BT_SECURITY_FIPS, 16, full), Ok(16));
    for n in SMP_MIN_ENC_KEY_SIZE..SMP_MAX_ENC_KEY_SIZE {
        assert_eq!(check_enc_key_size(BT_SECURITY_FIPS, n, full), Err(SMP_ENC_KEY_SIZE),
                   "size {}", n);
        // The same size is fine at a lower level, so the refusal is the level's
        // doing and not the size's.
        assert_eq!(check_enc_key_size(BT_SECURITY_HIGH, n, full), Ok(n), "size {}", n);
    }
}

#[test]
fn a_controller_limit_below_the_maximum_is_honoured() {
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 10, 10), Ok(10));
    assert_eq!(check_enc_key_size(BT_SECURITY_MEDIUM, 11, 10), Err(SMP_ENC_KEY_SIZE));
    // And a controller that cannot do full width cannot reach the top level.
    assert_eq!(check_enc_key_size(BT_SECURITY_FIPS, 10, 10), Err(SMP_ENC_KEY_SIZE));
}

#[test]
fn the_lowest_level_is_always_satisfied() {
    for level in [BT_SECURITY_LOW] {
        assert!(sufficient_security(BT_SECURITY_LOW, false, false, level, KeyPref::UseLtk));
        assert!(sufficient_security(BT_SECURITY_LOW, true, true, level, KeyPref::UseLtk));
    }
}

#[test]
fn sufficiency_is_an_ordering_on_the_current_level() {
    let levels = [BT_SECURITY_MEDIUM, BT_SECURITY_HIGH, BT_SECURITY_FIPS];
    for current in levels {
        for want in levels {
            assert_eq!(
                sufficient_security(current, false, false, want, KeyPref::UseLtk),
                current >= want,
                "current {} want {}", current, want);
        }
    }
}

#[test]
fn a_pairing_key_is_refused_when_a_stored_one_exists_and_is_wanted() {
    // Encrypted at the top level with the pairing key, a stored key present:
    // refused, so the link is re-encrypted with the stored key.
    assert!(!sufficient_security(BT_SECURITY_FIPS, true, true, BT_SECURITY_MEDIUM,
                                 KeyPref::UseLtk));
    // No stored key to move to: the pairing key stands.
    assert!(sufficient_security(BT_SECURITY_FIPS, true, false, BT_SECURITY_MEDIUM,
                                KeyPref::UseLtk));
    // The caller that does not mind: the pairing key stands either way.
    assert!(sufficient_security(BT_SECURITY_FIPS, true, true, BT_SECURITY_MEDIUM,
                                KeyPref::AllowStk));
    // Not encrypted with a pairing key at all: the preference is irrelevant.
    assert!(sufficient_security(BT_SECURITY_FIPS, false, true, BT_SECURITY_MEDIUM,
                                KeyPref::UseLtk));
}

#[test]
fn every_stored_key_type_is_checked_against_every_level() {
    use crate::smp::keys::Ltk;
    use crate::hci::conn::PeerId;
    use crate::uapi::bt::{BDADDR_LE_PUBLIC, BdAddr};
    let peer = PeerId::new(BdAddr([1, 2, 3, 4, 5, 6]), BDADDR_LE_PUBLIC);
    for key_type in [SMP_STK, SMP_LTK, SMP_LTK_RESPONDER, SMP_LTK_P256, SMP_LTK_P256_DEBUG] {
        for authenticated in [false, true] {
            let k = Ltk { peer, key_type, authenticated, val: [0; SMP_KEY_LEN],
                          enc_size: SMP_MAX_ENC_KEY_SIZE, ediv: 0, rand: 0 };
            for want in [BT_SECURITY_LOW, BT_SECURITY_MEDIUM, BT_SECURITY_HIGH, BT_SECURITY_FIPS] {
                assert_eq!(k.satisfies(want),
                           ltk_sec_level(key_type, authenticated) >= want,
                           "type {} auth {} want {}", key_type, authenticated, want);
            }
        }
    }
}
