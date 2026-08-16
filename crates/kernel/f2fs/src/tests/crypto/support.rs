//! Which policies may be used, and why each refusal exists.

use super::fixture::*;
use crate::crypto::policy::FsFacts;
use crate::crypto::support::check;
use crate::crypto::uapi::*;
use crate::crypto::FscryptError;

#[test]
fn the_defined_mode_pairs_are_accepted() {
    for (c, n) in [(MODE_AES_256_XTS, MODE_AES_256_CTS), (MODE_AES_128_CBC, MODE_AES_128_CTS)] {
        check(&policy_v1(c, n, 0), &reg(), &fs()).unwrap();
        check(&policy_v2(c, n, 0), &reg(), &fs()).unwrap();
    }
}

/// Both numbers name real modes; the PAIRING is what was never defined.
#[test]
fn an_undefined_pairing_is_refused_even_though_both_modes_exist() {
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_128_CTS, 0);
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
    let q = policy_v2(MODE_AES_128_CBC, MODE_AES_256_CTS, 0);
    assert_eq!(check(&q, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
}

/// The newer pairings are v2 only; naming one in a v1 policy is refused.
#[test]
fn newer_pairings_are_not_available_to_the_older_version() {
    let v2 = policy_v2(MODE_SM4_XTS, MODE_SM4_CTS, 0);
    // Accepted as a policy, then refused for want of a cipher — a different
    // answer from a pairing that was never defined.
    assert_eq!(check(&v2, &reg(), &fs()).unwrap_err(),
               FscryptError::UnsupportedMode(MODE_SM4_XTS));
    let v1 = policy_v1(MODE_SM4_XTS, MODE_SM4_CTS, 0);
    assert_eq!(check(&v1, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
}

/// A mode another kernel carries is not a corrupt volume, and the two answers
/// are deliberately different errno values.
#[test]
fn a_mode_this_build_lacks_differs_from_a_mode_that_does_not_exist() {
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_HCTR2, 0);
    let e = check(&p, &dir(), &fs()).unwrap_err();
    assert_eq!(e, FscryptError::UnsupportedMode(MODE_AES_256_HCTR2));
    assert_eq!(e.errno(), syscall::errno::Errno::Enopkg);
    let q = policy_v2(200, 201, 0);
    assert_eq!(check(&q, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
}

#[test]
fn flags_outside_the_version_are_refused() {
    // The inode-in-the-IV flags did not exist for the older version.
    let p = policy_v1(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAG_IV_INO_LBLK_64);
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(),
               FscryptError::UnsupportedFlags(FLAG_IV_INO_LBLK_64));
    let q = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, 0x20);
    assert_eq!(check(&q, &reg(), &fs()).unwrap_err(), FscryptError::UnsupportedFlags(0x20));
}

/// Each derivation flag REPLACES the default one; two of them name no scheme.
#[test]
fn two_derivation_flags_at_once_are_refused() {
    let both = FLAG_IV_INO_LBLK_64 | FLAG_IV_INO_LBLK_32;
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, both);
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::MutuallyExclusiveFlags(both));
    let d = FLAG_DIRECT_KEY | FLAG_IV_INO_LBLK_64;
    let q = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, d);
    assert_eq!(check(&q, &reg(), &fs()).unwrap_err(), FscryptError::MutuallyExclusiveFlags(d));
}

/// The direct-key flag needs the file nonce in the IV, and none of the block
/// modes has room for it — which is why no policy this build can serve uses
/// it, exactly as upstream.
#[test]
fn direct_key_is_refused_for_every_mode_this_build_carries() {
    for m in [MODE_AES_256_XTS, MODE_AES_128_CBC] {
        let names = if m == MODE_AES_256_XTS { MODE_AES_256_CTS } else { MODE_AES_128_CTS };
        let p = policy_v2(m, names, FLAG_DIRECT_KEY);
        // Different modes for contents and names is the first thing it fails.
        assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::DirectKeyModesDiffer);
        let q = policy_v2(m, m, FLAG_DIRECT_KEY);
        let e = check(&q, &reg(), &fs()).unwrap_err();
        // Same mode both sides is not a defined pairing for these, so it is
        // refused before the IV width is ever consulted.
        assert_eq!(e, FscryptError::ModePairNotAllowed);
    }
    // A pairing that IS defined with one mode on both sides reaches the IV
    // width check and fails there.
    let p = policy_v1(MODE_ADIANTUM, MODE_ADIANTUM, FLAG_DIRECT_KEY);
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(),
               FscryptError::UnsupportedMode(MODE_ADIANTUM));
}

/// The inode-in-the-IV policies were only ever defined for one contents mode.
#[test]
fn inode_in_the_iv_needs_the_tweakable_mode() {
    for f in [FLAG_IV_INO_LBLK_64, FLAG_IV_INO_LBLK_32] {
        let p = policy_v2(MODE_AES_128_CBC, MODE_AES_128_CTS, f);
        assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::IvInoLblkMode);
        check(&policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, f), &reg(), &fs()).unwrap();
    }
}

/// The index has to fit beside the inode number, so a volume whose files can
/// be long enough to need more than 32 bits of index cannot use them.
#[test]
fn inode_in_the_iv_needs_a_volume_whose_index_fits() {
    let big = FsFacts { max_file_bytes: 1 << 46, blkbits: 12 };
    let p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAG_IV_INO_LBLK_64);
    assert_eq!(check(&p, &reg(), &big).unwrap_err(), FscryptError::IvInoLblkVolume);
    // One bit smaller and it fits.
    let ok = FsFacts { max_file_bytes: 1 << 44, blkbits: 12 };
    check(&p, &reg(), &ok).unwrap();
}

#[test]
fn the_data_unit_size_is_bounded_by_the_block_and_the_sector() {
    let mut p = default_v2();
    p.log2_data_unit_size = 13;
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::DataUnitSize);
    p.log2_data_unit_size = 8;
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::DataUnitSize);
    p.log2_data_unit_size = 9;
    check(&p, &reg(), &fs()).unwrap();
    p.log2_data_unit_size = 12;
    check(&p, &reg(), &fs()).unwrap();
}

/// A unit smaller than a block cannot be combined with the hashed-inode
/// scheme: the index would wrap inside a block.
#[test]
fn a_sub_block_unit_is_refused_with_the_hashed_inode_scheme() {
    let mut p = policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, FLAG_IV_INO_LBLK_32);
    p.log2_data_unit_size = 9;
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::DataUnitSize);
    p.log2_data_unit_size = 12;
    check(&p, &reg(), &fs()).unwrap();
}

/// The older version cannot derive a directory hash key, and a case-folding
/// directory needs one — so the combination is refused rather than hashed
/// with a key that does not exist.
#[test]
fn the_older_version_is_refused_on_a_case_folding_directory() {
    let p = policy_v1(MODE_AES_256_XTS, MODE_AES_256_CTS, 0);
    assert_eq!(check(&p, &folding_dir(), &fs()).unwrap_err(), FscryptError::V1WithCasefold);
    check(&p, &dir(), &fs()).unwrap();
    check(&default_v2(), &folding_dir(), &fs()).unwrap();
}

/// A policy whose version and key naming disagree describes nothing.
#[test]
fn a_version_that_does_not_match_its_key_naming_is_refused() {
    let mut p = default_v2();
    p.version = POLICY_V1;
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::BadContext);
}
