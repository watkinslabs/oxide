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

/// The newer pairings are v2 only; naming one in a v1 policy is refused —
/// which is a statement about the POLICY VERSION, not about the ciphers: both
/// SM4 modes are carried and the v2 spelling of the same pair is accepted.
#[test]
fn newer_pairings_are_not_available_to_the_older_version() {
    check(&policy_v2(MODE_SM4_XTS, MODE_SM4_CTS, 0), &reg(), &fs()).unwrap();
    check(&policy_v2(MODE_SM4_XTS, MODE_SM4_CTS, 0), &dir(), &fs()).unwrap();
    let v1 = policy_v1(MODE_SM4_XTS, MODE_SM4_CTS, 0);
    assert_eq!(check(&v1, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
}

/// Every mode number the format assigns is carried, so the pairings that name
/// them are usable rather than refused for want of a cipher.
#[test]
fn every_assigned_mode_is_carried() {
    check(&policy_v2(MODE_AES_256_XTS, MODE_AES_256_HCTR2, 0), &dir(), &fs()).unwrap();
    check(&policy_v2(MODE_AES_256_XTS, MODE_AES_256_HCTR2, 0), &reg(), &fs()).unwrap();
    check(&policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, 0), &reg(), &fs()).unwrap();
    check(&policy_v1(MODE_ADIANTUM, MODE_ADIANTUM, 0), &reg(), &fs()).unwrap();
    for n in 1..=MODE_MAX {
        // 2 and 3 are holes in the numbering, never assigned.
        if n == 2 || n == 3 { continue; }
        crate::crypto::mode::by_number(n).unwrap();
    }
}

/// A number the format does not assign is a corrupt policy, not a file some
/// other kernel could open, and the two answers carry different errno values.
#[test]
fn an_unassigned_mode_number_is_a_corrupt_policy() {
    let e = crate::crypto::mode::by_number(200).unwrap_err();
    assert_eq!(e, FscryptError::UnknownMode(200));
    assert_eq!(e.errno(), syscall::errno::Errno::Einval);
    // A mode this build lacked would answer ENOPKG instead — the file is
    // intact and a different reader could open it.
    assert_eq!(FscryptError::UnsupportedMode(200).errno(), syscall::errno::Errno::Enopkg);
    // The pairing check runs first, so a policy naming two of them never
    // reaches the mode table at all.
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

/// The direct-key flag needs the file nonce in the IV, so it belongs only to
/// the one pairing that names a wide-tweak mode on both sides.
#[test]
fn direct_key_belongs_only_to_the_wide_tweak_pairing() {
    for m in [MODE_AES_256_XTS, MODE_AES_128_CBC, MODE_SM4_XTS] {
        let names = match m {
            MODE_AES_256_XTS => MODE_AES_256_CTS,
            MODE_SM4_XTS => MODE_SM4_CTS,
            _ => MODE_AES_128_CTS,
        };
        let p = policy_v2(m, names, FLAG_DIRECT_KEY);
        // Different modes for contents and names is the first thing it fails.
        assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::DirectKeyModesDiffer);
        let q = policy_v2(m, m, FLAG_DIRECT_KEY);
        // Same mode both sides is not a defined pairing for these, so it is
        // refused before the IV width is ever consulted.
        assert_eq!(check(&q, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
    }
    // The pairing that IS defined with one mode on both sides has a 32-byte
    // IV, which is the width the nonce needs, so it is accepted — under both
    // policy versions.
    check(&policy_v1(MODE_ADIANTUM, MODE_ADIANTUM, FLAG_DIRECT_KEY), &reg(), &fs()).unwrap();
    check(&policy_v2(MODE_ADIANTUM, MODE_ADIANTUM, FLAG_DIRECT_KEY), &reg(), &fs()).unwrap();
    // The width check is what admits it: the narrow modes fail it.
    assert!(crate::crypto::mode::iv_holds_nonce(crate::crypto::mode::ADIANTUM));
    assert!(crate::crypto::mode::iv_holds_nonce(crate::crypto::mode::AES_256_HCTR2));
    for m in [crate::crypto::mode::AES_256_XTS, crate::crypto::mode::SM4_XTS,
              crate::crypto::mode::SM4_CTS, crate::crypto::mode::AES_128_CBC] {
        assert!(!crate::crypto::mode::iv_holds_nonce(m));
    }
}

/// The other wide-tweak mode is only ever a FILENAMES mode, paired with a
/// narrow contents mode, so the direct-key flag can never reach it.
#[test]
fn the_other_wide_mode_is_never_paired_with_itself() {
    let p = policy_v2(MODE_AES_256_HCTR2, MODE_AES_256_HCTR2, FLAG_DIRECT_KEY);
    assert_eq!(check(&p, &reg(), &fs()).unwrap_err(), FscryptError::ModePairNotAllowed);
    let q = policy_v2(MODE_AES_256_XTS, MODE_AES_256_HCTR2, FLAG_DIRECT_KEY);
    assert_eq!(check(&q, &reg(), &fs()).unwrap_err(), FscryptError::DirectKeyModesDiffer);
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
