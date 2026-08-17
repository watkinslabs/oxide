//! The stored context: what parses, what does not, and what a round trip
//! must preserve.

use super::fixture::*;
use crate::crypto::policy::{self, KeyId};
use crate::crypto::uapi::*;
use crate::crypto::FscryptError;

/// A v1 context, assembled byte by byte the way the format lays it out.
fn v1_bytes() -> [u8; CONTEXT_V1_SIZE] {
    let mut b = [0u8; CONTEXT_V1_SIZE];
    b[CTX_VERSION] = CONTEXT_V1;
    b[CTX_CONTENTS_MODE] = MODE_AES_256_XTS;
    b[CTX_FILENAMES_MODE] = MODE_AES_256_CTS;
    b[CTX_FLAGS] = FLAGS_PAD_16;
    b[CTX_V1_DESCRIPTOR..CTX_V1_DESCRIPTOR + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    b[CTX_V1_NONCE..].copy_from_slice(&nonce());
    b
}

fn v2_bytes() -> [u8; CONTEXT_V2_SIZE] {
    let mut b = [0u8; CONTEXT_V2_SIZE];
    b[CTX_VERSION] = CONTEXT_V2;
    b[CTX_CONTENTS_MODE] = MODE_AES_256_XTS;
    b[CTX_FILENAMES_MODE] = MODE_AES_256_CTS;
    b[CTX_FLAGS] = FLAGS_PAD_32 | FLAG_IV_INO_LBLK_64;
    b[CTX_V2_LOG2_DU] = 12;
    b[CTX_V2_IDENTIFIER..CTX_V2_IDENTIFIER + 16].copy_from_slice(&hex::<16>(IDENTIFIER));
    b[CTX_V2_NONCE..].copy_from_slice(&nonce());
    b
}

/// The context version and the POLICY version are different numbers for the
/// older format: the context says 1 and the policy it describes is 0.
#[test]
fn v1_context_yields_a_version_zero_policy() {
    let c = policy::parse(&v1_bytes()).unwrap();
    assert_eq!(c.policy.version, POLICY_V1);
    assert_eq!(c.policy.contents_mode, MODE_AES_256_XTS);
    assert_eq!(c.policy.filenames_mode, MODE_AES_256_CTS);
    assert_eq!(c.policy.flags, FLAGS_PAD_16);
    assert_eq!(c.policy.key, KeyId::Descriptor([1, 2, 3, 4, 5, 6, 7, 8]));
    assert_eq!(c.nonce, nonce());
    // The older context has no data-unit field at all, so it never names one.
    assert_eq!(c.policy.log2_data_unit_size, 0);
}

#[test]
fn v2_context_carries_identifier_and_data_unit() {
    let c = policy::parse(&v2_bytes()).unwrap();
    assert_eq!(c.policy.version, POLICY_V2);
    assert_eq!(c.policy.flags, FLAGS_PAD_32 | FLAG_IV_INO_LBLK_64);
    assert_eq!(c.policy.log2_data_unit_size, 12);
    assert_eq!(c.policy.key, KeyId::Identifier(hex(IDENTIFIER)));
}

#[test]
fn round_trip_is_byte_exact_at_both_versions() {
    for want in [&v1_bytes()[..], &v2_bytes()[..]] {
        let c = policy::parse(want).unwrap();
        let (got, n) = policy::serialize(&c);
        assert_eq!(n, want.len());
        assert_eq!(&got[..n], want);
    }
}

/// A record of the wrong length for its version is a different structure, not
/// a truncated one: reading a nonce out of the bytes past it would derive a
/// plausible wrong key rather than fail.
#[test]
fn a_length_that_does_not_match_the_version_is_refused() {
    let full = v2_bytes();
    for n in [1usize, CONTEXT_V1_SIZE, CONTEXT_V2_SIZE - 1] {
        assert_eq!(policy::parse(&full[..n]).unwrap_err(), FscryptError::BadContext);
    }
    // An empty attribute is no context at all.
    assert_eq!(policy::parse(&[]).unwrap_err(), FscryptError::BadContext);
    let short = v1_bytes();
    assert_eq!(policy::parse(&short[..CONTEXT_V1_SIZE - 1]).unwrap_err(),
               FscryptError::BadContext);
    // The right length for the OTHER version is still the wrong length here.
    let mut wrong = [0u8; CONTEXT_V2_SIZE];
    wrong[CTX_VERSION] = CONTEXT_V1;
    assert_eq!(policy::parse(&wrong).unwrap_err(), FscryptError::BadContext);
}

#[test]
fn an_unknown_context_version_names_itself() {
    let mut b = v2_bytes();
    b[CTX_VERSION] = 3;
    assert_eq!(policy::parse(&b).unwrap_err(), FscryptError::UnknownContextVersion(3));
}

/// The reserved bytes are part of the policy. A context with them set was
/// written by something that knows a field this build does not, so honouring
/// the rest of it would ignore a setting that changes the answer.
#[test]
fn reserved_bytes_set_are_refused() {
    for i in 0..CTX_V2_RESERVED_LEN {
        let mut b = v2_bytes();
        b[CTX_V2_RESERVED + i] = 1;
        assert_eq!(policy::parse(&b).unwrap_err(), FscryptError::ReservedSet);
    }
}

#[test]
fn padding_comes_from_the_low_two_flag_bits() {
    for (flag, want) in [(FLAGS_PAD_4, 4usize), (FLAGS_PAD_8, 8), (FLAGS_PAD_16, 16),
                         (FLAGS_PAD_32, 32)] {
        assert_eq!(policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS, flag).padding(), want);
        // The other flags do not disturb it.
        assert_eq!(policy_v2(MODE_AES_256_XTS, MODE_AES_256_CTS,
                             flag | FLAG_IV_INO_LBLK_64).padding(), want);
    }
}

/// A v1 policy has no data-unit field, so its granularity is the block
/// whatever the volume's block size is; a v2 policy's zero means the same.
#[test]
fn data_unit_bits_default_to_the_block() {
    let f = fs();
    assert_eq!(policy_v1(MODE_AES_256_XTS, MODE_AES_256_CTS, 0).data_unit_bits(&f), 12);
    assert_eq!(default_v2().data_unit_bits(&f), 12);
    let mut p = default_v2();
    p.log2_data_unit_size = 9;
    assert_eq!(p.data_unit_bits(&f), 9);
}

/// Only three file types are encryptable; anything else has no mode.
#[test]
fn mode_selection_follows_the_file_type() {
    let p = default_v2();
    assert_eq!(p.mode_for(&reg()).unwrap().num, MODE_AES_256_XTS);
    assert_eq!(p.mode_for(&dir()).unwrap().num, MODE_AES_256_CTS);
    assert_eq!(p.mode_for(&lnk()).unwrap().num, MODE_AES_256_CTS);
    let other = crate::crypto::policy::InodeFacts {
        is_dir: false, is_reg: false, is_symlink: false, casefolded: false,
    };
    assert_eq!(p.mode_for(&other).unwrap_err(), FscryptError::NotEncryptable);
}

/// The inode's own mode follows its type, and the assembled encryption
/// reports the one it actually keyed.
#[test]
fn the_assembled_inode_reports_the_mode_it_keyed() {
    assert_eq!(info(reg(), 5).mode().num, MODE_AES_256_XTS);
    assert_eq!(info(reg(), 5).mode().key_size, 64);
    assert_eq!(info(dir(), 5).mode().num, MODE_AES_256_CTS);
    assert_eq!(info(dir(), 5).mode().key_size, 32);
    assert_eq!(info(lnk(), 5).mode().num, MODE_AES_256_CTS);
    // The tweakable mode takes TWO cipher keys in one buffer, so its key is
    // twice the cipher's width; halving it would still round-trip.
    assert_eq!(info(reg(), 5).mode().key_size, 2 * info(dir(), 5).mode().key_size);
}
