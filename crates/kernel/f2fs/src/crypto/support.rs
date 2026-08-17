//! Whether a policy may be used at all, on this build, on this volume, on
//! this inode.
//!
//! Parsing a context says what it claims. This says whether the claim is one
//! that can be honoured. Every refusal here is a file that cannot be opened
//! correctly; the alternative to refusing is a plausible wrong answer, which
//! is why none of these checks is advisory.
//!
//! The mode pairs are a fixed list, not a cross product. Contents and names
//! are encrypted by different constructions, and only certain pairings were
//! ever defined — a policy naming a contents mode for names is refused even
//! though both numbers are valid modes.

use super::mode;
use super::policy::{FsFacts, InodeFacts, KeyId, Policy};
use super::uapi::*;
use super::FscryptError;

/// Mode pairs a v1 policy may name. Deliberately closed: the older policy
/// version gains nothing new.
/// # C: O(1)
fn valid_modes_v1(contents: u8, names: u8) -> bool {
    matches!((contents, names),
        (MODE_AES_256_XTS, MODE_AES_256_CTS)
        | (MODE_AES_128_CBC, MODE_AES_128_CTS)
        | (MODE_ADIANTUM, MODE_ADIANTUM))
}

/// Mode pairs a v2 policy may name: everything v1 allows, and the newer
/// pairings. # C: O(1)
fn valid_modes_v2(contents: u8, names: u8) -> bool {
    matches!((contents, names),
        (MODE_AES_256_XTS, MODE_AES_256_HCTR2) | (MODE_SM4_XTS, MODE_SM4_CTS))
        || valid_modes_v1(contents, names)
}

/// The direct-key flag reuses one key across a whole mode, so the file's
/// nonce has to travel in the IV instead — which needs the two modes to be
/// the same and the IV to have room for it. # C: O(1)
fn direct_key_ok(p: &Policy) -> Result<(), FscryptError> {
    if p.contents_mode != p.filenames_mode { return Err(FscryptError::DirectKeyModesDiffer); }
    let m = mode::by_number(p.contents_mode)?;
    if !mode::iv_holds_nonce(m) { return Err(FscryptError::DirectKeyIvTooSmall); }
    Ok(())
}

/// Number of bits the largest data unit index on this volume occupies.
/// # C: O(1)
pub(super) fn max_file_dun_bits(fs: &FsFacts, du_bits: u8) -> u32 {
    let top = fs.max_file_bytes.saturating_sub(1);
    let used = u64::BITS - top.leading_zeros();
    used.saturating_sub(u32::from(du_bits))
}

/// The two inode-number-in-the-IV policies exist for hardware that cannot do
/// anything else, and they are only safe on a volume whose inode numbers are
/// stable and small and whose files are short enough that the index fits
/// beside them. # C: O(1)
fn iv_ino_lblk_ok(p: &Policy, fs: &FsFacts) -> Result<(), FscryptError> {
    if p.contents_mode != MODE_AES_256_XTS { return Err(FscryptError::IvInoLblkMode); }
    if !HAS_STABLE_INODES || !HAS_32BIT_INODES { return Err(FscryptError::IvInoLblkVolume); }
    if max_file_dun_bits(fs, p.data_unit_bits(fs)) > 32 {
        return Err(FscryptError::IvInoLblkVolume);
    }
    Ok(())
}

/// Whether a v1 policy is usable. # C: O(1)
fn check_v1(p: &Policy, inode: &InodeFacts) -> Result<(), FscryptError> {
    if !valid_modes_v1(p.contents_mode, p.filenames_mode) {
        return Err(FscryptError::ModePairNotAllowed);
    }
    if p.flags & !(FLAGS_PAD_MASK | FLAG_DIRECT_KEY) != 0 {
        return Err(FscryptError::UnsupportedFlags(p.flags));
    }
    if p.flags & FLAG_DIRECT_KEY != 0 { direct_key_ok(p)?; }
    // A case-folding directory hashes names with a key derived from the
    // master key, and the older policy has no derivation that can produce
    // one. There is no fallback: a wrong hash puts every entry in a bucket
    // no lookup searches.
    if inode.casefolded { return Err(FscryptError::V1WithCasefold); }
    // Whether the modes this build carries can serve the inode.
    p.mode_for(inode)?;
    Ok(())
}

/// Whether a v2 policy is usable. # C: O(1)
fn check_v2(p: &Policy, inode: &InodeFacts, fs: &FsFacts) -> Result<(), FscryptError> {
    if !valid_modes_v2(p.contents_mode, p.filenames_mode) {
        return Err(FscryptError::ModePairNotAllowed);
    }
    const KNOWN: u8 = FLAGS_PAD_MASK | FLAG_DIRECT_KEY | FLAG_IV_INO_LBLK_64 | FLAG_IV_INO_LBLK_32;
    if p.flags & !KNOWN != 0 { return Err(FscryptError::UnsupportedFlags(p.flags)); }
    // The three key-derivation flags each replace the per-file key with a
    // different scheme; two at once names no scheme at all.
    let picked = u32::from(p.flags & FLAG_DIRECT_KEY != 0)
        + u32::from(p.flags & FLAG_IV_INO_LBLK_64 != 0)
        + u32::from(p.flags & FLAG_IV_INO_LBLK_32 != 0);
    if picked > 1 { return Err(FscryptError::MutuallyExclusiveFlags(p.flags)); }
    if p.log2_data_unit_size != 0 {
        if !SUPPORTS_SUBBLOCK_DATA_UNITS { return Err(FscryptError::DataUnitSize); }
        if p.log2_data_unit_size > fs.blkbits
            || p.log2_data_unit_size < MIN_LOG2_DATA_UNIT_SIZE
        {
            return Err(FscryptError::DataUnitSize);
        }
        // A unit smaller than a block would let the index wrap inside a
        // block, which the hashed-inode scheme cannot express.
        if p.log2_data_unit_size != fs.blkbits && p.flags & FLAG_IV_INO_LBLK_32 != 0 {
            return Err(FscryptError::DataUnitSize);
        }
    }
    if p.flags & FLAG_DIRECT_KEY != 0 { direct_key_ok(p)?; }
    if p.flags & (FLAG_IV_INO_LBLK_64 | FLAG_IV_INO_LBLK_32) != 0 { iv_ino_lblk_ok(p, fs)?; }
    p.mode_for(inode)?;
    Ok(())
}

/// Whether the volume's ROOT directory may be given a policy.
///
/// A volume advertising lost+found tells a repair tool that the directory it
/// reparents recovered orphans into exists and is readable. A tool walking a
/// broken volume holds no key, so a policy on the root would put the entire
/// tree — including that directory — out of its reach, and the volume would
/// still be advertising a repair path it no longer has.
///
/// The two cannot both stand and the bit wins: it is on the medium, where
/// every later tool reads it, whereas the policy is a request that has not
/// been honoured yet. Only the ROOT is refused; a policy anywhere below it
/// leaves the reparenting target reachable.
/// # C: O(1)
pub fn root_may_be_encrypted(feature: u32) -> bool {
    !crate::features::has_lost_found(feature)
}

/// Whether `p` may be used for `inode` on this volume. # C: O(1)
pub fn check(p: &Policy, inode: &InodeFacts, fs: &FsFacts) -> Result<(), FscryptError> {
    match (p.version, p.key) {
        (POLICY_V1, KeyId::Descriptor(_)) => check_v1(p, inode),
        (POLICY_V2, KeyId::Identifier(_)) => check_v2(p, inode, fs),
        _ => Err(FscryptError::BadContext),
    }
}
