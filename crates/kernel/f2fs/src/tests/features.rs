//! The refusal contract: what a feature word permits.

use super::*;

#[test]
fn a_plain_volume_mounts_read_write() {
    assert_eq!(access(0, false), Ok(Access::ReadWrite));
}

#[test]
fn every_readable_feature_mounts() {
    for f in [
        FEATURE_EXTRA_ATTR,
        FEATURE_PRJQUOTA,
        FEATURE_INODE_CHKSUM,
        FEATURE_FLEXIBLE_INLINE_XATTR,
        FEATURE_QUOTA_INO,
        FEATURE_INODE_CRTIME,
        FEATURE_LOST_FOUND,
        FEATURE_VERITY,
        FEATURE_SB_CHKSUM,
        FEATURE_ATOMIC_WRITE,
        FEATURE_COMPRESSION,
        FEATURE_ENCRYPT,
        FEATURE_PACKED_SSA,
    ] {
        assert_eq!(access(f, false), Ok(Access::ReadWrite), "feature {f:#x}");
    }
}

#[test]
fn a_volume_marked_read_only_mounts_read_only() {
    assert_eq!(access(FEATURE_RO, false), Ok(Access::ReadOnly));
}

#[test]
fn an_unknown_bit_refuses_the_mount() {
    // The bit above every one this build knows. A later format revision could
    // change any layout, and mounting it would misread rather than fail.
    let bit = 1u32 << 20;
    assert_eq!(access(bit, false), Err(Refusal::Unknown(bit)));
}

#[test]
fn an_unknown_bit_beside_known_ones_still_refuses() {
    let bit = 1u32 << 31;
    assert_eq!(access(FEATURE_EXTRA_ATTR | bit, false), Err(Refusal::Unknown(bit)));
}

#[test]
fn unknown_reports_only_the_unknown_bits() {
    let bits = (1u32 << 20) | (1u32 << 21);
    assert_eq!(access(KNOWN | bits, false), Err(Refusal::Unknown(bits)));
}

#[test]
fn casefolding_refuses_because_names_would_resolve_differently() {
    assert_eq!(access(FEATURE_CASEFOLD, false), Err(Refusal::Casefold));
}

#[test]
fn zoned_refuses_because_a_plain_device_has_no_zones() {
    assert_eq!(access(FEATURE_BLKZONED, false), Err(Refusal::Zoned));
}

#[test]
fn a_device_alias_refuses() {
    assert_eq!(access(FEATURE_DEVICE_ALIAS, false), Err(Refusal::MultiDevice));
}

#[test]
fn a_second_listed_device_refuses_without_any_feature_bit() {
    // A volume may span devices with no bit set at all; the LIST is what makes
    // the rest of it unreachable.
    assert_eq!(access(0, true), Err(Refusal::MultiDevice));
}

#[test]
fn refusal_beats_read_only() {
    // A refused volume is refused whether or not it also asks to be read-only.
    assert_eq!(access(FEATURE_RO | FEATURE_CASEFOLD, false), Err(Refusal::Casefold));
}

#[test]
fn unknown_beats_every_other_refusal() {
    let bit = 1u32 << 24;
    assert!(matches!(access(FEATURE_CASEFOLD | bit, false), Err(Refusal::Unknown(_))));
}

#[test]
fn known_covers_every_named_bit_and_nothing_above_them() {
    assert_eq!(KNOWN, 0x0001_FFFF);
}

#[test]
fn the_predicates_read_their_own_bit() {
    assert!(has_inode_chksum(FEATURE_INODE_CHKSUM));
    assert!(!has_inode_chksum(FEATURE_SB_CHKSUM));
    assert!(has_sb_chksum(FEATURE_SB_CHKSUM));
    assert!(has_extra_attr(FEATURE_EXTRA_ATTR));
    assert!(has_flexible_inline_xattr(FEATURE_FLEXIBLE_INLINE_XATTR));
    assert!(has_inode_crtime(FEATURE_INODE_CRTIME));
    assert!(has_project_quota(FEATURE_PRJQUOTA));
    assert!(has_compression(FEATURE_COMPRESSION));
    assert!(has_encrypt(FEATURE_ENCRYPT));
}
