//! The refusal contract: what a feature word permits.

use super::*;

#[test]
fn a_plain_volume_mounts_read_write() {
    assert_eq!(access(0, false), Ok(Access::ReadWrite));
}

#[test]
fn every_readable_feature_mounts() {
    for f in [
        FEATURE_CASEFOLD,
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
fn an_unrecognised_bit_is_ignored() {
    // The feature word is not an incompatibility mask. Every bit that changes
    // a layout is named and judged on its own; refusing a volume for a bit
    // that means nothing here would refuse filesystems that read perfectly.
    assert_eq!(access(1u32 << 20, false), Ok(Access::ReadWrite));
    assert_eq!(access(1u32 << 31, false), Ok(Access::ReadWrite));
}

#[test]
fn an_unrecognised_bit_does_not_disturb_the_recognised_ones() {
    let bit = 1u32 << 21;
    assert_eq!(access(FEATURE_EXTRA_ATTR | bit, false), Ok(Access::ReadWrite));
    assert_eq!(access(FEATURE_RO | bit, false), Ok(Access::ReadOnly));
    assert_eq!(access(FEATURE_BLKZONED | bit, false), Err(Refusal::Zoned));
}

#[test]
fn casefolding_alone_does_not_refuse_here() {
    // Whether a folding volume mounts is decided by its ENCODING, which this
    // predicate cannot see; `sb::sanity::access` makes that call.
    assert_eq!(access(FEATURE_CASEFOLD, false), Ok(Access::ReadWrite));
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
    assert_eq!(access(FEATURE_RO | FEATURE_BLKZONED, false), Err(Refusal::Zoned));
}

#[test]
fn the_recognised_set_covers_every_named_bit_and_nothing_above_them() {
    assert_eq!(KNOWN, 0x0001_FFFF);
}

#[test]
fn only_the_bits_that_change_how_bytes_are_read_are_refused() {
    // The whole refusal surface, stated once: a bit not in this list mounts.
    for f in 0..17u32 {
        let bit = 1u32 << f;
        let refused = access(bit, false).is_err();
        let should = matches!(bit, FEATURE_BLKZONED | FEATURE_DEVICE_ALIAS);
        assert_eq!(refused, should, "feature {bit:#x}");
    }
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
