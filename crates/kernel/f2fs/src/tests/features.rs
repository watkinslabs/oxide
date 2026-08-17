//! The refusal contract: what a feature word permits.

use super::*;

#[test]
fn a_plain_volume_mounts_read_write() {
    assert_eq!(access(0), Ok(Access::ReadWrite));
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
        assert_eq!(access(f), Ok(Access::ReadWrite), "feature {f:#x}");
    }
}

#[test]
fn a_volume_marked_read_only_mounts_read_only() {
    assert_eq!(access(FEATURE_RO), Ok(Access::ReadOnly));
}

#[test]
fn an_unrecognised_bit_is_ignored() {
    // The feature word is not an incompatibility mask. Every bit that changes
    // a layout is named and judged on its own; refusing a volume for a bit
    // that means nothing here would refuse filesystems that read perfectly.
    assert_eq!(access(1u32 << 20), Ok(Access::ReadWrite));
    assert_eq!(access(1u32 << 31), Ok(Access::ReadWrite));
}

#[test]
fn an_unrecognised_bit_does_not_disturb_the_recognised_ones() {
    let bit = 1u32 << 21;
    assert_eq!(access(FEATURE_EXTRA_ATTR | bit), Ok(Access::ReadWrite));
    assert_eq!(access(FEATURE_RO | bit), Ok(Access::ReadOnly));
    assert_eq!(access(FEATURE_BLKZONED | bit), Ok(Access::ReadWrite));
}

#[test]
fn casefolding_alone_does_not_refuse_here() {
    // Whether a folding volume mounts is decided by its ENCODING, which this
    // predicate cannot see; `sb::sanity::access` makes that call.
    assert_eq!(access(FEATURE_CASEFOLD), Ok(Access::ReadWrite));
}

#[test]
fn a_zoned_layout_is_not_refused_here() {
    // Where its blocks may go is a question for the DRIVE's zone report, not
    // for the feature word; `zoned` answers it and refuses only a layout
    // nothing can locate.
    assert_eq!(access(FEATURE_BLKZONED), Ok(Access::ReadWrite));
}

#[test]
fn a_device_alias_is_not_refused_here() {
    assert_eq!(access(FEATURE_DEVICE_ALIAS), Ok(Access::ReadWrite));
}

#[test]
fn a_read_only_volume_stays_read_only_whatever_else_it_carries() {
    assert_eq!(access(FEATURE_RO | FEATURE_BLKZONED), Ok(Access::ReadOnly));
    assert_eq!(access(FEATURE_RO | FEATURE_DEVICE_ALIAS), Ok(Access::ReadOnly));
}

#[test]
fn the_recognised_set_covers_every_named_bit_and_nothing_above_them() {
    assert_eq!(KNOWN, 0x0001_FFFF);
}

#[test]
fn no_feature_bit_refuses_a_volume_by_itself() {
    // The whole refusal surface, stated once. Folding is decided by the
    // encoding and zones by the drive's report; the feature word alone never
    // declines a volume.
    for f in 0..32u32 {
        let bit = 1u32 << f;
        assert!(access(bit).is_ok(), "feature {bit:#x}");
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
