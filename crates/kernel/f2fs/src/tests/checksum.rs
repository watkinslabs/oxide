//! The checksum's convention, and the four things it seals.
//!
//! The vectors here are the provenance for the convention itself: the seed is
//! the volume magic, and neither the pre-inversion nor the post-inversion of
//! the usual reflected CRC-32 is applied. A build that used the standard
//! convention would fail every one of these.

use super::*;
use crate::uapi::*;
use alloc::vec;

#[test]
fn seed_is_the_volume_magic() {
    assert_eq!(SEED, 0xF2F5_2010);
}

#[test]
fn empty_input_returns_the_seed_unchanged() {
    // No inversion at either end: the identity for zero bytes is the seed.
    assert_eq!(crc32(&[]), SEED);
}

#[test]
fn differs_from_the_standard_convention() {
    // The standard reflected CRC-32 seeds with all-ones and inverts the
    // result. Agreeing with it here would mean the seed was ignored.
    assert_ne!(crc32(b"f2fs"), crc::crc32(b"f2fs"));
}

#[test]
fn chaining_equals_one_pass_over_the_join() {
    let a = b"the quick brown";
    let b = b" fox jumps over";
    let mut joined = a.to_vec();
    joined.extend_from_slice(b);
    assert_eq!(chksum(crc32(a), b), crc32(&joined));
}

#[test]
fn one_flipped_bit_changes_the_sum() {
    let mut data = vec![0u8; 64];
    let before = crc32(&data);
    data[31] ^= 0x01;
    assert_ne!(before, crc32(&data));
}

/// A superblock copy whose CRC is correct.
fn sealed_super() -> alloc::vec::Vec<u8> {
    let mut s = vec![0u8; SUPER_SIZE];
    s[SB_MAGIC..SB_MAGIC + 4].copy_from_slice(&MAGIC.to_le_bytes());
    s[SB_CHECKSUM_OFFSET..SB_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&(SB_CRC as u32).to_le_bytes());
    let crc = crc32(&s[..SB_CRC]);
    s[SB_CRC..SB_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    s
}

#[test]
fn super_checksum_accepts_a_sealed_copy() {
    assert!(super_ok(&sealed_super()));
}

#[test]
fn super_checksum_rejects_a_changed_body() {
    let mut s = sealed_super();
    s[SB_SEGMENT_COUNT] ^= 0xFF;
    assert!(!super_ok(&s));
}

#[test]
fn super_checksum_rejects_an_offset_that_is_not_the_crc_position() {
    // Any other offset would seal a range nobody wrote, so the field is a
    // constant in disguise and is checked as one.
    let mut s = sealed_super();
    s[SB_CHECKSUM_OFFSET..SB_CHECKSUM_OFFSET + 4].copy_from_slice(&1000u32.to_le_bytes());
    assert!(!super_ok(&s));
}

#[test]
fn super_checksum_covers_the_whole_body_not_a_prefix() {
    // The byte just before the CRC is inside the sealed range.
    let mut s = sealed_super();
    s[SB_CRC - 1] ^= 0xFF;
    assert!(!super_ok(&s));
}

#[test]
fn super_checksum_rejects_a_short_slice() {
    assert!(!super_ok(&[0u8; 16]));
}

/// A checkpoint block sealed at `off`.
fn sealed_cp(off: usize) -> alloc::vec::Vec<u8> {
    let mut c = vec![0u8; BLKSIZE];
    c[CP_CHECKSUM_OFFSET_FIELD..CP_CHECKSUM_OFFSET_FIELD + 4]
        .copy_from_slice(&(off as u32).to_le_bytes());
    let crc = crc32(&c[..off]);
    c[off..off + 4].copy_from_slice(&crc.to_le_bytes());
    c
}

#[test]
fn checkpoint_checksum_accepts_a_sealed_block_at_the_block_end() {
    assert!(checkpoint_ok(&sealed_cp(CP_MAX_CHKSUM_OFFSET)));
}

#[test]
fn checkpoint_checksum_accepts_a_sealed_block_at_the_bitmap_start() {
    assert!(checkpoint_ok(&sealed_cp(CP_SIT_NAT_VERSION_BITMAP)));
}

#[test]
fn checkpoint_checksum_rejects_an_offset_below_the_bitmaps() {
    let c = sealed_cp(CP_SIT_NAT_VERSION_BITMAP - 4);
    assert!(!checkpoint_ok(&c));
    assert_eq!(crc_offset(&c), None);
}

#[test]
fn checkpoint_checksum_rejects_an_offset_past_the_block() {
    let mut c = vec![0u8; BLKSIZE];
    c[CP_CHECKSUM_OFFSET_FIELD..CP_CHECKSUM_OFFSET_FIELD + 4]
        .copy_from_slice(&(BLKSIZE as u32).to_le_bytes());
    assert_eq!(crc_offset(&c), None);
    assert!(!checkpoint_ok(&c));
}

#[test]
fn checkpoint_checksum_rejects_a_changed_version() {
    let mut c = sealed_cp(CP_MAX_CHKSUM_OFFSET);
    c[CP_CHECKPOINT_VER] ^= 0xFF;
    assert!(!checkpoint_ok(&c));
}

#[test]
fn checkpoint_checksum_at_the_bitmap_start_still_covers_the_header() {
    let mut c = sealed_cp(CP_SIT_NAT_VERSION_BITMAP);
    c[CP_VALID_BLOCK_COUNT] ^= 0xFF;
    assert!(!checkpoint_ok(&c));
}

#[test]
fn inode_seed_depends_on_the_uuid() {
    assert_ne!(inode_seed(&[0u8; 16]), inode_seed(&[1u8; 16]));
}

#[test]
fn inode_checksum_excludes_the_stored_word() {
    // The stored value must not feed itself: two blocks differing only in the
    // checksum word must produce the same computed sum.
    let mut a = vec![0u8; BLKSIZE];
    a[I_GENERATION] = 9;
    let mut b = a.clone();
    b[I_INODE_CHECKSUM..I_INODE_CHECKSUM + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    assert_eq!(inode_chksum(1, &a), inode_chksum(1, &b));
}

#[test]
fn inode_checksum_covers_the_generation_and_the_footer_inode_number() {
    let base = vec![0u8; BLKSIZE];
    let mut gen = base.clone();
    gen[I_GENERATION] = 1;
    let mut ino = base.clone();
    ino[NODE_FOOTER_OFF + FOOTER_INO] = 1;
    assert_ne!(inode_chksum(1, &base), inode_chksum(1, &gen));
    assert_ne!(inode_chksum(1, &base), inode_chksum(1, &ino));
}

#[test]
fn inode_checksum_covers_bytes_past_the_stored_word() {
    let base = vec![0u8; BLKSIZE];
    let mut tail = base.clone();
    tail[BLKSIZE - 32] = 7;
    assert_ne!(inode_chksum(1, &base), inode_chksum(1, &tail));
}

#[test]
fn inode_checksum_refuses_a_short_block() {
    assert_eq!(inode_chksum(1, &[0u8; 64]), None);
}
