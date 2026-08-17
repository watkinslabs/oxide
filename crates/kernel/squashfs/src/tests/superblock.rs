//! The superblock, and every documented reason a volume is refused before a
//! byte of its content is believed.

use alloc::vec::Vec;

use super::{inode_block, inode_offset, make_reference, Super, SuperError};
use crate::compress::CodecError;
use crate::test_image::Builder;
use crate::uapi::SUPER_BYTES;

/// A minimal but fully valid image's first `SUPER_BYTES` bytes.
fn valid() -> Vec<u8> { Builder::new().file("a", b"hello").build_bytes() }

#[test]
fn a_valid_superblock_parses() {
    let img = valid();
    let sb = Super::parse(&img[..SUPER_BYTES], img.len() as u64).unwrap();
    assert_eq!(sb.major, 4);
    assert_eq!(sb.minor, 0);
    assert_eq!(sb.bytes_used, img.len() as u64);
    assert!(sb.uncompressed_inodes());
    assert!(sb.uncompressed_data());
    assert!(sb.uncompressed_fragments());
    assert!(!sb.exportable());
}

#[test]
fn short_buffer_is_refused() {
    let img = valid();
    assert_eq!(Super::parse(&img[..SUPER_BYTES - 1], img.len() as u64), Err(SuperError::Short));
}

#[test]
fn bad_magic_is_refused() {
    let mut img = valid();
    img[0] = !img[0];
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64), Err(SuperError::BadMagic));
}

#[test]
fn wrong_major_version_is_refused() {
    let mut img = valid();
    img[28..30].copy_from_slice(&3u16.to_le_bytes()); // major
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64), Err(SuperError::Version(3, 0)));
}

#[test]
fn minor_above_supported_is_refused() {
    let mut img = valid();
    img[30..32].copy_from_slice(&1u16.to_le_bytes()); // minor
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64), Err(SuperError::Version(4, 1)));
}

#[test]
fn unknown_compressor_is_refused_as_codec_error() {
    let mut img = valid();
    img[20..22].copy_from_slice(&0u16.to_le_bytes()); // compression id
    let err = Super::parse(&img[..SUPER_BYTES], img.len() as u64).unwrap_err();
    assert_eq!(err, SuperError::Codec(CodecError::Unknown(0)));
}

#[test]
fn format_defined_but_unbuilt_compressor_is_unsupported_not_unknown() {
    let mut img = valid();
    img[20..22].copy_from_slice(&2u16.to_le_bytes()); // LZMA
    let err = Super::parse(&img[..SUPER_BYTES], img.len() as u64).unwrap_err();
    assert_eq!(err, SuperError::Codec(CodecError::Unsupported(2)));
}

#[test]
fn bytes_used_smaller_than_a_superblock_is_insane() {
    let mut img = valid();
    img[40..48].copy_from_slice(&10u64.to_le_bytes()); // bytes_used
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("bytes_used")));
}

#[test]
fn bytes_used_past_the_medium_is_truncated() {
    let img = valid();
    let claimed = img.len() as u64;
    let err = Super::parse(&img[..SUPER_BYTES], claimed - 1).unwrap_err();
    assert_eq!(err, SuperError::Truncated { claimed, medium: claimed - 1 });
}

#[test]
fn block_size_below_a_page_is_insane() {
    let mut img = valid();
    img[12..16].copy_from_slice(&2048u32.to_le_bytes()); // block_size
    img[22..24].copy_from_slice(&11u16.to_le_bytes()); // block_log = log2(2048)
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("block_size < page")));
}

#[test]
fn block_size_not_matching_block_log_is_insane() {
    let mut img = valid();
    img[22..24].copy_from_slice(&16u16.to_le_bytes()); // block_log, no longer matches block_size
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("block_log mismatch")));
}

#[test]
fn root_inode_offset_past_a_metadata_block_is_insane() {
    let mut img = valid();
    let bogus = make_reference(0, 9000); // offset alone exceeds METADATA_SIZE (8192)
    img[32..40].copy_from_slice(&bogus.to_le_bytes());
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("root_inode offset")));
}

#[test]
fn directory_table_not_after_inode_table_is_insane() {
    let mut img = valid();
    let inode_table_start = u64::from_le_bytes(img[64..72].try_into().unwrap());
    img[72..80].copy_from_slice(&inode_table_start.to_le_bytes()); // directory_table_start
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("inode_table >= directory_table")));
}

#[test]
fn directory_table_past_the_image_is_insane() {
    let mut img = valid();
    let bytes_used = u64::from_le_bytes(img[40..48].try_into().unwrap());
    img[72..80].copy_from_slice(&bytes_used.to_le_bytes()); // directory_table_start
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("directory_table past image")));
}

#[test]
fn no_ids_zero_is_insane() {
    let mut img = valid();
    img[26..28].copy_from_slice(&0u16.to_le_bytes()); // no_ids
    assert_eq!(Super::parse(&img[..SUPER_BYTES], img.len() as u64),
        Err(SuperError::Insane("no ids")));
}

#[test]
fn flag_bit_reads_back_what_was_set() {
    let img = valid();
    let sb = Super::parse(&img[..SUPER_BYTES], img.len() as u64).unwrap();
    assert!(sb.flag(crate::uapi::flags::NOI));
    assert!(!sb.flag(crate::uapi::flags::EXPORT));
}

#[test]
fn inode_reference_packs_and_unpacks() {
    let r = make_reference(0x1234, 0x56);
    assert_eq!(inode_block(r), 0x1234);
    assert_eq!(inode_offset(r), 0x56);
}

#[test]
fn inode_offset_is_masked_to_sixteen_bits() {
    // The offset half of a reference is exactly the low 16 bits; a caller
    // that packed a larger value would silently lose the high bits, which is
    // what the mask is FOR — this pins the mask's width.
    let r = make_reference(1, 0x1_0000);
    assert_eq!(inode_offset(r), 0);
}
