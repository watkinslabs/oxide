//! The two block length encodings, and the failure of decoding one with the
//! other's mask.

use super::{data_length, metadata_length};
use crate::uapi::{COMPRESSED_BIT, COMPRESSED_BIT_BLOCK};

#[test]
fn metadata_uncompressed_bit_set_means_stored_raw() {
    let d = metadata_length(40 | COMPRESSED_BIT);
    assert_eq!(d.on_disk, 40);
    assert!(!d.compressed);
}

#[test]
fn metadata_bit_clear_means_compressed() {
    let d = metadata_length(40);
    assert_eq!(d.on_disk, 40);
    assert!(d.compressed);
}

#[test]
fn metadata_bare_flag_word_denotes_the_largest_length() {
    // A word of exactly the flag bit alone: the length field is zero, which
    // the format uses to mean "the largest length this encoding can express".
    let d = metadata_length(COMPRESSED_BIT);
    assert_eq!(d.on_disk, COMPRESSED_BIT as usize);
    assert!(!d.compressed);
}

#[test]
fn data_uncompressed_bit_set_means_stored_raw() {
    let d = data_length(40 | COMPRESSED_BIT_BLOCK).unwrap();
    assert_eq!(d.on_disk, 40);
    assert!(!d.compressed);
}

#[test]
fn data_bit_clear_means_compressed() {
    let d = data_length(40).unwrap();
    assert_eq!(d.on_disk, 40);
    assert!(d.compressed);
}

#[test]
fn data_word_wider_than_the_format_allows_is_corruption() {
    // Bit 25 or above cannot describe a block this format can hold.
    assert!(data_length(1u32 << 25).is_err());
}

#[test]
fn sparse_block_is_a_zero_length_hole() {
    let d = data_length(COMPRESSED_BIT_BLOCK).unwrap();
    assert!(d.on_disk == 0);
    assert!(d.is_sparse());
}

/// Decoding a METADATA word with the DATA mask reads the wrong length: the
/// flag bit sits at a different position in each encoding, so applying the
/// data mask to a metadata word leaves the metadata flag INSIDE the length
/// field instead of stripping it. `lib.rs` names this as the failure that
/// survives a casual look — a 40-byte uncompressed metadata block, decoded
/// with the data-block mask, reads as a huge bogus length rather than 40.
#[test]
fn decoding_a_metadata_word_with_the_data_mask_reads_the_wrong_length() {
    let word = 40u16 | COMPRESSED_BIT; // a real, valid metadata word
    let right = metadata_length(word);
    assert_eq!(right.on_disk, 40);

    // Widen to 32 bits and run it through the DATA decoder instead.
    let wrong = data_length(u32::from(word)).unwrap();
    assert_ne!(wrong.on_disk, right.on_disk);
    assert_eq!(wrong.on_disk, u32::from(word) as usize);
}
