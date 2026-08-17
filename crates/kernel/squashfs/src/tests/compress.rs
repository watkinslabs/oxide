//! Each `Codec` identifier maps to the right decompressor, an unsupported one
//! is distinguished from an unknown one, and a decoded block is bounded by
//! what the CALLER expects, never by what the medium claims.

use alloc::vec::Vec;

use super::{Codec, CodecError};
use crate::uapi::comp;

const SAMPLE: &[u8] = b"squashfs test payload, repeated repeated repeated repeated";

fn zlib_bytes(src: &[u8]) -> Vec<u8> { miniz_oxide::deflate::compress_to_vec_zlib(src, 6) }

fn lzo_bytes(src: &[u8]) -> Vec<u8> { lzokay::compress::compress(src).expect("lzo compress") }

fn lz4_bytes(src: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; lz4_flex::block::get_maximum_output_size(src.len())];
    let n = lz4_flex::block::compress_into(src, &mut out).expect("lz4 compress");
    out.truncate(n);
    out
}

fn zstd_bytes(src: &[u8]) -> Vec<u8> { zstd::compress(src, zstd::Level::Fast).expect("zstd compress") }

#[test]
fn from_id_resolves_every_supported_codec() {
    assert_eq!(Codec::from_id(comp::ZLIB), Ok(Codec::Zlib));
    assert_eq!(Codec::from_id(comp::LZO), Ok(Codec::Lzo));
    assert_eq!(Codec::from_id(comp::LZ4), Ok(Codec::Lz4));
    assert_eq!(Codec::from_id(comp::ZSTD), Ok(Codec::Zstd));
}

#[test]
fn from_id_distinguishes_unsupported_from_unknown() {
    // LZMA/XZ are FORMAT-DEFINED but this build has no decoder for them.
    assert_eq!(Codec::from_id(comp::LZMA), Err(CodecError::Unsupported(comp::LZMA)));
    assert_eq!(Codec::from_id(comp::XZ), Err(CodecError::Unsupported(comp::XZ)));
    // An id the format itself never defines.
    assert_eq!(Codec::from_id(0), Err(CodecError::Unknown(0)));
    assert_eq!(Codec::from_id(999), Err(CodecError::Unknown(999)));
}

#[test]
fn every_codec_name_is_distinct_and_lowercase() {
    let names = [Codec::Zlib.name(), Codec::Lzo.name(), Codec::Lz4.name(), Codec::Zstd.name()];
    for n in names { assert_eq!(n, n.to_lowercase()); }
    for i in 0..names.len() {
        for j in (i + 1)..names.len() { assert_ne!(names[i], names[j]); }
    }
}

#[test]
fn zlib_round_trips_through_bounded_and_exact() {
    let packed = zlib_bytes(SAMPLE);
    let out = Codec::Zlib.decompress_bounded(&packed, SAMPLE.len()).unwrap();
    assert_eq!(out, SAMPLE);
    let out = Codec::Zlib.decompress_exact(&packed, SAMPLE.len()).unwrap();
    assert_eq!(out, SAMPLE);
}

#[test]
fn lzo_round_trips() {
    let packed = lzo_bytes(SAMPLE);
    let out = Codec::Lzo.decompress_bounded(&packed, SAMPLE.len()).unwrap();
    assert_eq!(out, SAMPLE);
}

#[test]
fn lz4_round_trips() {
    let packed = lz4_bytes(SAMPLE);
    let out = Codec::Lz4.decompress_bounded(&packed, SAMPLE.len()).unwrap();
    assert_eq!(out, SAMPLE);
}

#[test]
fn zstd_round_trips() {
    let packed = zstd_bytes(SAMPLE);
    let out = Codec::Zstd.decompress_bounded(&packed, SAMPLE.len()).unwrap();
    assert_eq!(out, SAMPLE);
}

#[test]
fn empty_source_is_refused_regardless_of_codec() {
    assert!(Codec::Zlib.decompress_bounded(&[], 16).is_err());
}

#[test]
fn zero_max_is_refused() {
    let packed = zlib_bytes(SAMPLE);
    assert!(Codec::Zlib.decompress_bounded(&packed, 0).is_err());
}

#[test]
fn exact_rejects_a_length_the_block_did_not_actually_decode_to() {
    let packed = zlib_bytes(SAMPLE);
    // The block truly decodes to SAMPLE.len() bytes; asking for a different
    // exact count must fail even though the block itself is valid.
    assert!(Codec::Zlib.decompress_exact(&packed, SAMPLE.len() + 1).is_err());
}

#[test]
fn bounded_rejects_a_block_whose_output_exceeds_the_callers_ceiling() {
    let packed = zlib_bytes(SAMPLE);
    // The caller's ceiling is the FORMAT's bound, never the block's own
    // claim; a block that would produce more than that ceiling is corrupt.
    assert!(Codec::Zlib.decompress_bounded(&packed, SAMPLE.len() - 1).is_err());
}
