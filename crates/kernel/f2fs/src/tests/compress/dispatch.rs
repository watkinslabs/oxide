//! Codec policy, checksums, and whole clusters end to end.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::checksum;
use crate::compress::algo::{
    algorithm, Algorithm, COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_MAX, COMPRESS_ZSTD,
    MAX_COMPRESS_LOG_SIZE, MIN_COMPRESS_LOG_SIZE,
};
use crate::compress::cluster::Geometry;
use crate::compress::encode::{self, Stored};
use crate::compress::{decompress_cluster, Chksum, CompressError};
use crate::uapi::BLKSIZE;

use super::build::{image, image_with_clen, lz4_compress, lz4_literals, lzo_uniform, patterned};

const CHKSUM_FLAG: u16 = 1;

#[test]
fn the_stored_numbers_name_the_four_codecs() {
    assert_eq!(Algorithm::from_stored(COMPRESS_LZO), Some(Algorithm::Lzo));
    assert_eq!(Algorithm::from_stored(COMPRESS_LZ4), Some(Algorithm::Lz4));
    assert_eq!(Algorithm::from_stored(COMPRESS_ZSTD), Some(Algorithm::Zstd));
    assert_eq!(Algorithm::from_stored(COMPRESS_LZORLE), Some(Algorithm::LzoRle));
    assert_eq!(COMPRESS_MAX, 4);
}

#[test]
fn a_number_past_the_last_codec_names_none() {
    for n in COMPRESS_MAX..=255 {
        assert_eq!(Algorithm::from_stored(n), None, "number {n}");
        assert_eq!(algorithm(n), Err(CompressError::UnknownAlgorithm(n)), "number {n}");
    }
}

#[test]
fn every_codec_round_trips_its_own_number() {
    for a in [Algorithm::Lzo, Algorithm::Lz4, Algorithm::Zstd, Algorithm::LzoRle] {
        assert_eq!(Algorithm::from_stored(a.stored()), Some(a));
    }
}

#[test]
fn every_codec_the_format_names_is_one_this_build_unpacks() {
    // The predicate is what decides `UnsupportedAlgorithm`, so a codec
    // dropping out of this list is a volume that reads as unsupported rather
    // than as a file.
    for a in [Algorithm::Lzo, Algorithm::Lz4, Algorithm::Zstd, Algorithm::LzoRle] {
        assert!(a.unpacks(), "{a:?}");
        assert_eq!(algorithm(a.stored()), Ok(a));
    }
}

#[test]
fn only_the_unsupported_codec_reports_an_unsupported_operation() {
    assert_eq!(
        CompressError::UnsupportedAlgorithm(Algorithm::Zstd).errno(),
        Errno::Eopnotsupp
    );
    assert_eq!(CompressError::UnknownAlgorithm(9).errno(), Errno::Euclean);
    assert_eq!(CompressError::BadClusterSize(1).errno(), Errno::Euclean);
    assert_eq!(CompressError::NotCompressed.errno(), Errno::Euclean);
    assert_eq!(CompressError::BadLayout.errno(), Errno::Euclean);
    assert_eq!(CompressError::BadHeader.errno(), Errno::Euclean);
    assert_eq!(CompressError::Decode.errno(), Errno::Eio);
    assert_eq!(CompressError::ShortOutput.errno(), Errno::Eio);
}

#[test]
fn a_geometry_exists_for_every_codec_the_format_names_and_no_other() {
    // The structural guarantee behind the errno: a geometry is built only
    // where a decoder exists, so there is no path on which a cluster's stored
    // bytes could be handed to nothing and mistaken for the file's.
    for n in 0..=255u8 {
        match Geometry::new(n, 2, 0) {
            Ok(g) => {
                assert!(n < COMPRESS_MAX, "number {n} produced a geometry");
                assert!(g.algorithm().unpacks(), "number {n} has no decoder");
            }
            Err(CompressError::UnknownAlgorithm(m)) => {
                assert_eq!(m, n);
                assert!(n >= COMPRESS_MAX, "number {n} names a codec");
            }
            Err(e) => panic!("number {n}: unexpected {e:?}"),
        }
    }
}

#[test]
fn a_zstd_cluster_round_trips_at_every_width_the_format_admits() {
    // A cluster wider than 32 blocks is a MULTI-block frame for this codec,
    // which is where a per-block encoder would silently write something with
    // a worse ratio than the level asked for, and where a decoder that lost
    // its tables across a block boundary would produce garbage.
    for log in MIN_COMPRESS_LOG_SIZE..=MAX_COMPRESS_LOG_SIZE {
        let g = Geometry::new(COMPRESS_ZSTD, log, 0).unwrap();
        assert_eq!(g.algorithm(), Algorithm::Zstd);
        let plain = patterned(g.bytes());
        let Stored::Compressed(img) = encode::compress_cluster(&g, &plain).unwrap() else {
            panic!("log {log}: a patterned cluster did not compress");
        };
        assert!(img.blocks < g.blocks(), "log {log}: {} blocks", img.blocks);
        assert_eq!(decompress_cluster(&g, &img.bytes).unwrap().data, plain, "log {log}");
    }
}

#[test]
fn a_zstd_cluster_the_codec_refuses_reports_a_read_error() {
    // Not a claim about the build: the bytes are not a frame, so the volume
    // is what is wrong.
    let g = Geometry::new(COMPRESS_ZSTD, 2, 0).unwrap();
    let e = decompress_cluster(&g, &image(&[0xFFu8; 64], 0)).unwrap_err();
    assert_eq!(e, CompressError::Decode);
    assert_eq!(e.errno(), Errno::Eio);
}

#[test]
fn the_stored_level_picks_an_effort_and_zero_means_the_default() {
    use crate::compress::zstd::{effort, DEFAULT_LEVEL, DEFAULT_MAX_LEVEL, FAST_MAX_LEVEL};
    // Zero is not a level the format has; it is what a file written without
    // asking for one carries, and it must land where level one does.
    assert_eq!(effort(0), effort(DEFAULT_LEVEL));
    for l in 1..=FAST_MAX_LEVEL { assert_eq!(effort(l), zstd::Level::Fast, "level {l}"); }
    for l in FAST_MAX_LEVEL + 1..=DEFAULT_MAX_LEVEL {
        assert_eq!(effort(l), zstd::Level::Default, "level {l}");
    }
    for l in DEFAULT_MAX_LEVEL + 1..=255 {
        assert_eq!(effort(l), zstd::Level::Best, "level {l}");
    }
}

#[test]
fn a_zstd_cluster_round_trips_at_every_level_the_codec_admits() {
    for level in 0..=crate::compress::policy::ZSTD_MAX_LEVEL {
        let g = Geometry::new(COMPRESS_ZSTD, 4, (level as u16) << 8).unwrap();
        assert_eq!(g.level(), level);
        let plain = patterned(g.bytes());
        let Stored::Compressed(img) = encode::compress_cluster(&g, &plain).unwrap() else {
            panic!("level {level}: a patterned cluster did not compress");
        };
        assert_eq!(decompress_cluster(&g, &img.bytes).unwrap().data, plain, "level {level}");
    }
}

fn lz4_cluster(log: u8, flag: u16, plain: &[u8]) -> (Geometry, Vec<u8>) {
    let g = Geometry::new(COMPRESS_LZ4, log, flag).unwrap();
    let cdata = lz4_compress(plain);
    let sum = if flag & CHKSUM_FLAG != 0 { checksum::crc32(&cdata) } else { 0 };
    (g, image(&cdata, sum))
}

#[test]
fn a_compressed_cluster_becomes_the_bytes_it_was_made_from() {
    let plain = patterned(4 * BLKSIZE);
    let (g, img) = lz4_cluster(2, 0, &plain);
    let out = decompress_cluster(&g, &img).unwrap();
    assert_eq!(out.data, plain);
    assert_eq!(out.chksum, Chksum::Absent);
}

#[test]
fn every_admitted_cluster_width_round_trips() {
    for log in 2u8..=6 {
        let plain = patterned((1usize << log) * BLKSIZE);
        let (g, img) = lz4_cluster(log, 0, &plain);
        let out = decompress_cluster(&g, &img).unwrap();
        assert_eq!(out.data.len(), (1usize << log) * BLKSIZE, "log {log}");
        assert_eq!(out.data, plain, "log {log}");
    }
}

#[test]
fn a_cluster_always_yields_a_whole_cluster_even_at_the_end_of_a_file() {
    // The image holds four blocks of plain bytes whatever the file's size is;
    // where the file stops is the inode's business, not the codec's.
    let plain = patterned(4 * BLKSIZE);
    let (g, img) = lz4_cluster(2, 0, &plain);
    assert_eq!(decompress_cluster(&g, &img).unwrap().data.len(), 4 * BLKSIZE);
}

#[test]
fn a_cluster_with_no_image_reads_as_zeroes() {
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let out = decompress_cluster(&g, &[]).unwrap();
    assert_eq!(out.data, vec![0u8; 4 * BLKSIZE]);
    assert_eq!(out.chksum, Chksum::Absent);
}

#[test]
fn a_cluster_with_no_image_is_a_whole_cluster_of_zeroes_at_every_width() {
    for log in 2u8..=8 {
        let g = Geometry::new(COMPRESS_LZ4, log, 0).unwrap();
        let out = decompress_cluster(&g, &[]).unwrap();
        assert_eq!(out.data.len(), (1usize << log) * BLKSIZE, "log {log}");
        assert!(out.data.iter().all(|&b| b == 0), "log {log}");
    }
}

#[test]
fn a_checksum_that_agrees_is_reported_as_agreeing() {
    let plain = patterned(4 * BLKSIZE);
    let (g, img) = lz4_cluster(2, CHKSUM_FLAG, &plain);
    let out = decompress_cluster(&g, &img).unwrap();
    assert_eq!(out.chksum, Chksum::Ok);
    assert_eq!(out.data, plain);
}

#[test]
fn a_checksum_that_disagrees_is_reported_and_the_bytes_still_come_back() {
    let plain = patterned(4 * BLKSIZE);
    let g = Geometry::new(COMPRESS_LZ4, 2, CHKSUM_FLAG).unwrap();
    let cdata = lz4_compress(&plain);
    let real = checksum::crc32(&cdata);
    let img = image(&cdata, real ^ 1);
    let out = decompress_cluster(&g, &img).unwrap();
    assert_eq!(out.chksum, Chksum::Mismatch { stored: real ^ 1, computed: real });
    assert_eq!(out.data, plain);
}

#[test]
fn a_stored_checksum_is_ignored_when_the_file_does_not_ask_for_one() {
    let plain = patterned(4 * BLKSIZE);
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let img = image(&lz4_compress(&plain), 0x1234_5678);
    assert_eq!(decompress_cluster(&g, &img).unwrap().chksum, Chksum::Absent);
}

#[test]
fn the_checksum_covers_the_compressed_bytes_and_not_the_padding() {
    let plain = patterned(4 * BLKSIZE);
    let cdata = lz4_compress(&plain);
    let g = Geometry::new(COMPRESS_LZ4, 2, CHKSUM_FLAG).unwrap();
    let mut img = image(&cdata, checksum::crc32(&cdata));
    // Scribble on the block padding past the stored length.
    let at = img.len() - 1;
    img[at] = 0xff;
    assert_eq!(decompress_cluster(&g, &img).unwrap().chksum, Chksum::Ok);
}

#[test]
fn a_length_that_disagrees_with_the_bytes_after_it_is_refused() {
    let plain = patterned(4 * BLKSIZE);
    let cdata = lz4_compress(&plain);
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    // One byte short: the codec is handed a block that stops mid-sequence.
    let short = image_with_clen(&cdata, cdata.len() as u32 - 1, 0);
    assert_eq!(decompress_cluster(&g, &short), Err(CompressError::Decode));
    // One byte long: the padding byte becomes part of the block, which no
    // longer ends where the format says it must.
    let long = image_with_clen(&cdata, cdata.len() as u32 + 1, 0);
    assert_eq!(decompress_cluster(&g, &long), Err(CompressError::Decode));
}

#[test]
fn a_length_past_the_stored_blocks_is_refused_before_the_codec_runs() {
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let img = image_with_clen(&[0u8; 16], 100_000, 0);
    assert_eq!(decompress_cluster(&g, &img), Err(CompressError::BadHeader));
}

#[test]
fn an_image_that_decodes_to_less_than_a_cluster_is_refused() {
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let img = image(&lz4_literals(&patterned(100)), 0);
    assert_eq!(decompress_cluster(&g, &img), Err(CompressError::ShortOutput));
}

#[test]
fn an_image_that_decodes_to_more_than_a_cluster_is_refused() {
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let img = image(&lz4_compress(&patterned(5 * BLKSIZE)), 0);
    assert_eq!(decompress_cluster(&g, &img), Err(CompressError::Decode));
}

#[test]
fn a_damaged_image_never_returns_the_stored_bytes_as_the_file() {
    let plain = patterned(4 * BLKSIZE);
    let cdata = lz4_compress(&plain);
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    for at in [0usize, 1, 3, 17, cdata.len() / 2] {
        let mut bad = cdata.clone();
        bad[at] ^= 0xff;
        let img = image(&bad, 0);
        match decompress_cluster(&g, &img) {
            Err(_) => {}
            Ok(out) => assert_ne!(out.data[..bad.len()], bad[..], "at {at}"),
        }
    }
}

#[test]
fn an_lzo_cluster_round_trips() {
    let g = Geometry::new(COMPRESS_LZO, 2, 0).unwrap();
    let img = image(&lzo_uniform(4 * BLKSIZE, 0x5a), 0);
    assert_eq!(decompress_cluster(&g, &img).unwrap().data, vec![0x5au8; 4 * BLKSIZE]);
}

#[test]
fn a_run_length_cluster_uses_the_same_reader() {
    let g = Geometry::new(COMPRESS_LZORLE, 3, 0).unwrap();
    let img = image(&lzo_uniform(8 * BLKSIZE, 0x77), 0);
    assert_eq!(decompress_cluster(&g, &img).unwrap().data, vec![0x77u8; 8 * BLKSIZE]);
}

#[test]
fn an_lzo_cluster_carries_its_checksum_the_same_way() {
    let g = Geometry::new(COMPRESS_LZO, 2, CHKSUM_FLAG).unwrap();
    let cdata = lzo_uniform(4 * BLKSIZE, 0x21);
    let img = image(&cdata, checksum::crc32(&cdata));
    assert_eq!(decompress_cluster(&g, &img).unwrap().chksum, Chksum::Ok);
}

#[test]
fn an_lzo_image_that_decodes_short_is_refused() {
    let g = Geometry::new(COMPRESS_LZO, 2, 0).unwrap();
    let img = image(&lzo_uniform(BLKSIZE, 0x5a), 0);
    assert_eq!(decompress_cluster(&g, &img), Err(CompressError::ShortOutput));
}

#[test]
fn a_cluster_written_by_one_codec_is_not_read_by_another() {
    // Same bytes, wrong codec: a refusal, never a plausible-looking cluster.
    let cdata = lzo_uniform(4 * BLKSIZE, 0x5a);
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let img = image(&cdata, 0);
    match decompress_cluster(&g, &img) {
        Err(_) => {}
        Ok(out) => assert_ne!(out.data, vec![0x5au8; 4 * BLKSIZE]),
    }
}
