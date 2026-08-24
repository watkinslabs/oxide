//! Whole clusters, from plain bytes to the image the medium stores.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_MAX,
                            COMPRESS_ZSTD};
use crate::compress::cluster::COMPRESS_HEADER_SIZE;
use crate::compress::{
    decompress_cluster, decompress_cluster_into, encode, max_clen, Chksum, CompressError,
    Geometry, Stored,
};
use crate::uapi::{le32, BLKSIZE};

const CHKSUM_FLAG: u16 = 1;

/// Every codec this build writes. # C: O(1)
const CODECS: [u8; 4] = [COMPRESS_LZO, COMPRESS_LZ4, COMPRESS_LZORLE, COMPRESS_ZSTD];

/// # C: O(n)
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 11) as u8
        })
        .collect()
}

/// Bytes that compress well, of exactly one cluster. # C: O(bytes)
fn patterned(g: &Geometry) -> Vec<u8> {
    (0..g.bytes()).map(|i| ((i / 64) % 11) as u8).collect()
}

#[test]
fn a_compressible_cluster_comes_back_as_the_bytes_it_went_in_as() {
    for algo in CODECS {
        for log in 2u8..=8 {
            let g = Geometry::new(algo, log, 0).unwrap();
            let plain = patterned(&g);
            let Stored::Compressed(img) = encode::compress_cluster(&g, &plain).unwrap() else {
                panic!("codec {algo} log {log} refused compressible bytes");
            };
            assert_eq!(img.bytes.len(), img.blocks * BLKSIZE, "image is whole blocks");
            assert!(img.blocks < g.blocks(), "codec {algo} log {log} saved nothing");
            let back = decompress_cluster(&g, &img.bytes).unwrap();
            assert_eq!(back.data, plain, "codec {algo} log {log}");
        }
    }
}

#[test]
fn speculative_decompression_can_reuse_one_preallocated_destination() {
    let mut scratch = vec![0u8; 8 * BLKSIZE];
    let ptr = scratch.as_mut_ptr();
    for algo in CODECS {
        let g = Geometry::new(algo, 2, 0).unwrap();
        let plain = patterned(&g);
        let Stored::Compressed(img) = encode::compress_cluster(&g, &plain).unwrap() else {
            panic!("codec {algo} refused compressible input");
        };
        assert_eq!(decompress_cluster_into(&g, &img.bytes, &mut scratch).unwrap(), Chksum::Absent);
        assert_eq!(&scratch[..g.bytes()], &plain);
        assert_eq!(scratch.as_mut_ptr(), ptr, "readahead context moved");
    }
}

#[test]
fn a_cluster_that_does_not_shrink_by_a_whole_block_is_stored_plain() {
    for algo in CODECS {
        for log in 2u8..=8 {
            let g = Geometry::new(algo, log, 0).unwrap();
            let plain = noise(g.bytes(), (algo as u32) << 8 | log as u32);
            assert_eq!(
                encode::compress_cluster(&g, &plain).unwrap(),
                Stored::Plain,
                "codec {algo} log {log}"
            );
        }
    }
}

#[test]
fn the_budget_is_one_block_less_than_the_cluster_minus_the_header() {
    for log in 2u8..=8 {
        let g = Geometry::new(COMPRESS_LZ4, log, 0).unwrap();
        assert_eq!(max_clen(&g), (g.blocks() - 1) * BLKSIZE - COMPRESS_HEADER_SIZE);
    }
}

#[test]
fn an_image_that_exactly_fills_the_budget_is_kept() {
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let img = encode::image(&g, &noise(max_clen(&g), 5));
    assert_eq!(img.blocks, g.blocks() - 1);
    assert_eq!(img.clen, max_clen(&g));
}

#[test]
fn the_header_records_the_length_the_reader_hands_the_codec() {
    let g = Geometry::new(COMPRESS_LZ4, 3, 0).unwrap();
    let plain = patterned(&g);
    let Stored::Compressed(img) = encode::compress_cluster(&g, &plain).unwrap() else {
        panic!("refused");
    };
    assert_eq!(le32(&img.bytes, 0), Some(img.clen as u32));
    // The last block's tail is padding, and the length is what keeps it out
    // of the codec's hands.
    assert!(img.bytes[COMPRESS_HEADER_SIZE + img.clen..].iter().all(|&b| b == 0));
}

#[test]
fn the_reserved_words_are_zero() {
    let g = Geometry::new(COMPRESS_LZO, 2, 0).unwrap();
    let img = encode::image(&g, b"abcd");
    assert!(img.bytes[8..COMPRESS_HEADER_SIZE].iter().all(|&b| b == 0));
}

#[test]
fn a_checksum_is_written_only_when_the_file_asks_for_one() {
    let plain = {
        let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
        patterned(&g)
    };
    for algo in CODECS {
        let off = Geometry::new(algo, 2, 0).unwrap();
        let on = Geometry::new(algo, 2, CHKSUM_FLAG).unwrap();
        let Stored::Compressed(a) = encode::compress_cluster(&off, &plain).unwrap() else {
            panic!("refused")
        };
        let Stored::Compressed(b) = encode::compress_cluster(&on, &plain).unwrap() else {
            panic!("refused")
        };
        assert_eq!(le32(&a.bytes, 4), Some(0), "codec {algo} wrote a checksum unasked");
        let stored = le32(&b.bytes, 4).unwrap();
        assert_eq!(
            stored,
            crate::checksum::crc32(&b.bytes[COMPRESS_HEADER_SIZE..COMPRESS_HEADER_SIZE + b.clen])
        );
        assert_eq!(decompress_cluster(&on, &b.bytes).unwrap().chksum, Chksum::Ok);
        assert_eq!(decompress_cluster(&off, &a.bytes).unwrap().chksum, Chksum::Absent);
    }
}

#[test]
fn a_damaged_checksum_is_reported_rather_than_hidden() {
    let g = Geometry::new(COMPRESS_LZ4, 2, CHKSUM_FLAG).unwrap();
    let plain = patterned(&g);
    let Stored::Compressed(mut img) = encode::compress_cluster(&g, &plain).unwrap() else {
        panic!("refused")
    };
    img.bytes[4] ^= 0xff;
    assert!(matches!(
        decompress_cluster(&g, &img.bytes).unwrap().chksum,
        Chksum::Mismatch { .. }
    ));
}

#[test]
fn bytes_that_are_not_a_whole_cluster_are_refused() {
    let g = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    for n in [0usize, 1, BLKSIZE, g.bytes() - 1, g.bytes() + 1] {
        assert_eq!(
            encode::compress_cluster(&g, &vec![0u8; n]),
            Err(CompressError::NotAWholeCluster),
            "length {n}"
        );
    }
}

#[test]
fn a_codec_number_the_format_does_not_name_is_refused_before_a_geometry_exists() {
    assert_eq!(Geometry::new(COMPRESS_MAX, 2, 0),
               Err(CompressError::UnknownAlgorithm(COMPRESS_MAX)));
}

#[test]
fn a_cluster_of_zeroes_compresses_for_every_codec() {
    for algo in CODECS {
        let g = Geometry::new(algo, 4, 0).unwrap();
        let plain = vec![0u8; g.bytes()];
        let Stored::Compressed(img) = encode::compress_cluster(&g, &plain).unwrap() else {
            panic!("codec {algo} refused a cluster of zeroes");
        };
        assert_eq!(img.blocks, 1, "codec {algo} needed {} blocks", img.blocks);
        assert_eq!(decompress_cluster(&g, &img.bytes).unwrap().data, plain);
    }
}
