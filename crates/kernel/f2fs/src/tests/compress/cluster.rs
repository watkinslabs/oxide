//! Cluster geometry, the stored header, and which of a cluster's addresses
//! hold its image.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_ZSTD};
use crate::compress::cluster::{data_blocks, header, Geometry, COMPRESS_HEADER_SIZE};
use crate::compress::CompressError;
use crate::uapi::{BLKSIZE, COMPRESS_ADDR, NEW_ADDR, NULL_ADDR};

use super::build::image_with_clen;

fn geom(log: u8) -> Geometry { Geometry::new(COMPRESS_LZ4, log, 0).unwrap() }

#[test]
fn the_header_is_a_length_a_checksum_and_a_reservation() {
    assert_eq!(COMPRESS_HEADER_SIZE, 24);
}

#[test]
fn a_cluster_is_two_to_the_stored_log_blocks_wide() {
    for log in 2u8..=8 {
        let g = geom(log);
        assert_eq!(g.blocks(), 1usize << log, "log {log}");
        assert_eq!(g.bytes(), (1usize << log) * BLKSIZE, "log {log}");
        assert_ne!(g.blocks(), log as usize, "log {log}");
    }
}

#[test]
fn a_log_outside_what_the_format_admits_is_refused() {
    for log in [0u8, 1, 9, 16, 255] {
        assert_eq!(
            Geometry::new(COMPRESS_LZ4, log, 0),
            Err(CompressError::BadClusterSize(log)),
            "log {log}"
        );
    }
}

#[test]
fn an_unpackable_codec_is_refused_before_any_geometry_is_built() {
    assert!(matches!(
        Geometry::new(COMPRESS_ZSTD, 2, 0),
        Err(CompressError::UnsupportedAlgorithm(_))
    ));
}

#[test]
fn a_block_index_maps_to_its_cluster() {
    let g = geom(2);
    for (index, cluster) in [(0u64, 0u64), (1, 0), (3, 0), (4, 1), (7, 1), (8, 2), (4095, 1023)] {
        assert_eq!(g.cluster_of(index), cluster, "index {index}");
    }
}

#[test]
fn a_block_index_maps_to_its_clusters_first_block() {
    for log in 2u8..=8 {
        let g = geom(log);
        let width = 1u64 << log;
        for index in [0u64, 1, width - 1, width, width + 1, width * 5 + 2] {
            assert_eq!(g.first_block(index), (index / width) * width, "log {log} index {index}");
        }
    }
}

#[test]
fn a_block_index_maps_to_its_offset_inside_the_cluster() {
    let g = geom(3);
    assert_eq!(g.offset_in_cluster(0), 0);
    assert_eq!(g.offset_in_cluster(1), BLKSIZE);
    assert_eq!(g.offset_in_cluster(7), 7 * BLKSIZE);
    assert_eq!(g.offset_in_cluster(8), 0);
    assert_eq!(g.offset_in_cluster(11), 3 * BLKSIZE);
}

#[test]
fn the_flag_word_separates_the_checksum_bit_from_the_level() {
    let plain = Geometry::new(COMPRESS_LZ4, 2, 0).unwrap();
    let summed = Geometry::new(COMPRESS_LZ4, 2, 1).unwrap();
    let levelled = Geometry::new(COMPRESS_LZ4, 2, 9 << 8).unwrap();
    let both = Geometry::new(COMPRESS_LZ4, 2, (9 << 8) | 1).unwrap();
    assert!(!plain.checksummed() && plain.level() == 0);
    assert!(summed.checksummed() && summed.level() == 0);
    assert!(!levelled.checksummed() && levelled.level() == 9);
    assert!(both.checksummed() && both.level() == 9);
}

#[test]
fn the_image_addresses_are_the_run_after_the_sentinel() {
    let addrs = [COMPRESS_ADDR, 100, 101, 102, NULL_ADDR, NULL_ADDR, NULL_ADDR, NULL_ADDR];
    assert_eq!(data_blocks(&addrs).unwrap(), &[100, 101, 102]);
}

#[test]
fn a_full_cluster_leaves_no_hole_after_the_run() {
    let addrs = [COMPRESS_ADDR, 10, 11, 12];
    assert_eq!(data_blocks(&addrs).unwrap(), &[10, 11, 12]);
}

#[test]
fn a_cluster_whose_blocks_were_released_has_no_image() {
    let addrs = [COMPRESS_ADDR, NULL_ADDR, NULL_ADDR, NULL_ADDR];
    assert_eq!(data_blocks(&addrs).unwrap(), &[] as &[u32]);
}

#[test]
fn a_reserved_but_unwritten_address_ends_the_run() {
    let addrs = [COMPRESS_ADDR, 10, NEW_ADDR, NULL_ADDR];
    assert_eq!(data_blocks(&addrs).unwrap(), &[10]);
}

#[test]
fn a_run_that_does_not_start_with_the_sentinel_is_not_a_cluster() {
    assert_eq!(data_blocks(&[10, 11, 12, 13]), Err(CompressError::NotCompressed));
    assert_eq!(data_blocks(&[NULL_ADDR, 11, 12, 13]), Err(CompressError::NotCompressed));
    assert_eq!(data_blocks(&[]), Err(CompressError::NotCompressed));
}

#[test]
fn a_second_sentinel_inside_one_cluster_is_refused() {
    let addrs = [COMPRESS_ADDR, 10, COMPRESS_ADDR, 11];
    assert_eq!(data_blocks(&addrs), Err(CompressError::BadLayout));
}

#[test]
fn a_live_address_after_the_run_has_ended_is_refused() {
    let addrs = [COMPRESS_ADDR, 10, NULL_ADDR, 11];
    assert_eq!(data_blocks(&addrs), Err(CompressError::BadLayout));
}

#[test]
fn the_header_reports_the_length_and_checksum_it_stores() {
    let payload = [1u8, 2, 3, 4, 5];
    let img = image_with_clen(&payload, 5, 0xdead_beef);
    let (h, cdata) = header(&img).unwrap();
    assert_eq!(h.clen, 5);
    assert_eq!(h.chksum, 0xdead_beef);
    assert_eq!(cdata, &payload);
}

#[test]
fn the_length_word_and_not_the_block_size_bounds_the_payload() {
    // A block's tail is padding; handing it to a codec is how a stored image
    // grows bytes it never had.
    let payload = [7u8; 300];
    let img = image_with_clen(&payload, 300, 0);
    assert_eq!(img.len(), BLKSIZE);
    let (_, cdata) = header(&img).unwrap();
    assert_eq!(cdata.len(), 300);
}

#[test]
fn a_length_past_the_end_of_the_image_is_refused() {
    let img = image_with_clen(&[1u8; 8], (BLKSIZE - COMPRESS_HEADER_SIZE + 1) as u32, 0);
    assert_eq!(header(&img), Err(CompressError::BadHeader));
}

#[test]
fn a_length_of_exactly_the_image_is_accepted() {
    let img = image_with_clen(&[1u8; 8], (BLKSIZE - COMPRESS_HEADER_SIZE) as u32, 0);
    assert_eq!(header(&img).unwrap().1.len(), BLKSIZE - COMPRESS_HEADER_SIZE);
}

#[test]
fn an_image_too_short_to_hold_a_header_is_refused() {
    for n in 0..COMPRESS_HEADER_SIZE {
        let img = vec![0u8; n];
        assert_eq!(header(&img), Err(CompressError::BadHeader), "len {n}");
    }
}

#[test]
fn a_length_of_zero_yields_an_empty_payload() {
    let img = image_with_clen(&[], 0, 0);
    let (h, cdata) = header(&img).unwrap();
    assert_eq!(h.clen, 0);
    assert!(cdata.is_empty());
}

#[test]
fn a_two_block_image_may_carry_a_longer_payload() {
    let payload: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    let img = image_with_clen(&payload, 5000, 0);
    assert_eq!(img.len(), 2 * BLKSIZE);
    assert_eq!(header(&img).unwrap().1, &payload[..]);
}
