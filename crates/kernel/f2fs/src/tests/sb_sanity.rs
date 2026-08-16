//! Whether a superblock's fields can describe a real volume.
//!
//! Each test breaks exactly ONE field of an otherwise valid copy, so a check
//! that stopped firing would show up as one failure rather than as a suite
//! that still passes for a different reason.

use super::*;
use crate::sb::parse;
use crate::uapi::*;
use crate::test_image::meta::{self, put32, put64};
use crate::test_image::Builder;
use alloc::vec::Vec;

/// A valid copy's bytes.
fn good() -> Vec<u8> { meta::super_bytes(&Builder::new()) }

/// Reseal a copy after breaking a field, so the CRC is not what fails.
fn reseal(b: &mut [u8]) {
    let crc = crate::checksum::crc32(&b[..SB_CRC]);
    put32(b, SB_CRC, crc);
}

/// Check a copy after breaking one field and resealing.
fn after(f: impl FnOnce(&mut Vec<u8>)) -> Result<(), SbError> {
    let mut b = good();
    f(&mut b);
    reseal(&mut b);
    let s = parse(&b).expect("still parses");
    check(&s, &b)
}

#[test]
fn a_fixture_copy_passes_every_check() {
    let b = good();
    assert_eq!(check(&parse(&b).unwrap(), &b), Ok(()));
}

#[test]
fn a_broken_crc_is_rejected_when_the_volume_claims_one() {
    let mut b = good();
    b[SB_SEGMENT_COUNT] ^= 0xFF;
    assert_eq!(check(&parse(&b).unwrap(), &b), Err(SbError::Checksum));
}

#[test]
fn a_volume_without_the_checksum_feature_is_not_checksum_checked() {
    // An older volume carries a zero there; refusing it would refuse every
    // filesystem formatted before the feature existed.
    let mut b = good();
    put32(&mut b, SB_FEATURE, 0);
    put32(&mut b, SB_CRC, 0);
    assert_eq!(check(&parse(&b).unwrap(), &b), Ok(()));
}

#[test]
fn a_block_size_this_build_does_not_read_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_LOG_BLOCKSIZE, 14)), Err(SbError::BlockSize));
}

#[test]
fn a_segment_size_the_format_does_not_fix_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_LOG_BLOCKS_PER_SEG, 10)), Err(SbError::SegmentSize));
}

#[test]
fn a_sector_smaller_than_the_format_allows_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_LOG_SECTORSIZE, 8)), Err(SbError::SectorSize));
}

#[test]
fn a_sector_wider_than_a_block_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_LOG_SECTORSIZE, 13)), Err(SbError::SectorSize));
}

#[test]
fn a_sector_count_that_does_not_compose_the_block_is_rejected() {
    // The two logs must sum to the block's log exactly: a sector count that
    // says otherwise describes a block that is not the block size.
    assert_eq!(
        after(|b| { put32(b, SB_LOG_SECTORSIZE, 9); put32(b, SB_LOG_SECTORS_PER_BLOCK, 2); }),
        Err(SbError::SectorSize)
    );
}

#[test]
fn a_sector_count_that_does_compose_the_block_is_accepted() {
    let mut b = good();
    put32(&mut b, SB_LOG_SECTORSIZE, 9);
    put32(&mut b, SB_LOG_SECTORS_PER_BLOCK, 3);
    reseal(&mut b);
    assert_eq!(check(&parse(&b).unwrap(), &b), Ok(()));
}

#[test]
fn a_volume_with_too_few_segments_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_SEGMENT_COUNT, MIN_SEGMENTS - 1)), Err(SbError::Counts));
}

#[test]
fn a_volume_with_more_segments_than_the_address_can_reach_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_SEGMENT_COUNT, MAX_SEGMENT + 1)), Err(SbError::Counts));
}

#[test]
fn a_zero_segments_per_section_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_SEGS_PER_SEC, 0)), Err(SbError::Counts));
}

#[test]
fn a_section_count_that_does_not_multiply_out_is_rejected() {
    // Main segments must be exactly sections times segments-per-section.
    assert_eq!(after(|b| put32(b, SB_SECTION_COUNT, 1)), Err(SbError::Counts));
}

#[test]
fn a_zero_sections_per_zone_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_SECS_PER_ZONE, 0)), Err(SbError::Counts));
}

#[test]
fn more_zones_than_sections_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_SECS_PER_ZONE, 99)), Err(SbError::Counts));
}

#[test]
fn a_block_count_too_small_for_the_segments_is_rejected() {
    assert_eq!(after(|b| put64(b, SB_BLOCK_COUNT, 1024)), Err(SbError::Blocks));
}

#[test]
fn a_device_list_whose_segments_do_not_sum_to_the_total_is_rejected() {
    assert_eq!(
        after(|b| {
            b[SB_DEVS] = b'/';
            put32(b, SB_DEVS + DEV_PATH_LEN, 1);
        }),
        Err(SbError::Counts)
    );
}

#[test]
fn a_device_list_whose_segments_do_sum_is_accepted() {
    let mut b = good();
    b[SB_DEVS] = b'/';
    put32(&mut b, SB_DEVS + DEV_PATH_LEN, crate::test_image::SEGMENT_COUNT);
    reseal(&mut b);
    assert_eq!(check(&parse(&b).unwrap(), &b), Ok(()));
}

#[test]
fn an_extension_count_past_the_array_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_EXTENSION_COUNT, MAX_EXTENSION + 1)), Err(SbError::Extensions));
}

#[test]
fn the_two_extension_counts_are_checked_together() {
    // Either alone fits; together they overrun the one array they share.
    assert_eq!(
        after(|b| { put32(b, SB_EXTENSION_COUNT, 40); b[SB_HOT_EXT_COUNT] = 40; }),
        Err(SbError::Extensions)
    );
}

#[test]
fn a_payload_leaving_no_room_for_the_pack_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_CP_PAYLOAD, BLKS_PER_SEG)), Err(SbError::CpPayload));
}

#[test]
fn the_three_reserved_inode_numbers_must_be_the_fixed_ones() {
    assert_eq!(after(|b| put32(b, SB_ROOT_INO, 4)), Err(SbError::ReservedIno));
    assert_eq!(after(|b| put32(b, SB_NODE_INO, 9)), Err(SbError::ReservedIno));
    assert_eq!(after(|b| put32(b, SB_META_INO, 9)), Err(SbError::ReservedIno));
}

#[test]
fn segment_zero_must_be_where_the_checkpoint_starts() {
    assert_eq!(after(|b| put32(b, SB_SEGMENT0_BLKADDR, 4)), Err(SbError::AreaBoundary));
}

#[test]
fn the_checkpoint_area_must_end_where_the_segment_table_begins() {
    assert_eq!(after(|b| put32(b, SB_SEGMENT_COUNT_CKPT, 1)), Err(SbError::AreaBoundary));
}

#[test]
fn the_segment_table_must_end_where_the_node_table_begins() {
    assert_eq!(after(|b| put32(b, SB_SIT_BLKADDR, crate::test_image::SIT_BLKADDR + 1)),
               Err(SbError::AreaBoundary));
}

#[test]
fn the_node_table_must_end_where_the_summary_area_begins() {
    assert_eq!(after(|b| put32(b, SB_SEGMENT_COUNT_NAT, 3)), Err(SbError::AreaBoundary));
}

#[test]
fn the_summary_area_must_end_where_the_main_area_begins() {
    assert_eq!(after(|b| put32(b, SB_SEGMENT_COUNT_SSA, 2)), Err(SbError::AreaBoundary));
}

#[test]
fn a_main_area_running_past_the_volume_is_rejected() {
    assert_eq!(after(|b| put32(b, SB_MAIN_BLKADDR, crate::test_image::MAIN_BLKADDR + 512)),
               Err(SbError::AreaBoundary));
}

#[test]
fn a_main_area_stopping_short_of_the_volume_is_accepted() {
    // A formatter that rounded down leaves the tail unused; that is not
    // corruption, and refusing it would refuse volumes the reference mounts.
    let mut b = good();
    put32(&mut b, SB_SEGMENT_COUNT, crate::test_image::SEGMENT_COUNT + 1);
    put64(&mut b, SB_BLOCK_COUNT, crate::test_image::BLOCK_COUNT + 1024);
    reseal(&mut b);
    assert_eq!(check(&parse(&b).unwrap(), &b), Ok(()));
}

#[test]
fn access_reports_what_the_feature_word_permits() {
    let b = good();
    assert_eq!(access(&parse(&b).unwrap()), Ok(crate::features::Access::ReadWrite));
}

#[test]
fn access_refuses_a_bit_that_changes_how_names_resolve() {
    let mut b = good();
    put32(&mut b, SB_FEATURE, crate::flags::FEATURE_CASEFOLD);
    reseal(&mut b);
    assert!(access(&parse(&b).unwrap()).is_err());
}

#[test]
fn access_ignores_a_bit_it_does_not_recognise() {
    let mut b = good();
    put32(&mut b, SB_FEATURE, 1 << 25);
    reseal(&mut b);
    assert_eq!(access(&parse(&b).unwrap()), Ok(crate::features::Access::ReadWrite));
}
