//! Reading a superblock copy's fields out of its bytes.

use super::*;
use crate::test_image::meta;
use crate::test_image::{self, Builder};

/// The bytes of a fixture volume's superblock copy.
fn bytes() -> alloc::vec::Vec<u8> { meta::super_bytes(&Builder::new()) }

#[test]
fn a_fixture_copy_parses() {
    assert!(parse(&bytes()).is_some());
}

#[test]
fn a_slice_shorter_than_a_superblock_does_not_parse() {
    let mut b = bytes();
    b.truncate(SUPER_SIZE - 1);
    assert_eq!(parse(&b), None);
}

#[test]
fn a_wrong_magic_does_not_parse() {
    let mut b = bytes();
    b[SB_MAGIC] ^= 0xFF;
    assert_eq!(parse(&b), None);
}

#[test]
fn geometry_reads_back_what_the_fixture_wrote() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.log_blocksize, BLKSIZE_BITS);
    assert_eq!(s.log_blocks_per_seg, LOG_BLKS_PER_SEG);
    assert_eq!(s.segment_count, test_image::SEGMENT_COUNT);
    assert_eq!(s.segment_count_main, test_image::SEG_MAIN);
    assert_eq!(s.block_count, test_image::BLOCK_COUNT);
}

#[test]
fn the_five_area_addresses_read_back() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.segment0_blkaddr, test_image::CP_BLKADDR);
    assert_eq!(s.cp_blkaddr, test_image::CP_BLKADDR);
    assert_eq!(s.sit_blkaddr, test_image::SIT_BLKADDR);
    assert_eq!(s.nat_blkaddr, test_image::NAT_BLKADDR);
    assert_eq!(s.ssa_blkaddr, test_image::SSA_BLKADDR);
    assert_eq!(s.main_blkaddr, test_image::MAIN_BLKADDR);
}

#[test]
fn the_three_reserved_inode_numbers_read_back() {
    let s = parse(&bytes()).unwrap();
    assert_eq!((s.node_ino, s.meta_ino, s.root_ino), (1, 2, 3));
}

#[test]
fn the_uuid_reads_back_whole() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.uuid, [0x5A; SB_UUID_LEN]);
}

#[test]
fn the_volume_name_is_utf16_and_stops_at_its_first_zero() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.volume_name, "oxide");
}

#[test]
fn a_volume_name_filling_the_field_is_not_truncated_early() {
    let mut b = bytes();
    for i in 0..SB_VOLUME_NAME_UNITS {
        b[SB_VOLUME_NAME + i * 2..SB_VOLUME_NAME + i * 2 + 2]
            .copy_from_slice(&u16::from(b'x').to_le_bytes());
    }
    let s = parse(&b).unwrap();
    assert_eq!(s.volume_name.len(), SB_VOLUME_NAME_UNITS);
}

#[test]
fn an_unpaired_surrogate_in_the_name_is_replaced_not_refused() {
    let mut b = bytes();
    b[SB_VOLUME_NAME..SB_VOLUME_NAME + 2].copy_from_slice(&0xD800u16.to_le_bytes());
    b[SB_VOLUME_NAME + 2..SB_VOLUME_NAME + 4].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(parse(&b).unwrap().volume_name, "\u{FFFD}");
}

#[test]
fn the_extension_list_reads_back_trimmed_at_each_entrys_zero() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.extension_count, 2);
    assert_eq!(s.extensions, ["jpg", "mp4"]);
}

#[test]
fn an_absurd_extension_count_does_not_read_past_the_array() {
    // The count is checked in `sanity`; parsing must still not overrun.
    let mut b = bytes();
    b[SB_EXTENSION_COUNT..SB_EXTENSION_COUNT + 4].copy_from_slice(&9999u32.to_le_bytes());
    let s = parse(&b).unwrap();
    assert_eq!(s.extension_count, 9999);
    assert_eq!(s.extensions.len(), MAX_EXTENSION as usize);
}

#[test]
fn a_volume_listing_no_devices_reports_none() {
    let s = parse(&bytes()).unwrap();
    assert!(s.devices.is_empty());
    assert!(!s.multi_device());
}

#[test]
fn a_two_device_list_reads_both_and_stops_at_the_empty_path() {
    let mut b = bytes();
    b[SB_DEVS] = b'/';
    b[SB_DEVS + DEV_PATH_LEN..SB_DEVS + DEV_PATH_LEN + 4].copy_from_slice(&4u32.to_le_bytes());
    let at = SB_DEVS + DEV_ENTRY_SIZE;
    b[at] = b'/';
    b[at + DEV_PATH_LEN..at + DEV_PATH_LEN + 4].copy_from_slice(&5u32.to_le_bytes());
    let s = parse(&b).unwrap();
    assert_eq!(s.devices.iter().map(|d| d.total_segments).collect::<alloc::vec::Vec<_>>(),
               [4, 5]);
    assert_eq!(s.devices[0].path, "/");
    assert!(s.multi_device());
}

#[test]
fn the_encoding_fields_read_back() {
    let mut b = bytes();
    b[SB_S_ENCODING..SB_S_ENCODING + 2].copy_from_slice(&ENC_UTF8_12_1.to_le_bytes());
    b[SB_S_ENCODING_FLAGS..SB_S_ENCODING_FLAGS + 2].copy_from_slice(&3u16.to_le_bytes());
    let s = parse(&b).unwrap();
    assert_eq!(s.s_encoding, ENC_UTF8_12_1);
    assert_eq!(s.s_encoding_flags, 3);
}

#[test]
fn the_checksum_offset_and_crc_read_back() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.checksum_offset, SB_CRC as u32);
    assert_ne!(s.crc, 0);
}

#[test]
fn blks_per_seg_follows_the_stored_log() {
    assert_eq!(parse(&bytes()).unwrap().blks_per_seg(), BLKS_PER_SEG);
}

#[test]
fn max_blkaddr_is_the_first_block_past_the_volume() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.max_blkaddr(), test_image::BLOCK_COUNT);
}

#[test]
fn main_area_membership_is_exclusive_at_the_top() {
    let s = parse(&bytes()).unwrap();
    let end = test_image::MAIN_BLKADDR + test_image::SEG_MAIN * BLKS_PER_SEG;
    assert!(!s.valid_main_blkaddr(test_image::MAIN_BLKADDR - 1));
    assert!(s.valid_main_blkaddr(test_image::MAIN_BLKADDR));
    assert!(s.valid_main_blkaddr(end - 1));
    assert!(!s.valid_main_blkaddr(end));
}

#[test]
fn a_metadata_address_is_not_in_the_main_area() {
    let s = parse(&bytes()).unwrap();
    for addr in [0, 1, test_image::CP_BLKADDR, test_image::NAT_BLKADDR, test_image::SSA_BLKADDR] {
        assert!(!s.valid_main_blkaddr(addr), "{addr} should not be main");
    }
}

#[test]
fn segno_of_splits_the_main_area_by_segment() {
    let s = parse(&bytes()).unwrap();
    assert_eq!(s.segno_of(test_image::MAIN_BLKADDR), Some(0));
    assert_eq!(s.segno_of(test_image::MAIN_BLKADDR + BLKS_PER_SEG - 1), Some(0));
    assert_eq!(s.segno_of(test_image::MAIN_BLKADDR + BLKS_PER_SEG), Some(1));
    assert_eq!(s.segno_of(0), None);
}
