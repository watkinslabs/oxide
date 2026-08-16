//! The two headers, and the tree shape they imply.

use crate::quota::info::{self, Revision};
use crate::quota::uapi::*;
use crate::quota::QuotaError;

use super::image;

#[test]
fn each_kind_has_its_own_magic() {
    // Three distinct words; a file of one kind must not parse as another.
    assert_ne!(MAGIC[USRQUOTA], MAGIC[GRPQUOTA]);
    assert_ne!(MAGIC[GRPQUOTA], MAGIC[PRJQUOTA]);
    assert_ne!(MAGIC[USRQUOTA], MAGIC[PRJQUOTA]);
    for kind in [USRQUOTA, GRPQUOTA, PRJQUOTA] {
        let f = image::file(kind, Revision::R1, 2);
        let info = info::parse(&f, kind).expect("own kind parses");
        assert_eq!(info.kind, kind);
    }
}

#[test]
fn a_file_read_as_the_wrong_kind_is_refused() {
    let f = image::file(USRQUOTA, Revision::R1, 2);
    assert_eq!(info::parse(&f, GRPQUOTA), Err(QuotaError::BadMagic));
    assert_eq!(info::parse(&f, PRJQUOTA), Err(QuotaError::BadMagic));
}

#[test]
fn a_kind_outside_the_three_is_refused() {
    let f = image::file(USRQUOTA, Revision::R1, 2);
    assert_eq!(info::parse(&f, MAX_QUOTAS), Err(QuotaError::BadKind));
}

#[test]
fn both_revisions_parse_and_a_later_one_does_not() {
    let f0 = image::file(USRQUOTA, Revision::R0, 2);
    assert_eq!(info::parse(&f0, USRQUOTA).unwrap().revision, Revision::R0);
    let f1 = image::file(USRQUOTA, Revision::R1, 2);
    assert_eq!(info::parse(&f1, USRQUOTA).unwrap().revision, Revision::R1);
    let mut f2 = f1.clone();
    image::put32(&mut f2, DQH_VERSION, MAX_VERSION + 1);
    assert_eq!(info::parse(&f2, USRQUOTA), Err(QuotaError::BadVersion));
}

#[test]
fn the_grace_words_are_read() {
    let f = image::file(USRQUOTA, Revision::R1, 2);
    let info = info::parse(&f, USRQUOTA).unwrap();
    assert_eq!(info.bgrace, 604_800);
    assert_eq!(info.igrace, 604_800);
}

#[test]
fn the_revisions_differ_in_record_width() {
    assert_eq!(Revision::R0.entry_size(), R0_SIZE);
    assert_eq!(Revision::R1.entry_size(), R1_SIZE);
    assert_ne!(R0_SIZE, R1_SIZE);
}

#[test]
fn the_tree_depth_covers_the_whole_identity_space() {
    // Each level consumes eight bits of the id at this block size, so four
    // levels address every four-byte identity and three would not.
    assert_eq!(info::depth_for(QT_BLOCK_SIZE), 4);
    assert_eq!(info::refs_per_block(QT_BLOCK_SIZE), 256);
    let epb = info::refs_per_block(QT_BLOCK_SIZE) as u64;
    assert!(epb.pow(info::depth_for(QT_BLOCK_SIZE)) >= 1u64 << u32::BITS);
    assert!(epb.pow(info::depth_for(QT_BLOCK_SIZE) - 1) < 1u64 << u32::BITS);
}

#[test]
fn a_leaf_holds_what_fits_past_its_header() {
    assert_eq!(info::entries_per_block(QT_BLOCK_SIZE, Revision::R1), (QT_BLOCK_SIZE - DQDH_SIZE) / R1_SIZE);
    assert_eq!(info::entries_per_block(QT_BLOCK_SIZE, Revision::R0), 21);
}

#[test]
fn the_index_of_a_level_takes_its_own_slice_of_the_id() {
    let d = 4;
    // The leaf level takes the low byte, the root the high one.
    assert_eq!(info::index_of(0x1122_3344, 3, d, QT_BLOCK_SIZE), 0x44);
    assert_eq!(info::index_of(0x1122_3344, 2, d, QT_BLOCK_SIZE), 0x33);
    assert_eq!(info::index_of(0x1122_3344, 1, d, QT_BLOCK_SIZE), 0x22);
    assert_eq!(info::index_of(0x1122_3344, 0, d, QT_BLOCK_SIZE), 0x11);
}

#[test]
fn a_block_count_past_the_file_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R1, 2);
    image::put32(&mut f, INFO_OFF + DQI_BLOCKS, 9);
    assert_eq!(info::parse(&f, USRQUOTA), Err(QuotaError::BlocksPastEnd));
}

#[test]
fn a_free_list_head_outside_the_file_is_refused() {
    let mut f = image::file(USRQUOTA, Revision::R1, 4);
    image::put32(&mut f, INFO_OFF + DQI_FREE_BLK, 4);
    assert_eq!(info::parse(&f, USRQUOTA), Err(QuotaError::BlockOutOfRange));
    let mut f = image::file(USRQUOTA, Revision::R1, 4);
    // The header block can never be a free data block.
    image::put32(&mut f, INFO_OFF + DQI_FREE_ENTRY, QT_TREE_OFF);
    assert_eq!(info::parse(&f, USRQUOTA), Err(QuotaError::BlockOutOfRange));
    let mut f = image::file(USRQUOTA, Revision::R1, 4);
    image::put32(&mut f, INFO_OFF + DQI_FREE_ENTRY, 2);
    assert!(info::parse(&f, USRQUOTA).is_ok());
}

#[test]
fn a_file_shorter_than_its_header_is_refused() {
    assert_eq!(info::parse(&[], USRQUOTA), Err(QuotaError::Truncated));
    assert_eq!(info::parse(&[0u8; 2], USRQUOTA), Err(QuotaError::Truncated));
    // The magic is whole but the per-type header is not.
    let mut short = image::file(USRQUOTA, Revision::R1, 1);
    short.truncate(INFO_OFF + 2);
    assert_eq!(info::parse(&short, USRQUOTA), Err(QuotaError::Truncated));
}

#[test]
fn the_headers_round_trip() {
    let f = image::file(PRJQUOTA, Revision::R0, 3);
    let mut back = f.clone();
    let mut info = info::parse(&f, PRJQUOTA).unwrap();
    info.bgrace = 42;
    info.free_entry = 2;
    info::store(&mut back, &info).unwrap();
    assert_eq!(info::parse(&back, PRJQUOTA).unwrap(), info);
    // Only the header region moved.
    assert_eq!(&back[QT_BLOCK_SIZE..], &f[QT_BLOCK_SIZE..]);
}

#[test]
fn the_derived_offsets_land_where_the_format_puts_them() {
    // Each offset above is written as the sum of the field widths before it,
    // so one wrong width would shift every field after it in step and no
    // other test would notice. These are the format's own numbers.
    assert_eq!((DQH_MAGIC, DQH_VERSION, HEADER_SIZE), (0, 4, 8));
    assert_eq!((DQI_BGRACE, DQI_IGRACE, DQI_FLAGS), (0, 4, 8));
    assert_eq!((DQI_BLOCKS, DQI_FREE_BLK, DQI_FREE_ENTRY, INFO_SIZE), (12, 16, 20, 24));
    assert_eq!((DQDH_NEXT_FREE, DQDH_PREV_FREE, DQDH_ENTRIES, DQDH_SIZE), (0, 4, 8, 16));
    assert_eq!((R0_ID, R0_IHARDLIMIT, R0_ISOFTLIMIT, R0_CURINODES), (0, 4, 8, 12));
    assert_eq!((R0_BHARDLIMIT, R0_BSOFTLIMIT, R0_CURSPACE), (16, 20, 24));
    assert_eq!((R0_BTIME, R0_ITIME, R0_SIZE), (32, 40, 48));
    assert_eq!((R1_ID, R1_PAD, R1_IHARDLIMIT, R1_ISOFTLIMIT), (0, 4, 8, 16));
    assert_eq!((R1_CURINODES, R1_BHARDLIMIT, R1_BSOFTLIMIT), (24, 32, 40));
    assert_eq!((R1_CURSPACE, R1_BTIME, R1_ITIME, R1_SIZE), (48, 56, 64, 72));
    assert_eq!((QT_BLOCK_SIZE, QT_TREE_OFF, SPACE_UNIT), (1024, 1, 1024));
    assert_eq!(MAGIC, [0xd9c0_1f11, 0xd9c0_1927, 0xd9c0_3f14]);
}
