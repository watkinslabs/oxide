use super::*;
use alloc::vec;
use alloc::vec::Vec;

/// A boot sector for a plausible FAT16 volume, which each test then breaks in
/// exactly one way.
fn fat16_sector() -> Vec<u8> {
    let mut s = vec![0u8; 512];
    s[off::SECTOR_SIZE..off::SECTOR_SIZE + 2].copy_from_slice(&512u16.to_le_bytes());
    s[off::SEC_PER_CLUS] = 4;
    s[off::RESERVED..off::RESERVED + 2].copy_from_slice(&1u16.to_le_bytes());
    s[off::FATS] = 2;
    s[off::DIR_ENTRIES..off::DIR_ENTRIES + 2].copy_from_slice(&512u16.to_le_bytes());
    s[off::TOTAL_SECT16..off::TOTAL_SECT16 + 2].copy_from_slice(&65535u16.to_le_bytes());
    s[off::MEDIA] = 0xf8;
    s[off::FAT_LENGTH16..off::FAT_LENGTH16 + 2].copy_from_slice(&64u16.to_le_bytes());
    s
}

/// A FAT32 boot sector: the 16-bit table length is zero and the 32-bit one
/// carries it, which is what declares the width.
fn fat32_sector() -> Vec<u8> {
    let mut s = fat16_sector();
    s[off::FAT_LENGTH16..off::FAT_LENGTH16 + 2].copy_from_slice(&0u16.to_le_bytes());
    s[off::FAT_LENGTH32..off::FAT_LENGTH32 + 4].copy_from_slice(&2048u32.to_le_bytes());
    s[off::DIR_ENTRIES..off::DIR_ENTRIES + 2].copy_from_slice(&0u16.to_le_bytes());
    s[off::TOTAL_SECT16..off::TOTAL_SECT16 + 2].copy_from_slice(&0u16.to_le_bytes());
    s[off::TOTAL_SECT32..off::TOTAL_SECT32 + 4].copy_from_slice(&1_048_576u32.to_le_bytes());
    s[off::ROOT_CLUSTER..off::ROOT_CLUSTER + 4].copy_from_slice(&2u32.to_le_bytes());
    s
}

#[test]
fn a_plausible_volume_parses_every_field() {
    let b = parse(&fat16_sector()).expect("valid");
    assert_eq!(b.sector_size, 512);
    assert_eq!(b.sec_per_clus, 4);
    assert_eq!(b.reserved, 1);
    assert_eq!(b.fats, 2);
    assert_eq!(b.dir_entries, 512);
    assert_eq!(b.media, 0xf8);
    assert_eq!(b.fat_length(), 64);
    assert_eq!(b.total_sectors(), 65535);
    assert!(!b.declares_fat32());
    assert_eq!(b.dir_per_sector(), 16);
}

/// Two 16-bit fields sit at ODD offsets. Reading them as aligned words is the
/// mistake this test exists to catch: it would take the wrong bytes entirely.
#[test]
fn the_odd_offset_fields_are_read_unaligned() {
    let mut s = fat16_sector();
    // 0x0b and 0x11 are both odd.
    s[off::SECTOR_SIZE..off::SECTOR_SIZE + 2].copy_from_slice(&4096u16.to_le_bytes());
    s[off::DIR_ENTRIES..off::DIR_ENTRIES + 2].copy_from_slice(&224u16.to_le_bytes());
    let b = parse(&s).expect("valid");
    assert_eq!(b.sector_size, 4096);
    assert_eq!(b.dir_entries, 224);
    assert_eq!(off::SECTOR_SIZE % 2, 1, "the field really is at an odd offset");
    assert_eq!(off::DIR_ENTRIES % 2, 1);
}

/// Refusal ORDER. A sector wrong in every way reports the first check, so a
/// caller probing a medium gets one stable answer.
#[test]
fn the_refusal_order_is_fixed() {
    let mut s = fat16_sector();
    s[off::RESERVED..off::RESERVED + 2].copy_from_slice(&0u16.to_le_bytes());
    s[off::FATS] = 0;
    s[off::MEDIA] = 0;
    s[off::SECTOR_SIZE..off::SECTOR_SIZE + 2].copy_from_slice(&7u16.to_le_bytes());
    s[off::SEC_PER_CLUS] = 3;
    s[off::FAT_LENGTH16..off::FAT_LENGTH16 + 2].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(parse(&s), Err(BpbError::NoReservedSectors));

    s[off::RESERVED..off::RESERVED + 2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(parse(&s), Err(BpbError::NoFats));
    s[off::FATS] = 2;
    assert_eq!(parse(&s), Err(BpbError::BadMedia));
    s[off::MEDIA] = 0xf8;
    assert_eq!(parse(&s), Err(BpbError::BadSectorSize));
    s[off::SECTOR_SIZE..off::SECTOR_SIZE + 2].copy_from_slice(&512u16.to_le_bytes());
    assert_eq!(parse(&s), Err(BpbError::BadClusterSize));
    s[off::SEC_PER_CLUS] = 4;
    assert_eq!(parse(&s), Err(BpbError::NoFatLength));
}

/// The media descriptors a volume may carry, and the ones it may not.
#[test]
fn only_the_defined_media_descriptors_are_accepted() {
    for good in [0xf0u8, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff] {
        assert!(valid_media(good), "{good:#x}");
    }
    for bad in [0x00u8, 0x01, 0x7f, 0xef, 0xf1, 0xf7] {
        assert!(!valid_media(bad), "{bad:#x}");
    }
}

/// Sector sizes outside the supported range, or not a power of two, are
/// refused rather than accepted and used as a stride.
#[test]
fn sector_sizes_are_bounded_powers_of_two() {
    for bad in [0u32, 128, 256, 511, 1000, 8192, 65535] {
        let mut s = fat16_sector();
        s[off::SECTOR_SIZE..off::SECTOR_SIZE + 2].copy_from_slice(&(bad as u16).to_le_bytes());
        assert_eq!(parse(&s), Err(BpbError::BadSectorSize), "{bad}");
    }
    for good in [512u32, 1024, 2048, 4096] {
        let mut s = fat16_sector();
        s[off::SECTOR_SIZE..off::SECTOR_SIZE + 2].copy_from_slice(&(good as u16).to_le_bytes());
        assert_eq!(parse(&s).map(|b| b.sector_size), Ok(good));
    }
}

/// A cluster is a power-of-two count of sectors. Zero is refused too — it
/// would make every cluster-to-sector conversion divide by nothing.
#[test]
fn cluster_sizes_are_powers_of_two_and_never_zero() {
    for bad in [0u8, 3, 5, 6, 7, 9, 255] {
        let mut s = fat16_sector();
        s[off::SEC_PER_CLUS] = bad;
        assert_eq!(parse(&s), Err(BpbError::BadClusterSize), "{bad}");
    }
    for good in [1u8, 2, 4, 8, 16, 32, 64, 128] {
        let mut s = fat16_sector();
        s[off::SEC_PER_CLUS] = good;
        assert!(parse(&s).is_ok(), "{good}");
    }
}

/// The two size fields each have a wide form, used when the narrow one cannot
/// hold the value. Reading only the narrow one truncates a large volume to
/// nothing.
#[test]
fn the_wide_fields_carry_what_the_narrow_ones_cannot() {
    let b = parse(&fat32_sector()).expect("valid");
    assert_eq!(b.fat_length16, 0);
    assert_eq!(b.fat_length(), 2048, "the 32-bit table length is the one in use");
    assert_eq!(b.total_sect16, 0);
    assert_eq!(b.total_sectors(), 1_048_576);
    assert!(b.declares_fat32());
    assert_eq!(b.root_cluster, 2);
}

/// A volume that declares neither table length declares no table.
#[test]
fn a_volume_with_no_table_at_all_is_refused() {
    let mut s = fat16_sector();
    s[off::FAT_LENGTH16..off::FAT_LENGTH16 + 2].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(parse(&s), Err(BpbError::NoFatLength));
}

/// A sector too short to contain the block is refused rather than read past.
#[test]
fn a_short_sector_is_refused() {
    assert_eq!(parse(&[]), Err(BpbError::Short));
    assert_eq!(parse(&vec![0u8; 48]), Err(BpbError::Short));
    assert_eq!(parse(&vec![0u8; 0x31]), Err(BpbError::Short));
}

/// An all-zero sector is not a FAT volume, and says so through the first
/// field that proves it rather than through a panic or a wild geometry.
#[test]
fn an_all_zero_sector_is_not_a_volume() {
    assert_eq!(parse(&vec![0u8; 512]), Err(BpbError::NoReservedSectors));
}

#[test]
fn dos1x_accepts_only_the_linux_floppy_defaults() {
    let mut sector = vec![0u8; 512];
    sector[0] = 0xeb;
    sector[2] = 0x90;
    for (sectors, sec_per_clus, dirs, media, fat) in [
        (320, 1, 64, 0xfe, 1), (360, 1, 64, 0xfc, 2),
        (640, 2, 112, 0xff, 1), (720, 2, 112, 0xfd, 2),
    ] {
        let b = Bpb::dos1x(&sector, sectors).expect("recognized floppy");
        assert_eq!((b.sec_per_clus, b.dir_entries, b.media, b.fat_length()),
                   (sec_per_clus, dirs, media, fat));
    }
    assert!(Bpb::dos1x(&sector, 321).is_none(), "arbitrary media size");
    sector[off::FATS] = 1;
    assert!(Bpb::dos1x(&sector, 320).is_none(), "non-zero BPB");
}
