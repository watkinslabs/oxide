use super::*;
use crate::uapi::*;

/// A boot sector a formatter would write: 512-byte sectors, 8 sectors per
/// cluster, one table.
pub fn sector() -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; 512];
    b[OFF_FS_NAME..OFF_FS_NAME + FS_NAME_LEN].copy_from_slice(FS_NAME.as_slice());
    b[OFF_VOL_LENGTH..OFF_VOL_LENGTH + 8].copy_from_slice(&4096u64.to_le_bytes());
    b[OFF_FAT_OFFSET..OFF_FAT_OFFSET + 4].copy_from_slice(&24u32.to_le_bytes());
    b[OFF_FAT_LENGTH..OFF_FAT_LENGTH + 4].copy_from_slice(&8u32.to_le_bytes());
    b[OFF_CLU_OFFSET..OFF_CLU_OFFSET + 4].copy_from_slice(&32u32.to_le_bytes());
    b[OFF_CLU_COUNT..OFF_CLU_COUNT + 4].copy_from_slice(&500u32.to_le_bytes());
    b[OFF_ROOT_CLUSTER..OFF_ROOT_CLUSTER + 4].copy_from_slice(&2u32.to_le_bytes());
    b[OFF_SECT_SIZE_BITS] = 9;
    b[OFF_SECT_PER_CLUS_BITS] = 3;
    b[OFF_NUM_FATS] = 1;
    b[OFF_SIGNATURE..OFF_SIGNATURE + 2].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
    b
}

#[test]
fn a_well_formed_sector_parses() {
    let boot = parse(&sector()).unwrap();
    assert_eq!(boot.clu_count, 500);
    assert_eq!(boot.root_cluster, 2);
    assert_eq!(boot.sect_size_bits, 9);
    assert_eq!(boot.num_fats, 1);
}

#[test]
fn a_short_read_is_an_io_error_not_a_bad_field() {
    assert_eq!(parse(&[0u8; 100]), Err(BootError::TooShort));
    assert_eq!(BootError::TooShort.errno(), syscall::errno::Errno::Eio);
}

#[test]
fn the_signature_is_checked_before_the_name() {
    let mut b = sector();
    b[OFF_SIGNATURE] = 0;
    // The name is still correct, so a signature failure proves the order.
    assert_eq!(parse(&b), Err(BootError::BadSignature));
}

#[test]
fn a_volume_without_the_name_is_refused() {
    let mut b = sector();
    b[OFF_FS_NAME] = b'F';
    assert_eq!(parse(&b), Err(BootError::NotExfat));
}

#[test]
fn a_fat_volume_is_refused_by_the_field_that_must_be_zero() {
    // A FAT volume with the exFAT name pasted over it: its BIOS parameter
    // block occupies the field, and that is the only thing standing between a
    // FAT medium and being read with the wrong layout.
    let mut b = sector();
    b[OFF_MUST_BE_ZERO] = 0x02;
    assert_eq!(parse(&b), Err(BootError::FatVolume));
}

#[test]
fn neither_zero_nor_three_tables_is_accepted() {
    for count in [0u8, 3, 255] {
        let mut b = sector();
        b[OFF_NUM_FATS] = count;
        assert_eq!(parse(&b), Err(BootError::BadFatCount), "num_fats={count}");
    }
}

#[test]
fn the_sector_size_has_both_bounds() {
    for bits in [0u8, 8, 13, 255] {
        let mut b = sector();
        b[OFF_SECT_SIZE_BITS] = bits;
        assert_eq!(parse(&b), Err(BootError::BadSectorSize), "bits={bits}");
    }
    for bits in 9u8..=12 {
        let mut b = sector();
        b[OFF_SECT_SIZE_BITS] = bits;
        // The consistency checks depend on the sector size, so only the
        // sector-size verdict is asserted here.
        assert_ne!(parse(&b), Err(BootError::BadSectorSize), "bits={bits}");
    }
}

#[test]
fn a_cluster_over_the_ceiling_is_refused() {
    let mut b = sector();
    // 9 + 17 = 26 bits, one past the 32 MiB ceiling.
    b[OFF_SECT_PER_CLUS_BITS] = 17;
    assert_eq!(parse(&b), Err(BootError::BadClusterSize));
}

#[test]
fn a_table_too_short_for_its_clusters_is_refused() {
    let mut b = sector();
    // Eight sectors of 512 bytes hold 1024 entries; claim more clusters.
    b[OFF_CLU_COUNT..OFF_CLU_COUNT + 4].copy_from_slice(&2000u32.to_le_bytes());
    assert_eq!(parse(&b), Err(BootError::BadFatLength));
}

#[test]
fn a_heap_starting_inside_the_tables_is_refused() {
    let mut b = sector();
    b[OFF_CLU_OFFSET..OFF_CLU_OFFSET + 4].copy_from_slice(&30u32.to_le_bytes());
    assert_eq!(parse(&b), Err(BootError::BadDataStart));
}

#[test]
fn two_tables_must_both_fit_before_the_heap() {
    let mut b = sector();
    b[OFF_NUM_FATS] = 2;
    // 24 + 8*2 = 40 > 32, so the heap would begin inside the second table.
    assert_eq!(parse(&b), Err(BootError::BadDataStart));
}

#[test]
fn the_dirty_and_failure_flags_are_read_from_the_flags_word() {
    let mut b = sector();
    b[OFF_VOL_FLAGS..OFF_VOL_FLAGS + 2].copy_from_slice(&(VOLUME_DIRTY | MEDIA_FAILURE).to_le_bytes());
    let boot = parse(&b).unwrap();
    assert!(is_dirty(&boot));
    assert!(media_failure(&boot));
}

#[test]
fn clearing_dirty_keeps_a_media_failure_nobody_repaired() {
    let flags = flags_with_dirty(VOLUME_DIRTY | MEDIA_FAILURE, false);
    assert_eq!(flags & VOLUME_DIRTY, 0);
    assert_eq!(flags & MEDIA_FAILURE, MEDIA_FAILURE);
}

#[test]
fn setting_dirty_keeps_the_other_persistent_flags() {
    assert_eq!(flags_with_dirty(MEDIA_FAILURE, true), MEDIA_FAILURE | VOLUME_DIRTY);
}

#[test]
fn a_volume_with_anything_free_never_reports_full() {
    assert_eq!(percent_in_use(999, 1000), 99);
    assert_eq!(percent_in_use(1000, 1000), 100);
    assert_eq!(percent_in_use(0, 1000), 0);
    assert_eq!(percent_in_use(0, 0), 0);
}

#[test]
fn the_percentage_rounds_down() {
    assert_eq!(percent_in_use(19, 1000), 1);
}

#[test]
fn the_two_mutable_bytes_are_written_where_the_checksum_ignores_them() {
    let mut b = sector();
    set_vol_flags(&mut b, VOLUME_DIRTY);
    set_percent_in_use(&mut b, 42);
    assert_eq!(parse(&b).unwrap().vol_flags, VOLUME_DIRTY);
    assert_eq!(parse(&b).unwrap().percent_in_use, 42);
    // Both offsets are in the skip list, which is what makes this a
    // one-sector write.
    assert!(BOOT_CHECKSUM_SKIP.contains(&OFF_VOL_FLAGS));
    assert!(BOOT_CHECKSUM_SKIP.contains(&(OFF_VOL_FLAGS + 1)));
    assert!(BOOT_CHECKSUM_SKIP.contains(&OFF_PERCENT_IN_USE));
}
