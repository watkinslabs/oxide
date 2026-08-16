use super::*;

/// A boot sector a formatter would write: 512-byte sectors, 8 per cluster.
pub fn sector() -> alloc::vec::Vec<u8> {
    let mut b = alloc::vec![0u8; BOOT_BYTES];
    b[BOOT_OFF_SYSTEM_ID..BOOT_OFF_SYSTEM_ID + 8].copy_from_slice(SYSTEM_ID.as_slice());
    b[BOOT_OFF_BYTES_PER_SECTOR] = 0x00;
    b[BOOT_OFF_BYTES_PER_SECTOR + 1] = 0x02;
    b[BOOT_OFF_SECTORS_PER_CLUSTER] = 8;
    b[BOOT_OFF_SECTORS_PER_VOLUME..BOOT_OFF_SECTORS_PER_VOLUME + 8]
        .copy_from_slice(&4096u64.to_le_bytes());
    b[BOOT_OFF_MFT_CLST..BOOT_OFF_MFT_CLST + 8].copy_from_slice(&32u64.to_le_bytes());
    b[BOOT_OFF_MFT2_CLST..BOOT_OFF_MFT2_CLST + 8].copy_from_slice(&16u64.to_le_bytes());
    b[BOOT_OFF_RECORD_SIZE] = (-10i8) as u8;
    b[BOOT_OFF_INDEX_SIZE] = 1;
    b
}

#[test]
fn a_well_formed_sector_resolves() {
    let g = resolve(&parse(&sector()).unwrap()).unwrap();
    assert_eq!(g.sector_size, 512);
    assert_eq!(g.cluster_size, 4096);
    assert_eq!(g.cluster_bits, 12);
    assert_eq!(g.record_size, 1024);
    // A POSITIVE index size counts CLUSTERS, so 1 means one cluster.
    assert_eq!(g.index_size, 4096);
    assert_eq!(g.mft_offset, 32 * 4096);
    assert_eq!(g.mft_mirror_offset, 16 * 4096);
}

#[test]
fn the_sector_size_field_is_not_aligned() {
    // Read as an aligned 16-bit word it would come from the wrong offset.
    let mut b = sector();
    b[BOOT_OFF_BYTES_PER_SECTOR] = 0x00;
    b[BOOT_OFF_BYTES_PER_SECTOR + 1] = 0x10;
    assert_eq!(parse(&b).unwrap().bytes_per_sector, 4096);
}

#[test]
fn a_negative_record_size_is_a_power_of_two_byte_count() {
    for (field, bytes) in [(-9i8, 512u32), (-10, 1024), (-12, 4096)] {
        let mut b = sector();
        b[BOOT_OFF_RECORD_SIZE] = field as u8;
        assert_eq!(resolve(&parse(&b).unwrap()).unwrap().record_size, bytes, "field={field}");
    }
}

#[test]
fn a_positive_record_size_counts_clusters() {
    let mut b = sector();
    b[BOOT_OFF_RECORD_SIZE] = 1;
    // One cluster of 4096 bytes, not one byte.
    assert_eq!(resolve(&parse(&b).unwrap()).unwrap().record_size, 4096);
}

#[test]
fn a_sectors_per_cluster_byte_above_the_boundary_is_a_shift() {
    // 0xF4 is -12: a cluster of 4096 SECTORS, not 244 of them.
    assert_eq!(sectors_per_cluster(0xF4), 4096);
    assert_eq!(sectors_per_cluster(8), 8);
    assert_eq!(sectors_per_cluster(0x80), 0x80);
}

#[test]
fn a_volume_that_is_not_ntfs_is_refused() {
    let mut b = sector();
    b[BOOT_OFF_SYSTEM_ID] = b'F';
    assert_eq!(parse(&b), Err(BootError::NotNtfs));
}

#[test]
fn a_short_sector_is_an_io_error() {
    assert_eq!(parse(&[0u8; 100]), Err(BootError::TooShort));
    assert_eq!(BootError::TooShort.errno(), syscall::errno::Errno::Eio);
}

#[test]
fn a_sector_size_below_the_floor_or_not_a_power_of_two_is_refused() {
    for (lo, hi) in [(0u8, 1u8), (0x00, 0x03)] {
        let mut b = sector();
        b[BOOT_OFF_BYTES_PER_SECTOR] = lo;
        b[BOOT_OFF_BYTES_PER_SECTOR + 1] = hi;
        assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::BadSectorSize));
    }
}

#[test]
fn a_cluster_of_no_sectors_or_not_a_power_of_two_is_refused() {
    for count in [0u8, 3, 5] {
        let mut b = sector();
        b[BOOT_OFF_SECTORS_PER_CLUSTER] = count;
        assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::BadClusterSize), "{count}");
    }
}

#[test]
fn an_mft_outside_the_volume_is_refused() {
    let mut b = sector();
    b[BOOT_OFF_MFT_CLST..BOOT_OFF_MFT_CLST + 8].copy_from_slice(&99_999u64.to_le_bytes());
    assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::MftOutOfVolume));
    let mut b = sector();
    b[BOOT_OFF_MFT2_CLST..BOOT_OFF_MFT2_CLST + 8].copy_from_slice(&99_999u64.to_le_bytes());
    assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::MftOutOfVolume));
}

#[test]
fn a_record_size_the_format_cannot_express_is_refused() {
    let mut b = sector();
    // -20 is past the shift limit.
    b[BOOT_OFF_RECORD_SIZE] = (-20i8) as u8;
    assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::BadRecordSize));
    let mut b = sector();
    // Two clusters of 4096 is 8192, past the widest record.
    b[BOOT_OFF_RECORD_SIZE] = 2;
    assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::BadRecordSize));
}

#[test]
fn an_index_size_the_format_cannot_express_is_refused() {
    let mut b = sector();
    b[BOOT_OFF_INDEX_SIZE] = (-20i8) as u8;
    assert_eq!(resolve(&parse(&b).unwrap()), Err(BootError::BadIndexSize));
}

#[test]
fn a_record_offset_is_the_mft_plus_the_records_own_position() {
    let g = resolve(&parse(&sector()).unwrap()).unwrap();
    assert_eq!(g.record_offset(0), 32 * 4096);
    assert_eq!(g.record_offset(5), 32 * 4096 + 5 * 1024);
}

#[test]
fn a_length_rounds_up_to_whole_clusters() {
    let g = resolve(&parse(&sector()).unwrap()).unwrap();
    assert_eq!(g.clusters_for(0), 0);
    assert_eq!(g.clusters_for(1), 1);
    assert_eq!(g.clusters_for(4096), 1);
    assert_eq!(g.clusters_for(4097), 2);
}
