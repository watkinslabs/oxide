use super::*;

/// A boot sector's worth of fields, built directly so a test can name the one
/// value it cares about.
fn bpb(f: impl FnOnce(&mut Bpb)) -> Bpb {
    let mut b = Bpb {
        sector_size: 512, sec_per_clus: 4, reserved: 1, fats: 2, dir_entries: 512,
        media: 0xf8, fat_length16: 64, fat_length32: 0,
        total_sect16: 65535, total_sect32: 0, root_cluster: 0, fsinfo_sector: 1,
    };
    f(&mut b);
    b
}

/// The width is derived from the DATA-CLUSTER COUNT, and the boundary is
/// exactly `MAX_FAT12`. One cluster either side of it changes how every table
/// entry after the first is read; getting this wrong reads as corruption, not
/// as a mount failure.
#[test]
fn the_width_boundary_is_the_cluster_count_not_the_volume_size() {
    // Sized so the data area holds exactly MAX_FAT12 clusters: 1 sector per
    // cluster keeps the arithmetic direct, and the table is made long enough
    // that the clamp does not bind.
    let at_boundary = bpb(|b| {
        b.sec_per_clus = 1;
        b.fat_length16 = 512;
        b.dir_entries = 0;
        b.total_sect16 = 0;
        b.total_sect32 = 1 + 2 * 512 + MAX_FAT12;
    });
    let g = resolve(&at_boundary).expect("valid");
    assert_eq!(g.total_clusters, MAX_FAT12);
    assert_eq!(g.width, FatWidth::Fat12, "exactly at the boundary is still FAT12");

    let one_past = bpb(|b| {
        b.sec_per_clus = 1;
        b.fat_length16 = 512;
        b.dir_entries = 0;
        b.total_sect16 = 0;
        b.total_sect32 = 1 + 2 * 512 + MAX_FAT12 + 1;
    });
    let g = resolve(&one_past).expect("valid");
    assert_eq!(g.total_clusters, MAX_FAT12 + 1);
    assert_eq!(g.width, FatWidth::Fat16, "one cluster past it is FAT16");
}

/// The boundaries are the reserved-mark-adjusted values, not the full range of
/// the entry width. Writing `0xFFF` or `0xFFFF` here would accept a volume
/// whose top cluster numbers collide with the end-of-chain marks.
#[test]
fn the_boundaries_sit_below_the_reserved_marks() {
    assert_eq!(MAX_FAT12, 0xFF4);
    assert_eq!(MAX_FAT16, 0xFFF4);
    assert_eq!(MAX_FAT32, 0x0FFF_FFF6);
    assert!(MAX_FAT12 < (1 << 12) - 1);
    assert!(MAX_FAT16 < (1 << 16) - 1);
    assert!(MAX_FAT32 < (1u32 << 28) - 1, "FAT32 entries carry 28 usable bits");
}

/// A FAT32 volume is declared, not derived: its cluster count would otherwise
/// place it in FAT16's range.
#[test]
fn a_declared_fat32_volume_is_not_re_derived_from_its_cluster_count() {
    let small_fat32 = bpb(|b| {
        b.fat_length16 = 0;
        b.fat_length32 = 64;
        b.dir_entries = 0;
        b.total_sect16 = 8000;
        b.root_cluster = 2;
    });
    let g = resolve(&small_fat32).expect("valid");
    assert_eq!(g.width, FatWidth::Fat32);
    assert!(g.total_clusters < MAX_FAT12, "a count that would otherwise read as FAT12");
    assert!(!g.has_fixed_root(), "and its root is a cluster chain");
    assert_eq!(g.root_cluster, 2);
}

/// Each region begins where the one before it ends, and the data area starts
/// after every table plus the fixed root.
#[test]
fn the_regions_are_laid_out_end_to_end() {
    let g = resolve(&bpb(|_| {})).expect("valid");
    assert_eq!(g.fat_start, 1, "immediately after the boot sector");
    assert_eq!(g.dir_start, 1 + 2 * 64, "after both tables");
    // 512 entries of 32 bytes in 512-byte sectors is 32 sectors.
    assert_eq!(g.data_start, g.dir_start + 32);
    assert!(g.has_fixed_root());
}

/// A root directory that is not a whole number of sectors is refused: the
/// region's length would otherwise be rounded and overlap the data area.
#[test]
fn a_root_directory_that_is_not_whole_sectors_is_refused() {
    assert_eq!(resolve(&bpb(|b| b.dir_entries = 500)), Err(GeometryError::BadRootEntries));
    assert_eq!(resolve(&bpb(|b| b.dir_entries = 1)), Err(GeometryError::BadRootEntries));
    // A whole number of sectors is fine, including none at all.
    assert!(resolve(&bpb(|b| b.dir_entries = 16)).is_ok());
    assert!(resolve(&bpb(|b| b.dir_entries = 0)).is_ok());
}

/// A volume whose declared size does not reach its own data area is refused
/// rather than producing a negative cluster count.
#[test]
fn a_volume_shorter_than_its_own_metadata_is_refused() {
    let truncated = bpb(|b| { b.total_sect16 = 4; b.total_sect32 = 0; });
    assert_eq!(resolve(&truncated), Err(GeometryError::DataBeyondVolume));
}

/// The clamp: a table too short to index the data area caps the volume at what
/// it can reach. Refusing instead would reject volumes that mount elsewhere.
#[test]
fn a_short_table_caps_the_volume_instead_of_refusing_it() {
    // One 512-byte FAT16 sector holds 256 entries, of which 2 are reserved.
    let short_table = bpb(|b| {
        b.sec_per_clus = 1;
        b.fat_length16 = 1;
        b.dir_entries = 0;
        b.total_sect16 = 0;
        b.total_sect32 = 1 + 2 + 100_000;
    });
    let g = resolve(&short_table).expect("mounts, capped");
    assert_eq!(g.total_clusters, 254, "256 entries less the two reserved");
    assert_eq!(g.max_cluster, 256);
}

/// The width is decided BEFORE the clamp. A volume whose data area implies
/// FAT16 keeps that width even when a short table caps it into FAT12's range —
/// deciding after the clamp would read every entry at the wrong offset.
#[test]
fn the_width_is_decided_before_the_clamp_not_after() {
    let big_area_short_table = bpb(|b| {
        b.sec_per_clus = 1;
        b.fat_length16 = 1;
        b.dir_entries = 0;
        b.total_sect16 = 0;
        b.total_sect32 = 1 + 2 + MAX_FAT12 * 4;
    });
    let g = resolve(&big_area_short_table).expect("valid");
    assert_eq!(g.width, FatWidth::Fat16, "the data area decided this");
    assert!(g.total_clusters < MAX_FAT12, "even though the clamp brought it under");
}

/// Cluster 2 is the first data cluster and sits at the start of the data area;
/// the reserved numbers below it address nothing.
#[test]
fn cluster_two_is_the_first_data_cluster() {
    let g = resolve(&bpb(|_| {})).expect("valid");
    assert_eq!(g.cluster_sector(2), Some(g.data_start));
    assert_eq!(g.cluster_sector(3), Some(g.data_start + g.sec_per_clus));
    assert_eq!(g.cluster_sector(0), None, "reserved entry, not a cluster");
    assert_eq!(g.cluster_sector(1), None, "reserved entry, not a cluster");
}

/// A cluster number past the end addresses nothing, so a corrupt chain cannot
/// walk off the volume into whatever follows it on the disk.
#[test]
fn a_cluster_past_the_end_addresses_nothing() {
    let g = resolve(&bpb(|_| {})).expect("valid");
    assert!(g.cluster_sector(g.max_cluster - 1).is_some(), "the last one is addressable");
    assert_eq!(g.cluster_sector(g.max_cluster), None);
    assert_eq!(g.cluster_sector(g.max_cluster + 1), None);
    assert_eq!(g.cluster_sector(u32::MAX), None, "and the arithmetic cannot wrap");
}

/// Entries per table, in the order that does not overflow. A large FAT32
/// volume's table holds more entries than a 32-bit product would survive.
#[test]
fn table_entry_counts_do_not_overflow_on_a_large_volume() {
    assert_eq!(fat_entries(FatWidth::Fat16, 512, 1), 256);
    assert_eq!(fat_entries(FatWidth::Fat32, 512, 1), 128);
    // 12-bit entries do not divide a sector evenly: three sectors hold 1024.
    assert_eq!(fat_entries(FatWidth::Fat12, 512, 3), 1024);
    // A table spanning most of a 32-bit sector count still computes.
    let huge = fat_entries(FatWidth::Fat32, 4096, 1_000_000);
    assert_eq!(huge, 1_024_000_000);
}

/// Bytes per cluster is computed in 64 bits: the largest legal cluster on a
/// 4 KiB-sector volume overflows a 32-bit product.
#[test]
fn cluster_bytes_are_computed_wide() {
    let g = resolve(&bpb(|b| { b.sector_size = 4096; b.sec_per_clus = 128; b.dir_entries = 0; })).expect("valid");
    assert_eq!(g.cluster_bytes(), 4096 * 128);
}
