use super::*;
use crate::boot;

/// The layout of the boot sector the boot tests build.
fn geo() -> Geometry { resolve(&boot::parse(&crate::tests_boot_sector()).unwrap()) }

#[test]
fn the_shift_counts_resolve_to_sizes() {
    let g = geo();
    assert_eq!(g.sector_size, 512);
    assert_eq!(g.sectors_per_cluster, 8);
    assert_eq!(g.cluster_bytes(), 4096);
    assert_eq!(g.dentries_per_cluster(), 128);
}

#[test]
fn the_two_reserved_clusters_are_counted_but_not_usable() {
    let g = geo();
    assert_eq!(g.num_clusters, 502);
    assert_eq!(g.data_clusters(), 500);
    assert!(!g.valid_cluster(0));
    assert!(!g.valid_cluster(1));
    assert!(g.valid_cluster(2));
    assert!(g.valid_cluster(501));
    assert!(!g.valid_cluster(502));
}

#[test]
fn the_first_cluster_of_the_heap_is_the_data_start_sector() {
    let g = geo();
    assert_eq!(g.cluster_sector(2), Some(32));
    assert_eq!(g.cluster_sector(3), Some(40));
    assert_eq!(g.cluster_offset(3), Some(40 * 512));
    assert_eq!(g.cluster_sector(1), None);
}

#[test]
fn one_table_means_the_mirror_is_the_table() {
    let g = geo();
    assert_eq!(g.fat_start, 24);
    assert_eq!(g.fat_mirror_start, 24);
}

#[test]
fn two_tables_put_the_mirror_after_the_first() {
    let mut b = crate::tests_boot_sector();
    b[crate::uapi::OFF_NUM_FATS] = 2;
    b[crate::uapi::OFF_CLU_OFFSET..crate::uapi::OFF_CLU_OFFSET + 4]
        .copy_from_slice(&48u32.to_le_bytes());
    let g = resolve(&boot::parse(&b).unwrap());
    assert_eq!(g.fat_start, 24);
    assert_eq!(g.fat_mirror_start, 32);
}

#[test]
fn a_table_entry_is_located_by_sector_and_offset() {
    let g = geo();
    // 128 entries per 512-byte sector.
    assert_eq!(g.fat_sector_of(0), (24, 24));
    assert_eq!(g.fat_offset_in_sector(0), 0);
    assert_eq!(g.fat_sector_of(127), (24, 24));
    assert_eq!(g.fat_offset_in_sector(127), 508);
    assert_eq!(g.fat_sector_of(128), (25, 25));
    assert_eq!(g.fat_offset_in_sector(128), 0);
}

#[test]
fn a_length_rounds_up_to_whole_clusters() {
    let g = geo();
    assert_eq!(g.clusters_for(0), 0);
    assert_eq!(g.clusters_for(1), 1);
    assert_eq!(g.clusters_for(4096), 1);
    assert_eq!(g.clusters_for(4097), 2);
}
