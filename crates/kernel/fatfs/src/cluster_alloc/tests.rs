use super::*;
use crate::bpb::Bpb;
use crate::geometry::resolve;
use alloc::vec;

/// A small volume of each width, with a table big enough not to clamp.
fn geo(width: FatWidth) -> (Geometry, Vec<u8>) {
    let b = match width {
        FatWidth::Fat12 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 16, media: 0xf8, fat_length16: 4, fat_length32: 0,
            total_sect16: 600, total_sect32: 0, root_cluster: 0, fsinfo_sector: 0 },
        FatWidth::Fat16 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 16, media: 0xf8, fat_length16: 64, fat_length32: 0,
            total_sect16: 0, total_sect32: 20_000, root_cluster: 0, fsinfo_sector: 0 },
        FatWidth::Fat32 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 0, media: 0xf8, fat_length16: 0, fat_length32: 256,
            total_sect16: 0, total_sect32: 20_000, root_cluster: 2, fsinfo_sector: 1 },
    };
    let g = resolve(&b).expect("valid volume");
    assert_eq!(g.width, width);
    let table = vec![0u8; (g.fat_length * g.sector_size) as usize];
    (g, table)
}

fn link(g: &Geometry, t: &[u8], cluster: u32) -> Option<Link> { chain::read_entry(g.width, t, cluster) }

/// A twelve-bit entry shares a byte with its neighbour, so writing one must
/// leave the other intact. Overwriting the pair truncates or re-points the
/// neighbour's chain — data lost, discovered much later.
#[test]
fn writing_a_twelve_bit_entry_preserves_its_neighbour() {
    let (g, mut t) = geo(FatWidth::Fat12);
    // Neighbours in both orders: even-then-odd and odd-then-even.
    write_entry(g.width, &mut t, 2, 0x123).unwrap();
    write_entry(g.width, &mut t, 3, 0x456).unwrap();
    assert_eq!(link(&g, &t, 2), Some(Link::Next(0x123)));
    assert_eq!(link(&g, &t, 3), Some(Link::Next(0x456)));

    write_entry(g.width, &mut t, 2, 0x789).unwrap();
    assert_eq!(link(&g, &t, 3), Some(Link::Next(0x456)), "the odd neighbour survived");
    write_entry(g.width, &mut t, 3, 0xABC).unwrap();
    assert_eq!(link(&g, &t, 2), Some(Link::Next(0x789)), "the even neighbour survived");
}

/// Every value written reads back through the reader, at every width — the
/// reader having been tested against an independent writer.
#[test]
fn every_width_round_trips_through_the_reader() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        let (g, mut t) = geo(width);
        for (cluster, value) in [(2u32, 3u32), (3, 4), (10, 11), (11, 2)] {
            write_entry(width, &mut t, cluster, value).unwrap();
        }
        for (cluster, value) in [(2u32, 3u32), (3, 4), (10, 11), (11, 2)] {
            assert_eq!(link(&g, &t, cluster), Some(Link::Next(value)), "{width:?} {cluster}");
        }
    }
}

/// The end mark written reads as an end, at every width.
#[test]
fn the_end_mark_reads_as_an_end() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        let (g, mut t) = geo(width);
        write_entry(width, &mut t, 5, end_mark(width)).unwrap();
        assert_eq!(link(&g, &t, 5), Some(Link::End), "{width:?}");
    }
}

/// A FAT32 entry's top four bits are reserved and belong to whoever wrote them
/// first, so a write preserves them rather than clearing them.
#[test]
fn a_fat32_write_preserves_the_reserved_top_bits() {
    let (g, mut t) = geo(FatWidth::Fat32);
    t[5 * 4..5 * 4 + 4].copy_from_slice(&0xF000_0000u32.to_le_bytes());
    write_entry(g.width, &mut t, 5, 7).unwrap();
    let raw = u32::from_le_bytes([t[20], t[21], t[22], t[23]]);
    assert_eq!(raw, 0xF000_0007, "the reserved bits survived");
    assert_eq!(link(&g, &t, 5), Some(Link::Next(7)), "and the entry still reads as 7");
}

/// A search starts after the hint, so repeated allocations walk forward
/// instead of rescanning the same clusters.
#[test]
fn a_search_starts_after_the_hint() {
    let (g, t) = geo(FatWidth::Fat16);
    assert_eq!(find_free(&g, &t, 0, 3), Ok(vec![2, 3, 4]), "no hint starts at the first data cluster");
    assert_eq!(find_free(&g, &t, 5, 3), Ok(vec![6, 7, 8]), "a hint starts after it");
}

/// The search WRAPS. A volume whose tail is full still allocates from its
/// head; without the wrap it reports ENOSPC with the volume half empty.
#[test]
fn the_search_wraps_so_a_full_tail_still_allocates() {
    let (g, mut t) = geo(FatWidth::Fat16);
    // Fill everything from cluster 10 to the end.
    for cluster in 10..g.max_cluster { write_entry(g.width, &mut t, cluster, end_mark(g.width)).unwrap(); }
    let got = find_free(&g, &t, g.max_cluster - 5, 2).expect("wraps to the head");
    assert_eq!(got, vec![2, 3]);
}

/// An allocation that cannot be satisfied commits NOTHING. The reference marks
/// entries as it goes and reports the shortfall afterwards, leaking every
/// cluster it had already claimed; a caller here can retry smaller and lose
/// nothing.
#[test]
fn a_failed_allocation_leaves_the_table_untouched() {
    let (g, mut t) = geo(FatWidth::Fat16);
    for cluster in 4..g.max_cluster { write_entry(g.width, &mut t, cluster, end_mark(g.width)).unwrap(); }
    let before = t.clone();
    assert_eq!(allocate(&g, &mut t, 0, 5, None).err(), Some(Errno::Enospc), "only two are free");
    assert_eq!(t, before, "nothing was claimed");
    // ...and the two that ARE free can still be had.
    assert_eq!(allocate(&g, &mut t, 0, 2, None).map(|v| v.len()), Ok(2));
}

/// A fresh allocation is a chain the reader walks in order and ends.
#[test]
fn an_allocated_run_is_a_walkable_chain() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    assert_eq!(got, vec![2, 3, 4]);
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(vec![2, 3, 4]));
}

/// Appending attaches to an existing chain's last cluster, and the whole thing
/// walks as one.
#[test]
fn appending_extends_an_existing_chain() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let first = allocate(&g, &mut t, 0, 2, None).expect("allocate");
    let more = allocate(&g, &mut t, *first.last().unwrap(), 2, Some(*first.last().unwrap()))
        .expect("append");
    let whole = chain::walk(&g, &t, first[0]).expect("walk");
    assert_eq!(whole, vec![first[0], first[1], more[0], more[1]]);
}

/// Two allocations never hand out the same cluster, which is the failure that
/// silently corrupts two files at once.
#[test]
fn two_allocations_never_overlap() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let a = allocate(&g, &mut t, 0, 4, None).expect("a");
    let b = allocate(&g, &mut t, *a.last().unwrap(), 4, None).expect("b");
    for cluster in &b { assert!(!a.contains(cluster), "cluster {cluster} handed out twice"); }
}

/// Freeing a chain returns its clusters to the pool, and they are handed out
/// again rather than lost.
#[test]
fn a_freed_chain_becomes_allocatable_again() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let before = count_free(&g, &t);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    assert_eq!(count_free(&g, &t), before - 3);
    assert_eq!(free_chain(&g, &mut t, got[0]), Ok(3));
    assert_eq!(count_free(&g, &t), before, "every cluster came back");
    assert_eq!(find_free(&g, &t, 0, 3), Ok(vec![2, 3, 4]));
}

/// Truncation keeps the head, ends it, and releases the tail — and a reader
/// stopping between the two never follows a link into a freed cluster.
#[test]
fn truncation_ends_the_survivor_and_frees_the_rest() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 5, None).expect("allocate");
    assert_eq!(truncate_chain(&g, &mut t, got[0], 2), Ok(3));
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(vec![got[0], got[1]]));
    for cluster in &got[2..] {
        assert_eq!(link(&g, &t, *cluster), Some(Link::Free), "cluster {cluster} was released");
    }
}

/// Truncating to nothing releases the whole chain.
#[test]
fn truncating_to_nothing_releases_everything() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 3, None).expect("allocate");
    assert_eq!(truncate_chain(&g, &mut t, got[0], 0), Ok(3));
    for cluster in &got { assert_eq!(link(&g, &t, *cluster), Some(Link::Free)); }
}

/// Truncating to more than a chain holds changes nothing.
#[test]
fn truncating_past_the_end_is_a_no_op() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let got = allocate(&g, &mut t, 0, 2, None).expect("allocate");
    let before = t.clone();
    assert_eq!(truncate_chain(&g, &mut t, got[0], 9), Ok(0));
    assert_eq!(t, before);
}

/// A twelve-bit volume allocates, walks and frees through its shared bytes.
#[test]
fn a_twelve_bit_volume_allocates_and_frees_correctly() {
    let (g, mut t) = geo(FatWidth::Fat12);
    let got = allocate(&g, &mut t, 0, 4, None).expect("allocate");
    assert_eq!(chain::walk(&g, &t, got[0]), Ok(got.clone()));
    assert_eq!(free_chain(&g, &mut t, got[0]), Ok(4));
    assert_eq!(count_free(&g, &t), g.total_clusters, "every cluster free again");
}

/// A write past the end of the table is refused rather than reaching past it.
#[test]
fn a_write_past_the_table_is_refused() {
    let mut t = vec![0u8; 8];
    assert_eq!(write_entry(FatWidth::Fat16, &mut t, 4, 1), Err(Errno::Eio));
    assert_eq!(write_entry(FatWidth::Fat32, &mut t, 2, 1), Err(Errno::Eio));
    assert_eq!(write_entry(FatWidth::Fat12, &mut t, 100, 1), Err(Errno::Eio));
    assert!(write_entry(FatWidth::Fat16, &mut t, 3, 1).is_ok(), "the last one that fits");
}

/// Asking for nothing succeeds and changes nothing.
#[test]
fn allocating_nothing_is_a_no_op() {
    let (g, mut t) = geo(FatWidth::Fat16);
    let before = t.clone();
    assert_eq!(allocate(&g, &mut t, 0, 0, None), Ok(vec![]));
    assert_eq!(t, before);
}
