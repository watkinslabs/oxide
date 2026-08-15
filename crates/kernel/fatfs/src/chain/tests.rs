use super::*;
use crate::bpb::Bpb;
use crate::geometry::resolve;
use alloc::vec;

fn geo(width: FatWidth) -> Geometry {
    let b = match width {
        FatWidth::Fat12 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 16, media: 0xf8, fat_length16: 12, fat_length32: 0,
            total_sect16: 4000, total_sect32: 0, root_cluster: 0, fsinfo_sector: 0 },
        FatWidth::Fat16 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 16, media: 0xf8, fat_length16: 128, fat_length32: 0,
            total_sect16: 0, total_sect32: 20_000, root_cluster: 0, fsinfo_sector: 0 },
        FatWidth::Fat32 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 1,
            dir_entries: 0, media: 0xf8, fat_length16: 0, fat_length32: 256,
            total_sect16: 0, total_sect32: 20_000, root_cluster: 2, fsinfo_sector: 1 },
    };
    let g = resolve(&b).expect("valid volume");
    assert_eq!(g.width, width, "fixture builds the width it claims");
    g
}

/// Write `value` into a FAT12 table at `cluster`, the way a formatter would,
/// so the reader is tested against an independent writer.
fn put12(table: &mut [u8], cluster: u32, value: u32) {
    let at = (cluster + cluster / 2) as usize;
    let pair = u16::from_le_bytes([table[at], table[at + 1]]);
    let merged = if cluster & 1 == 0 {
        (pair & 0xF000) | (value as u16 & 0x0FFF)
    } else {
        (pair & 0x000F) | ((value as u16 & 0x0FFF) << 4)
    };
    table[at..at + 2].copy_from_slice(&merged.to_le_bytes());
}

fn put16(table: &mut [u8], cluster: u32, value: u32) {
    let at = (cluster * 2) as usize;
    table[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
}

fn put32(table: &mut [u8], cluster: u32, value: u32) {
    let at = (cluster * 4) as usize;
    table[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// Twelve-bit entries share bytes and alternate nibbles. Reading every entry
/// as if it were aligned yields a table that is right half the time — which
/// looks like sporadic corruption rather than a bug.
#[test]
fn twelve_bit_entries_alternate_between_shared_bytes() {
    let mut table = vec![0u8; 3072];
    // Adjacent entries with distinct values, so a nibble mix-up is visible.
    for (cluster, value) in [(2u32, 0x123u32), (3, 0x456), (4, 0x789), (5, 0xABC)] {
        put12(&mut table, cluster, value);
    }
    for (cluster, value) in [(2u32, 0x123u32), (3, 0x456), (4, 0x789), (5, 0xABC)] {
        assert_eq!(read_entry(FatWidth::Fat12, &table, cluster), Some(Link::Next(value)),
                   "cluster {cluster}");
    }
    // The shared byte really is shared: entries 2 and 3 overlap at offset 4.
    assert_eq!(entry_offset(FatWidth::Fat12, 2), 3);
    assert_eq!(entry_offset(FatWidth::Fat12, 3), 4);
    assert_eq!(entry_offset(FatWidth::Fat12, 4), 6);
}

/// A twelve-bit entry can straddle the boundary between two table sectors.
/// A reader that fetches one sector at a time and does not carry the byte
/// across reads the top nibble as zero.
#[test]
fn a_twelve_bit_entry_straddling_a_sector_boundary_reads_whole() {
    let mut table = vec![0u8; 3072];
    // Entry 341 spans offsets 511 and 512 — across the 512-byte boundary.
    let at = 341 + 341 / 2;
    assert_eq!(at, 511, "this entry really does straddle the boundary");
    put12(&mut table, 341, 0xABC);
    assert_eq!(read_entry(FatWidth::Fat12, &table, 341), Some(Link::Next(0xABC)));
    assert_ne!(table[511], 0, "the low half is in the first sector");
    assert_ne!(table[512], 0, "and the high half is in the second");
}

/// The three widths read their own entry sizes.
#[test]
fn each_width_reads_its_own_entry_size() {
    let mut t12 = vec![0u8; 3072];
    put12(&mut t12, 5, 0x321);
    assert_eq!(read_entry(FatWidth::Fat12, &t12, 5), Some(Link::Next(0x321)));

    let mut t16 = vec![0u8; 4096];
    put16(&mut t16, 5, 0x4321);
    assert_eq!(read_entry(FatWidth::Fat16, &t16, 5), Some(Link::Next(0x4321)));

    let mut t32 = vec![0u8; 8192];
    put32(&mut t32, 5, 0x0765_4321);
    assert_eq!(read_entry(FatWidth::Fat32, &t32, 5), Some(Link::Next(0x0765_4321)));
}

/// A FAT32 entry carries 28 bits: the top four are reserved and must be
/// ignored. Reading all 32 makes every entry a volume some other system wrote
/// read as out of range.
#[test]
fn the_reserved_top_bits_of_a_fat32_entry_are_ignored() {
    let mut t = vec![0u8; 8192];
    put32(&mut t, 5, 0xF000_0003);
    assert_eq!(read_entry(FatWidth::Fat32, &t, 5), Some(Link::Next(3)));
    // And an end mark with those bits set is still an end mark.
    put32(&mut t, 6, 0xFFFF_FFFF);
    assert_eq!(read_entry(FatWidth::Fat32, &t, 6), Some(Link::End));
}

/// A bad-cluster mark ENDS a chain rather than failing it — the reference
/// folds bad and every reserved value above it into end-of-chain. Erroring
/// instead turns a volume with one marked cluster into an unreadable one.
#[test]
fn a_bad_cluster_mark_ends_the_chain_rather_than_failing_it() {
    for (width, bad) in [(FatWidth::Fat12, BAD_FAT12), (FatWidth::Fat16, BAD_FAT16),
                         (FatWidth::Fat32, BAD_FAT32)] {
        assert_eq!(classify(width, bad), Link::End, "the bad mark itself");
        assert_eq!(classify(width, bad + 1), Link::End, "and everything above it");
        assert_eq!(classify(width, width.entry_mask()), Link::End, "including the end mark");
        assert_eq!(classify(width, bad - 1), Link::Next(bad - 1), "but not the value below");
    }
}

/// Free, and the two reserved numbers below the first data cluster, are not
/// next-cluster links.
#[test]
fn free_and_reserved_values_are_not_links() {
    for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
        assert_eq!(classify(width, 0), Link::Free);
        assert_eq!(classify(width, 1), Link::End, "entry 1 names no cluster");
        assert_eq!(classify(width, 2), Link::Next(2), "the first data cluster");
    }
}

/// An entry past the end of the bytes provided reads as nothing rather than
/// as whatever follows the table in memory.
#[test]
fn an_entry_past_the_table_is_not_read() {
    let t = vec![0u8; 16];
    assert_eq!(read_entry(FatWidth::Fat16, &t, 7), Some(Link::Free));
    assert_eq!(read_entry(FatWidth::Fat16, &t, 8), None, "one past the end");
    assert_eq!(read_entry(FatWidth::Fat32, &t, 4), None);
    assert_eq!(read_entry(FatWidth::Fat12, &t, 100), None);
    assert_eq!(read_entry(FatWidth::Fat32, &t, u32::MAX), None, "and cannot wrap");
}

/// An ordinary chain walks in order and stops at the end mark.
#[test]
fn a_chain_walks_in_order_and_stops_at_its_end() {
    let g = geo(FatWidth::Fat16);
    let mut t = vec![0u8; 128 * 512];
    put16(&mut t, 2, 3);
    put16(&mut t, 3, 7);
    put16(&mut t, 7, 0xFFFF);
    assert_eq!(walk(&g, &t, 2), Ok(vec![2, 3, 7]));
    // A one-cluster file is its own whole chain.
    put16(&mut t, 9, 0xFFF8);
    assert_eq!(walk(&g, &t, 9), Ok(vec![9]));
}

/// A chain that loops does not loop the reader. The bound is the volume's own
/// cluster count, which is the most a chain can visit without repeating.
#[test]
fn a_looping_chain_is_refused_rather_than_followed_forever() {
    let g = geo(FatWidth::Fat16);
    let mut t = vec![0u8; 128 * 512];
    put16(&mut t, 2, 3);
    put16(&mut t, 3, 4);
    put16(&mut t, 4, 2);
    assert_eq!(walk(&g, &t, 2), Err(ChainError::Cycle));
    // A cluster pointing at itself is the shortest loop there is.
    put16(&mut t, 10, 10);
    assert_eq!(walk(&g, &t, 10), Err(ChainError::Cycle));
}

/// A link past the end of the volume is refused, so a corrupt table cannot
/// make a reader address sectors the volume does not have.
#[test]
fn a_link_past_the_volume_is_refused() {
    let g = geo(FatWidth::Fat16);
    let mut t = vec![0u8; 128 * 512];
    put16(&mut t, 2, 0xFFF0); // below the bad mark, so it reads as a link
    assert_eq!(walk(&g, &t, 2), Err(ChainError::OutOfRange));
    assert_eq!(walk(&g, &t, g.max_cluster), Err(ChainError::OutOfRange), "and neither is the start");
    assert_eq!(walk(&g, &t, 0), Err(ChainError::OutOfRange));
    assert_eq!(walk(&g, &t, 1), Err(ChainError::OutOfRange));
}

/// A free entry in the middle of a chain is a corrupt table: the file claims
/// a cluster the volume believes nobody owns. Following it would read another
/// file's data, or data that was deleted.
#[test]
fn a_free_entry_mid_chain_is_refused() {
    let g = geo(FatWidth::Fat16);
    let mut t = vec![0u8; 128 * 512];
    put16(&mut t, 2, 3);
    // Cluster 3's entry is left free.
    assert_eq!(walk(&g, &t, 2), Err(ChainError::OutOfRange));
}

/// A table too short for the entry the walk needs stops the walk, rather than
/// reading past what was provided.
#[test]
fn a_short_table_stops_the_walk() {
    let g = geo(FatWidth::Fat16);
    // Long enough for cluster 2's entry and not for cluster 3's, which the
    // walk needs next.
    let mut t = vec![0u8; 6];
    put16(&mut t, 2, 3);
    assert_eq!(read_entry(FatWidth::Fat16, &t, 3), None, "the fixture really is short");
    assert_eq!(walk(&g, &t, 2), Err(ChainError::TableTooShort));
}

/// A FAT12 chain walks the same way, through the shared bytes.
#[test]
fn a_twelve_bit_chain_walks_through_its_shared_bytes() {
    let g = geo(FatWidth::Fat12);
    let mut t = vec![0u8; 12 * 512];
    put12(&mut t, 2, 3);
    put12(&mut t, 3, 4);
    put12(&mut t, 4, 0xFFF);
    assert_eq!(walk(&g, &t, 2), Ok(vec![2, 3, 4]));
}

/// Cluster counts round up, and a zero-length file occupies none — which is
/// why its entry names no cluster at all.
#[test]
fn a_file_occupies_whole_clusters_and_an_empty_one_occupies_none() {
    let g = geo(FatWidth::Fat16);
    assert_eq!(g.cluster_bytes(), 512);
    assert_eq!(clusters_for_size(&g, 0), 0);
    assert_eq!(clusters_for_size(&g, 1), 1);
    assert_eq!(clusters_for_size(&g, 512), 1);
    assert_eq!(clusters_for_size(&g, 513), 2);
    assert_eq!(clusters_for_size(&g, u32::MAX as u64), 8_388_608);
}
