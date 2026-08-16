//! Writing one table entry.

use super::geo;
use crate::chain::{self, Link};
use crate::cluster_alloc::entry::{end_mark, write_entry};
use crate::geometry::{FatWidth, Geometry};
use ::alloc::vec;
use syscall::errno::Errno;

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

/// The FAT12 boundary is `0xFF4`, not `0xFFF`: values above it are reserved,
/// and the width the geometry picks depends on that exact constant.
#[test]
fn the_twelve_bit_bad_boundary_stays_where_it_is() {
    assert_eq!(chain::BAD_FAT12, 0x0000_0FF7);
    assert_eq!(crate::geometry::MAX_FAT12, 0x0000_0FF4);
    assert_eq!(chain::classify(FatWidth::Fat12, 0x0FF6), Link::Next(0x0FF6), "below the bad mark");
    assert_eq!(chain::classify(FatWidth::Fat12, 0x0FF7), Link::End, "the bad mark itself");
    assert_eq!(chain::classify(FatWidth::Fat12, 0x0FFF), Link::End, "and the end mark");
    assert_eq!(end_mark(FatWidth::Fat12), 0x0FFF);
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

/// A write past the end of the table is refused rather than reaching past it.
#[test]
fn a_write_past_the_table_is_refused() {
    let mut t = vec![0u8; 8];
    assert_eq!(write_entry(FatWidth::Fat16, &mut t, 4, 1), Err(Errno::Eio));
    assert_eq!(write_entry(FatWidth::Fat32, &mut t, 2, 1), Err(Errno::Eio));
    assert_eq!(write_entry(FatWidth::Fat12, &mut t, 100, 1), Err(Errno::Eio));
    assert!(write_entry(FatWidth::Fat16, &mut t, 3, 1).is_ok(), "the last one that fits");
}
