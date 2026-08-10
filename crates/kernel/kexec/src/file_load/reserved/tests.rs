use super::*;

/// The interrupt-controller tables a relocation on this machine has to keep
/// clear, at the granule they are allocated and adopted at.
const PROP: (u64, u64) = (0xbf33_8000, 0x1_0000);
const PEND: (u64, u64) = (0xbf31_0000, 0x1_0000);

/// The machine's RAM, half-open.
const RAM: &[(u64, u64)] = &[(0x4000_0000, 0xc000_0000)];

#[test]
fn an_empty_reservation_describes_no_memory() {
    assert!(normalize(&[]).is_empty());
    assert!(normalize(&[(0xbf33_8000, 0)]).is_empty(), "zero length reserves nothing");
    assert_eq!(subtract(RAM, &[]), RAM.to_vec(), "nothing reserved leaves the map alone");
}

#[test]
fn a_reservation_is_rounded_outwards_to_whole_pages() {
    // A byte past a page boundary at each end must pull the whole page in:
    // half a reserved page is a page an allocator still hands out.
    assert_eq!(normalize(&[(0x4000_0fff, 2)]), alloc::vec![(0x4000_0000, 0x2000)]);
    assert_eq!(normalize(&[(0x4000_0000, 1)]), alloc::vec![(0x4000_0000, 0x1000)]);
    // Already whole pages stay exactly as they are.
    assert_eq!(normalize(&[PROP]), alloc::vec![PROP]);
}

#[test]
fn reservations_are_sorted_and_merged_when_they_meet() {
    // Recorded in the order the hardware was set up, which is not address
    // order; the pending table sits below the configuration table here.
    assert_eq!(normalize(&[PROP, PEND]), alloc::vec![PEND, PROP],
               "sorted by address, and left as two entries when they do not meet");
    // Abutting: one extent, not two.
    assert_eq!(normalize(&[(0x1000, 0x1000), (0x2000, 0x1000)]), alloc::vec![(0x1000, 0x2000)]);
    // Overlapping, and the shorter one enclosed by the longer.
    assert_eq!(normalize(&[(0x1000, 0x4000), (0x2000, 0x1000)]), alloc::vec![(0x1000, 0x4000)]);
    assert_eq!(normalize(&[(0x1000, 0x2000), (0x2000, 0x2000)]), alloc::vec![(0x1000, 0x3000)]);
}

#[test]
fn a_reservation_inside_a_range_splits_it_rather_than_truncating_it() {
    // This is the machine in the evidence: both tables sit near the top of a
    // single 2 GiB range, and the memory ABOVE them is still usable.
    let out = subtract(RAM, &[PROP, PEND]);
    assert_eq!(out, alloc::vec![
        (0x4000_0000, 0xbf31_0000),
        (0xbf32_0000, 0xbf33_8000),
        (0xbf34_8000, 0xc000_0000),
    ]);
    let total: u64 = out.iter().map(|(s, e)| e - s).sum();
    assert_eq!(total, (0xc000_0000u64 - 0x4000_0000) - 2 * 0x1_0000,
               "exactly the two tables are gone, and nothing else");
}

#[test]
fn no_surviving_range_overlaps_a_reservation() {
    // The property the placement search depends on, stated directly: whatever
    // subtract returns, a destination chosen anywhere inside it cannot be
    // inside a reserved table.
    for ram in [RAM, &[(0x4000_0000, 0x8000_0000), (0xbf30_0000, 0xc000_0000)][..]] {
        for (s, e) in subtract(ram, &[PROP, PEND]) {
            for (pa, len) in [PROP, PEND] {
                assert!(e <= pa || s >= pa + len,
                        "[{s:#x},{e:#x}) overlaps the reservation at {pa:#x}");
            }
        }
    }
}

#[test]
fn a_reservation_at_an_edge_trims_and_one_outside_the_map_changes_nothing() {
    assert_eq!(subtract(&[(0x1000, 0x5000)], &[(0x1000, 0x1000)]), alloc::vec![(0x2000, 0x5000)]);
    assert_eq!(subtract(&[(0x1000, 0x5000)], &[(0x4000, 0x1000)]), alloc::vec![(0x1000, 0x4000)]);
    // Covering the whole range removes it, leaving a map with no room rather
    // than a zero-length range a search would treat as usable.
    assert!(subtract(&[(0x1000, 0x5000)], &[(0x1000, 0x4000)]).is_empty());
    // Entirely outside, and exactly touching each end.
    assert_eq!(subtract(&[(0x1000, 0x5000)], &[(0x9000, 0x1000)]), alloc::vec![(0x1000, 0x5000)]);
    assert_eq!(subtract(&[(0x1000, 0x5000)], &[(0x5000, 0x1000)]), alloc::vec![(0x1000, 0x5000)]);
    assert_eq!(subtract(&[(0x1000, 0x5000)], &[(0x0, 0x1000)]), alloc::vec![(0x1000, 0x5000)]);
}
