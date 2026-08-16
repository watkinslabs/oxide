//! The member spans, and the address-to-member lookup.

use alloc::string::String;
use alloc::vec::Vec;

use crate::devices::{DevSpec, DevTable};
use crate::sb::SuperBlock;
use crate::test_image as image;
use crate::uapi::{BLKSIZE, SUPER_OFFSET, SUPER_SIZE};

/// The fixture's superblock, with `devs` named as its members. # C: O(image)
fn sb(devs: &[(&str, u32)]) -> SuperBlock {
    let bytes = image::Builder::new().devices(devs).finish();
    crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).expect("parses")
}

fn spec(path: &str, segs: u32) -> DevSpec {
    DevSpec { path: String::from(path), total_segments: segs }
}

#[test]
fn a_volume_naming_no_member_is_still_one_member() {
    let t = DevTable::scan(&sb(&[]));
    assert_eq!(t.len(), 1);
    assert!(!t.is_multi());
    assert_eq!(t.target(12345), (0, 12345));
}

#[test]
fn the_first_members_span_covers_the_metadata_before_segment_zero() {
    // The segment counts describe segments; the blocks before segment zero
    // belong to the first member too, and a span that omits them puts every
    // later member's blocks one metadata-length too low.
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let per_seg = s.blks_per_seg();
    assert_eq!(t.get(0).unwrap().start_blk, 0);
    assert_eq!(t.get(0).unwrap().end_blk, 8 * per_seg - 1 + s.segment0_blkaddr);
}

#[test]
fn members_tile_the_address_space_without_gap_or_overlap() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 4), ("/dev/c", 3)]);
    let t = DevTable::scan(&s);
    assert_eq!(t.len(), 3);
    for w in t.devs().windows(2) {
        assert_eq!(w[0].end_blk + 1, w[1].start_blk);
    }
    let last = t.devs().last().unwrap();
    assert_eq!(u64::from(last.end_blk) + 1, s.max_blkaddr());
}

#[test]
fn each_span_is_its_own_segment_count() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 4), ("/dev/c", 3)]);
    let t = DevTable::scan(&s);
    let per_seg = u64::from(s.blks_per_seg());
    for (i, d) in t.devs().iter().enumerate() {
        let mut want = u64::from(d.total_segments) * per_seg;
        if i == 0 { want += u64::from(s.segment0_blkaddr); }
        assert_eq!(u64::from(d.end_blk - d.start_blk) + 1, want, "member {i}");
    }
}

#[test]
fn an_address_resolves_to_the_member_holding_it_and_its_offset_there() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let first_of_b = t.get(1).unwrap().start_blk;
    assert_eq!(t.target(0), (0, 0));
    assert_eq!(t.target(first_of_b - 1), (0, first_of_b - 1));
    assert_eq!(t.target(first_of_b), (1, 0));
    assert_eq!(t.target(first_of_b + 9), (1, 9));
}

#[test]
fn an_address_no_member_claims_is_left_unshifted() {
    // Shifting it would turn a read that must fail into a read of some other
    // member's block.
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let past = u32::try_from(s.max_blkaddr()).unwrap() + 1;
    assert_eq!(t.target(past), (0, past));
}

#[test]
fn the_recorded_paths_survive_into_the_table() {
    let t = DevTable::scan(&sb(&[("/dev/vda", 8), ("/dev/vdb", 7)]));
    assert_eq!(t.get(0).unwrap().path, "/dev/vda");
    assert_eq!(t.get(1).unwrap().path, "/dev/vdb");
}

#[test]
fn segment_counts_that_do_not_sum_to_the_volume_are_refused() {
    // The superblock's own cross-check: a volume whose members do not add up
    // has an address space nothing can tile.
    let bytes = image::Builder::new().devices(&[("/dev/a", 8), ("/dev/b", 6)]).finish();
    let raw = &bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE];
    let parsed = crate::sb::parse(raw).expect("parses");
    assert!(crate::sb::check(&parsed, raw).is_err());
}

#[test]
fn a_table_built_by_hand_addresses_the_same_way_as_one_scanned() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let scanned = DevTable::scan(&s);
    let by_hand = DevTable::from_parts(scanned.devs().to_vec());
    for addr in [0u32, 1, 4095, u32::try_from(s.max_blkaddr()).unwrap() - 1] {
        assert_eq!(scanned.target(addr), by_hand.target(addr), "addr {addr}");
    }
}

#[test]
fn a_span_holds_exactly_its_own_addresses() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let d = t.get(1).unwrap();
    assert!(!d.holds(d.start_blk - 1));
    assert!(d.holds(d.start_blk));
    assert!(d.holds(d.end_blk));
    assert!(!d.holds(d.end_blk + 1));
}

#[test]
fn eight_members_are_all_read_back() {
    let names: Vec<(&str, u32)> =
        alloc::vec![("/dev/a", 8), ("/dev/b", 1), ("/dev/c", 1), ("/dev/d", 1),
                    ("/dev/e", 1), ("/dev/f", 1), ("/dev/g", 1), ("/dev/h", 1)];
    let s = sb(&names);
    assert_eq!(s.devices.len(), 8);
    assert_eq!(s.devices[7], spec("/dev/h", 1));
    assert_eq!(DevTable::scan(&s).len(), 8);
}

#[test]
fn one_block_of_every_member_addresses_inside_that_member() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 4), ("/dev/c", 3)]);
    let t = DevTable::scan(&s);
    for (i, d) in t.devs().iter().enumerate() {
        let (member, local) = t.target(d.end_blk);
        assert_eq!(member, i);
        assert_eq!(local, d.end_blk - d.start_blk);
        assert!(u64::from(local) * BLKSIZE as u64 <= s.max_blkaddr() * BLKSIZE as u64);
    }
}
