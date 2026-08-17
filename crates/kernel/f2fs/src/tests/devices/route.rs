//! Splitting a request at the member boundaries.

use alloc::vec;
use alloc::vec::Vec;

use sectors::{MemImage, SectorSource};

use crate::devices::route::{split_at, Run};
use crate::devices::{DeviceSet, DevInfo, DevTable};
use crate::uapi::BLKSIZE;

/// Two members, the first four blocks long and the second six.
fn table() -> DevTable {
    DevTable::from_parts(vec![
        DevInfo { path: alloc::string::String::new(), total_segments: 0, start_blk: 0, end_blk: 3 },
        DevInfo { path: alloc::string::String::new(), total_segments: 0, start_blk: 4, end_blk: 9 },
    ])
}

fn one() -> DevTable {
    DevTable::from_parts(vec![
        DevInfo { path: alloc::string::String::new(), total_segments: 0, start_blk: 0,
                  end_blk: u32::MAX },
    ])
}

#[test]
fn a_request_inside_one_member_is_not_split() {
    let r = split_at(&table(), 1, 2 * BLKSIZE).unwrap();
    assert_eq!(r, vec![Run { member: 0, local: 1, at: 0, len: 2 * BLKSIZE }]);
}

#[test]
fn a_request_crossing_a_boundary_is_split_at_it() {
    let r = split_at(&table(), 2, 4 * BLKSIZE).unwrap();
    assert_eq!(r, vec![
        Run { member: 0, local: 2, at: 0, len: 2 * BLKSIZE },
        Run { member: 1, local: 0, at: 2 * BLKSIZE, len: 2 * BLKSIZE },
    ]);
}

#[test]
fn a_single_member_set_never_splits() {
    let r = split_at(&one(), 0, 40 * BLKSIZE).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].member, 0);
    assert_eq!(r[0].local, 0);
}

#[test]
fn the_pieces_cover_the_buffer_exactly_once() {
    let want = 9 * BLKSIZE;
    let r = split_at(&table(), 1, want).unwrap();
    let total: usize = r.iter().map(|p| p.len).sum();
    assert_eq!(total, want);
    let mut at = 0;
    for p in &r { assert_eq!(p.at, at); at += p.len; }
}

#[test]
fn reads_through_the_set_return_each_members_own_bytes() {
    let a = MemImage::from_bytes(BLKSIZE as u32, vec![0xAA; 4 * BLKSIZE]);
    let b = MemImage::from_bytes(BLKSIZE as u32, vec![0xBB; 6 * BLKSIZE]);
    let set = DeviceSet::new(vec![a, b], table()).unwrap();
    let mut buf = vec![0u8; 4 * BLKSIZE];
    set.read_sectors(2, &mut buf).unwrap();
    assert!(buf[..2 * BLKSIZE].iter().all(|&x| x == 0xAA));
    assert!(buf[2 * BLKSIZE..].iter().all(|&x| x == 0xBB));
}

#[test]
fn a_write_across_the_boundary_lands_on_both_members() {
    let a = MemImage::from_bytes(BLKSIZE as u32, vec![0; 4 * BLKSIZE]);
    let b = MemImage::from_bytes(BLKSIZE as u32, vec![0; 6 * BLKSIZE]);
    let set = DeviceSet::new(vec![a, b], table()).unwrap();
    let data = vec![0x5A; 4 * BLKSIZE];
    set.write_sectors(2, &data).unwrap();
    let mut back = vec![0u8; 4 * BLKSIZE];
    set.read_sectors(2, &mut back).unwrap();
    assert_eq!(back, data);
    // And nothing outside the written span moved.
    let mut before = vec![0u8; BLKSIZE];
    set.read_sectors(1, &mut before).unwrap();
    assert!(before.iter().all(|&x| x == 0));
}

#[test]
fn a_read_past_the_last_member_fails_rather_than_wrapping() {
    let a = MemImage::from_bytes(BLKSIZE as u32, vec![0; 4 * BLKSIZE]);
    let b = MemImage::from_bytes(BLKSIZE as u32, vec![0; 6 * BLKSIZE]);
    let set = DeviceSet::new(vec![a, b], table()).unwrap();
    let mut buf = vec![0u8; 2 * BLKSIZE];
    assert!(set.read_sectors(9, &mut buf).is_err());
}

#[test]
fn a_set_whose_media_do_not_match_its_spans_is_refused() {
    let a = MemImage::from_bytes(BLKSIZE as u32, vec![0; 4 * BLKSIZE]);
    assert!(DeviceSet::new(vec![a], table()).is_err());
    let empty: Vec<MemImage> = Vec::new();
    assert!(DeviceSet::new(empty, one()).is_err());
}

#[test]
fn the_set_is_writable_only_when_every_member_is() {
    let a = MemImage::from_bytes(BLKSIZE as u32, vec![0; 4 * BLKSIZE]);
    let b = MemImage::from_bytes(BLKSIZE as u32, vec![0; 6 * BLKSIZE]).read_only();
    let set = DeviceSet::new(vec![a, b], table()).unwrap();
    assert!(!set.writable());
    let a = MemImage::from_bytes(BLKSIZE as u32, vec![0; 4 * BLKSIZE]);
    let b = MemImage::from_bytes(BLKSIZE as u32, vec![0; 6 * BLKSIZE]);
    assert!(DeviceSet::new(vec![a, b], table()).unwrap().writable());
}
