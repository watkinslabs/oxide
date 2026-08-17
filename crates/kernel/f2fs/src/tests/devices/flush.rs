//! The segment window one member occupies.

use crate::devices::{flush, DevTable};
use crate::sb::SuperBlock;
use crate::test_image as image;
use crate::uapi::{SUPER_OFFSET, SUPER_SIZE};

fn sb(devs: &[(&str, u32)]) -> SuperBlock {
    let bytes = image::Builder::new().devices(devs).finish();
    crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).expect("parses")
}

#[test]
fn the_first_member_starts_at_segment_zero() {
    // Its span begins in the metadata, which is in no main-area segment at
    // all; asking which segment its first block is in has no answer.
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let (first, _) = flush::segno_range(&s, &t, 0).unwrap();
    assert_eq!(first, 0);
}

#[test]
fn a_later_members_range_starts_where_its_blocks_do() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let start = t.get(1).unwrap().start_blk;
    let (first, last) = flush::segno_range(&s, &t, 1).unwrap();
    assert_eq!(first, s.segno_of(start).unwrap());
    assert_eq!(last, s.segno_of(t.get(1).unwrap().end_blk).unwrap());
    assert!(last >= first);
}

#[test]
fn a_member_that_does_not_exist_has_no_range() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    assert!(flush::segno_range(&s, &t, 2).is_none());
}

#[test]
fn a_cursor_outside_the_member_restarts_at_its_first_segment() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let (first, last) = flush::segno_range(&s, &t, 1).unwrap();
    assert_eq!(flush::window(&s, &t, 1, 2, 0).unwrap().0, first);
    assert_eq!(flush::window(&s, &t, 1, 2, last + 5).unwrap().0, first);
}

#[test]
fn a_cursor_inside_the_member_is_kept() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let (first, last) = flush::segno_range(&s, &t, 1).unwrap();
    if last > first + 1 {
        assert_eq!(flush::window(&s, &t, 1, 1, first + 1).unwrap().0, first + 1);
    }
}

#[test]
fn the_window_never_runs_past_the_member() {
    let s = sb(&[("/dev/a", 8), ("/dev/b", 7)]);
    let t = DevTable::scan(&s);
    let (_, last) = flush::segno_range(&s, &t, 1).unwrap();
    let (_, end) = flush::window(&s, &t, 1, u32::MAX, 0).unwrap();
    assert_eq!(end, last);
}
