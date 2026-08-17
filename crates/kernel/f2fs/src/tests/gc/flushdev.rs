//! Emptying one member device of a spread volume onto the rest.
//!
//! The fixture spreads the image so that member zero owns several main-area
//! segments and member one owns the rest. A file written before the log is
//! sealed therefore has live blocks ON member zero, which is the shape the
//! command exists to undo — and the assertion is where the blocks END UP, not
//! how many were moved.

use alloc::vec::Vec;

use crate::mode::S_IFREG;
use crate::test_image::{self as image, spread, MAIN_BLKADDR, ROOT_INO};
use crate::uapi::*;
use crate::volume::{map::Mapped, NewInode, Volume};

use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 3);
/// A split that leaves member zero holding several main-area segments; an
/// even one leaves it holding almost none, since its span begins in the
/// metadata rather than at segment zero.
const SPLIT: [(&str, u32); 2] = [("/dev/a", 12), ("/dev/b", 3)];

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn seg_of(addr: u32) -> u32 { (addr - MAIN_BLKADDR) / BLKS_PER_SEG }

fn addr_of(v: &Volume<spread::Spread>, ino: u32, index: u64) -> u32 {
    let inode = v.read_inode(ino).unwrap();
    match v.map_block(&inode, ino, index).unwrap() {
        Mapped::At(a) => a,
        _ => panic!("the file's block is not a block"),
    }
}

fn addrs(v: &Volume<spread::Spread>, ino: u32, n: u64) -> Vec<u32> {
    (0..n).map(|i| addr_of(v, ino, i)).collect()
}

/// A spread volume with a four-block file whose segment no log holds open.
fn payload() -> Vec<u8> {
    (0..4 * BLKSIZE).map(|i| (i / BLKSIZE * 37 + i % 251) as u8).collect()
}

fn fixture() -> (Volume<spread::Spread>, u32) {
    let mut v = spread::mount(image::with_root().devices(&SPLIT)).expect("mounts");
    let ino = v.create(ROOT_INO, b"onmember0", &spec(), None).unwrap();
    let data = payload();
    v.write_file(ino, 0, &data).unwrap();
    v.sync_data().unwrap();
    // Sealing the log writes the segment's summary block, which the cleaner
    // cannot work without, and moves the log off the segment.
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    (v, ino)
}

/// The window the command works over, so the rest of the file can say which
/// segments count as "on member zero".
fn window(v: &Volume<spread::Spread>, dev: usize, segments: u32) -> (u32, u32) {
    v.flush_device_window(dev, segments, 0).expect("the member has a range")
}

#[test]
fn the_fixture_puts_live_blocks_on_the_member_to_be_emptied() {
    let (v, ino) = fixture();
    assert_eq!(v.devices().len(), 2);
    let (first, last) = window(&v, 0, u32::MAX);
    assert!(last > first, "member zero holds no main-area segment to empty");
    for a in addrs(&v, ino, 4) {
        assert!(seg_of(a) >= first && seg_of(a) < last,
                "the fixture's blocks are not on the member being emptied");
    }
}

#[test]
fn emptying_a_member_moves_its_live_blocks_off_it() {
    let (mut v, ino) = fixture();
    let (first, last) = window(&v, 0, u32::MAX);
    let before = addrs(&v, ino, 4);
    v.flush_device(0, last - first).expect("the member empties");
    let after = addrs(&v, ino, 4);
    assert_ne!(before, after, "nothing moved");
    for a in &after {
        let s = seg_of(*a);
        assert!(s < first || s >= last, "a block is still inside the emptied range");
    }
    // And the file still reads what was written, which is the only thing a
    // caller notices about a move done right.
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), payload());
}

#[test]
fn a_request_walks_the_member_rather_than_restarting_at_its_first_segment() {
    let (mut v, _) = fixture();
    let (first, last) = window(&v, 0, u32::MAX);
    assert!(last - first >= 2, "the split must leave more than one segment to walk");
    v.flush_device(0, 1).unwrap();
    // The cursor records the segment ATTEMPTED, so the next request resumes
    // on it rather than stepping over it — which is what the reference does.
    assert_eq!(v.segstate.flush_dev_cursor, first);
    v.flush_device(0, 2).unwrap();
    assert_eq!(v.segstate.flush_dev_cursor, first + 1);
}

/// A cursor left outside the member — by an earlier request against another
/// member, or by one that reached the end — restarts at the member's first
/// segment rather than cleaning somebody else's segments.
#[test]
fn a_cursor_outside_the_member_restarts_at_its_first_segment() {
    let (mut v, _) = fixture();
    let (first, last) = window(&v, 0, u32::MAX);
    v.segstate.flush_dev_cursor = last + 5;
    v.flush_device(0, 1).unwrap();
    assert_eq!(v.segstate.flush_dev_cursor, first);
}

/// The ordinary victim search is pushed past the window, so a search running
/// after the request cannot choose a victim inside the range being emptied
/// and write its blocks straight back onto the member.
#[test]
fn emptying_pushes_the_ordinary_victim_search_past_the_window() {
    let (mut v, _) = fixture();
    let (first, last) = window(&v, 0, u32::MAX);
    v.segstate.gc_cursor = first;
    v.flush_device(0, last - first).unwrap();
    assert_eq!(v.segstate.gc_cursor, last + 1);
}

#[test]
fn a_member_the_volume_does_not_have_is_refused() {
    let (mut v, _) = fixture();
    assert_eq!(v.flush_device(9, 1), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_cannot_empty_a_member() {
    let (media, table) = spread::members(image::with_root().devices(&SPLIT));
    let set = crate::devices::DeviceSet::new(media, table).unwrap();
    let mut v = Volume::mount_devices(set, crate::opts::Options::defaults(), false, &[]).unwrap();
    assert_eq!(v.flush_device(0, 1), Err(Errno::Erofs));
}
