//! The claim the extent cache exists to make: a cached answer is the answer
//! the node walk it replaces would have given.
//!
//! A cache that is merely fast is worthless. The failure it can produce is
//! returning a block that belongs to a different offset — or to a different
//! file — and a read of that block succeeds, returns the wrong bytes, and
//! reports nothing. So every test here resolves the same offset TWICE: once
//! through `map_block`, which consults the cache, and once through
//! `map_block_raw`, which is the walk with no cache in front of it. Any
//! disagreement is the defect the cache exists to be free of.
//!
//! The invalidation points are what make that true, and each has a test that
//! fails without it: a rewrite moves a block, a truncate removes a range of
//! them, and a freed inode number is handed to something else.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::stats::counters::extent_of;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::*;
use crate::volume::{map::Mapped, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 0);

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

fn with_file(name: &[u8]) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, name, &spec(), None).unwrap();
    (v, ino)
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// What the walk alone says about one offset, with no cache consulted.
fn walked(v: &Volume<MemImage>, ino: u32, index: u64) -> Mapped {
    let inode = v.read_inode(ino).unwrap();
    match v.map_block_raw(&inode, ino, index).unwrap() {
        None => Mapped::Hole,
        Some(a) if crate::node::is_compressed(a) => Mapped::Compressed,
        Some(a) if crate::node::is_hole(a) => Mapped::Hole,
        Some(a) => Mapped::At(a),
    }
}

/// Both answers, for every offset up to `upto`.
fn agree_upto(v: &Volume<MemImage>, ino: u32, upto: u64) {
    let inode = v.read_inode(ino).unwrap();
    for index in 0..upto {
        let cached = v.map_block(&inode, ino, index).unwrap();
        assert_eq!(cached, walked(v, ino, index),
                   "ino {ino} index {index}: the cache and the walk disagree");
    }
}

/// A deterministic sequence. A failure nobody can re-run is a failure nobody
/// can fix, so the generator is a fixed shift register rather than a clock.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 { self.next() % n.max(1) }
}

fn page(fill: u8) -> Vec<u8> { vec![fill; BLKSIZE] }

/// The headline claim, over a long run of writes at scattered offsets. Every
/// write moves a block, so every one is a chance for a remembered run to go
/// stale, and the check runs after each.
#[test]
fn a_cached_block_is_always_the_block_the_walk_would_have_found() {
    let (mut v, ino) = with_file(b"f");
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let span = 40u64;
    for step in 0..120u64 {
        let at = rng.below(span);
        v.write_file(ino, at * BLKSIZE as u64, &page((step & 0xff) as u8)).unwrap();
        agree_upto(&v, ino, span);
    }
}

/// A rewrite is where a stale run bites hardest: the offset still exists, so a
/// cache that was not told answers confidently with the block the file used to
/// have and the read returns its PREVIOUS contents.
#[test]
fn rewriting_a_block_moves_the_answer_the_cache_gives() {
    let (mut v, ino) = with_file(b"f");
    v.write_file(ino, 0, &page(1)).unwrap();
    v.write_file(ino, BLKSIZE as u64, &page(2)).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let first = v.map_block(&inode, ino, 0).unwrap();
    v.write_file(ino, 0, &page(3)).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let after = v.map_block(&inode, ino, 0).unwrap();
    assert_ne!(first, after, "an out-of-place rewrite left the block where it was");
    assert_eq!(after, walked(&v, ino, 0));
    assert_eq!(v.read_whole(&inode, ino).unwrap()[0], 3);
}

/// A truncate frees whole node subtrees, so the per-address notification the
/// write path relies on never fires for them.
#[test]
fn a_truncated_tail_stops_being_answered_for() {
    let (mut v, ino) = with_file(b"f");
    let span = 24u64;
    for i in 0..span { v.write_file(ino, i * BLKSIZE as u64, &page(i as u8)).unwrap(); }
    agree_upto(&v, ino, span);
    v.truncate_file(ino, 4 * BLKSIZE as u64).unwrap();
    agree_upto(&v, ino, span);
    let inode = v.read_inode(ino).unwrap();
    for index in 4..span {
        assert_eq!(v.map_block(&inode, ino, index).unwrap(), Mapped::Hole,
                   "index {index} is past the end and still has an address");
    }
}

/// A freed inode number is handed to the next file created. Anything the cache
/// still remembers under it would answer for a file it never described.
#[test]
fn a_reused_inode_number_inherits_nothing() {
    let (mut v, ino) = with_file(b"f");
    for i in 0..6u64 { v.write_file(ino, i * BLKSIZE as u64, &page(9)).unwrap(); }
    agree_upto(&v, ino, 6);
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    let again = v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    let inode = v.read_inode(again).unwrap();
    for index in 0..6u64 {
        assert_eq!(v.map_block(&inode, again, index).unwrap(), Mapped::Hole,
                   "a fresh file answered for index {index}");
    }
}

/// The cache survives the file being written back and read again, which is the
/// case a seeded run has to be right about: the seed comes off the inode.
#[test]
fn the_answers_agree_again_after_a_remount() {
    let (mut v, ino) = with_file(b"f");
    for i in 0..12u64 { v.write_file(ino, i * BLKSIZE as u64, &page(i as u8)).unwrap(); }
    let v = remount(v);
    agree_upto(&v, ino, 12);
}

/// A file whose contents move INTO the inode has no blocks at all any more.
#[test]
fn a_file_that_becomes_inline_answers_for_nothing() {
    let (mut v, ino) = with_file(b"f");
    v.write_file(ino, 0, &page(7)).unwrap();
    agree_upto(&v, ino, 1);
    v.truncate_file(ino, 0).unwrap();
    v.write_file(ino, 0, b"small").unwrap();
    agree_upto(&v, ino, 1);
}

/// Every lookup that consults a tree is counted, and the answer is charged to
/// the structure that gave it. Without this the ratio the report publishes is
/// a number over an empty denominator.
#[test]
fn the_report_counts_the_lookups_the_cache_answered() {
    let (mut v, ino) = with_file(b"f");
    for i in 0..8u64 { v.write_file(ino, i * BLKSIZE as u64, &page(1)).unwrap(); }
    let before = v.counters();
    let inode = v.read_inode(ino).unwrap();
    for index in 0..8u64 { v.map_block(&inode, ino, index).unwrap(); }
    let after = v.counters();
    assert!(after.total_hit_ext[extent_of::READ] >= before.total_hit_ext[extent_of::READ] + 8,
            "eight lookups were not counted");
    assert!(after.hit_total(extent_of::READ) > before.hit_total(extent_of::READ),
            "no lookup was charged to a structure");
}

/// The age cache is filled by the same write path, so its figures move too.
#[test]
fn the_report_counts_the_age_lookups_a_write_makes() {
    let bytes = test_image::with_root().finish();
    let mut opts = Options::defaults();
    opts.age_extent_cache = true;
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), opts, true)
        .unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for i in 0..8u64 { v.write_file(ino, i * BLKSIZE as u64, &page(1)).unwrap(); }
    let c = v.counters();
    assert!(c.total_hit_ext[extent_of::BLOCK_AGE] > 0, "no age lookup was counted");
    assert!(c.allocated_data_blocks > 0, "no data block was counted as allocated");
}

/// A mount told not to keep the cache keeps none, and still answers correctly
/// — the walk is the answer either way.
#[test]
fn a_mount_without_the_cache_still_answers_from_the_walk() {
    let bytes = test_image::with_root().finish();
    let mut opts = Options::defaults();
    opts.extent_cache = false;
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), opts, true)
        .unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    for i in 0..10u64 { v.write_file(ino, i * BLKSIZE as u64, &page(2)).unwrap(); }
    agree_upto(&v, ino, 10);
    let (trees, _, nodes) = v.extent_cache_counts();
    assert_eq!((trees[extent_of::READ], nodes[extent_of::READ]), (0, 0),
               "a mount that refused the cache built one anyway");
}
