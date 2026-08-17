//! Handing blocks over: what the two files hold afterwards, and where.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
const BLK: u64 = BLKSIZE as u64;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn page(tag: u8) -> Vec<u8> { vec![tag; BLKSIZE] }

fn file(v: &mut Volume<MemImage>, name: &[u8], tags: &[u8]) -> u32 {
    let ino = v.create(ROOT_INO, name, &spec(), None).unwrap();
    for (i, t) in tags.iter().enumerate() {
        v.write_file(ino, i as u64 * BLK, &page(*t)).unwrap();
        v.sync_data().unwrap();
    }
    ino
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn tags(v: &Volume<MemImage>, ino: u32, n: u64) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    let mut out = vec![0u8; (n * BLK) as usize];
    v.read_file(&inode, ino, 0, &mut out).unwrap();
    (0..n).map(|i| out[(i * BLK) as usize]).collect()
}

// ---------------------------------------------------------------- the handover

#[test]
fn the_destination_ends_up_with_the_sources_blocks() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2, 3]);
    let dst = file(&mut v, b"b", &[9, 9, 9]);
    let was = (0..3).map(|i| v.mapped_addr(src, i).unwrap().unwrap()).collect::<Vec<_>>();
    v.exchange_blocks(src, dst, 0, 0, 3).unwrap();
    // The destination holds the very blocks the source held — nothing was
    // read and nothing was written, only the addresses moved.
    let now = (0..3).map(|i| v.mapped_addr(dst, i).unwrap().unwrap()).collect::<Vec<_>>();
    assert_eq!(now, was);
}

#[test]
fn the_source_is_left_with_holes() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2, 3]);
    let dst = file(&mut v, b"b", &[9, 9, 9]);
    v.exchange_blocks(src, dst, 0, 0, 3).unwrap();
    for i in 0..3 { assert_eq!(v.mapped_addr(src, i).unwrap(), None); }
}

#[test]
fn the_bytes_read_back_from_the_destination_after_a_remount() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2, 3]);
    let dst = file(&mut v, b"b", &[9, 9, 9]);
    v.exchange_blocks(src, dst, 0, 0, 3).unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, dst, 3), vec![1, 2, 3]);
    // And the source reads as the holes it now is.
    assert_eq!(tags(&v, src, 3), vec![0, 0, 0]);
}

#[test]
fn a_hole_in_the_source_leaves_the_destination_untouched() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = v.create(ROOT_INO, b"a", &spec(), None).unwrap();
    v.write_file(src, 0, &page(1)).unwrap();
    v.sync_data().unwrap();
    v.write_file(src, 2 * BLK, &page(3)).unwrap();
    v.sync_data().unwrap();
    let dst = file(&mut v, b"b", &[9, 9, 9]);
    v.exchange_blocks(src, dst, 0, 0, 3).unwrap();
    let v = remount(v);
    // Block one was a hole in the source, so the destination keeps its own.
    assert_eq!(tags(&v, dst, 3), vec![1, 9, 3]);
}

#[test]
fn the_destinations_old_blocks_come_back_to_the_volume() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2, 3]);
    let dst = file(&mut v, b"b", &[9, 9, 9]);
    let doomed = (0..3).map(|i| v.mapped_addr(dst, i).unwrap().unwrap()).collect::<Vec<_>>();
    v.exchange_blocks(src, dst, 0, 0, 3).unwrap();
    v.load_segments().unwrap();
    for a in doomed { assert!(!v.block_is_live(a).unwrap(), "block {a} was leaked"); }
}

#[test]
fn a_block_the_cleaner_would_move_now_names_its_new_owner() {
    // The summary is the cleaner's only record of who owns a block. One still
    // naming the source would put the block back into the source at the next
    // clean, and leave the destination pointing at whatever took its place.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2, 3]);
    let dst = file(&mut v, b"b", &[9]);
    let moved = v.mapped_addr(src, 0).unwrap().unwrap();
    v.exchange_blocks(src, dst, 0, 0, 1).unwrap();
    let (holder, ofs) = v.dnode_for_write(dst, 0).unwrap();
    let expect = match holder {
        crate::volume::Holder::Inode => dst,
        crate::volume::Holder::Direct(nid) => nid,
    };
    let off = moved - v.super_block().main_blkaddr;
    let segno = off / crate::uapi::BLKS_PER_SEG;
    let slot = (off % crate::uapi::BLKS_PER_SEG) as usize;
    let log = v.logs().iter().position(|c| c.segno == segno)
        .expect("the block should still be in an open log");
    let sum = v.logs()[log].summary(slot);
    assert_eq!(sum.nid, expect);
    assert_eq!(sum.ofs_in_node, ofs as u16);
}

#[test]
fn moving_a_range_within_one_file_moves_the_blocks_not_the_bytes() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = file(&mut v, b"a", &[1, 2, 3, 4]);
    let was = v.mapped_addr(ino, 2).unwrap().unwrap();
    v.exchange_blocks(ino, ino, 2, 0, 2).unwrap();
    assert_eq!(v.mapped_addr(ino, 0).unwrap(), Some(was));
    let v = remount(v);
    assert_eq!(tags(&v, ino, 4), vec![3, 4, 0, 0]);
}

#[test]
fn a_block_whose_summary_is_already_on_the_medium_is_copied_instead() {
    // Its owner is recorded in the summary area rather than in an open log,
    // and rewriting that record in place would break the state a crash
    // recovers to. So the bytes are copied and the source's slot punched —
    // the same result, reached the only safe way.
    let mut v = test_image::with_root().mount_rw().unwrap();
    let src = file(&mut v, b"a", &[1, 2]);
    let dst = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    // Bytes cannot be handed to a file whose bytes live inside its inode;
    // the whole move does this itself, and this test drives the exchange
    // alone.
    v.convert_inline(dst).unwrap();
    let was = (0..2).map(|i| v.mapped_addr(src, i).unwrap().unwrap()).collect::<Vec<_>>();
    let log = crate::volume::curseg::log_for(crate::volume::Kind::FileData,
                                             v.options().active_logs);
    v.open_segment(log).unwrap();
    v.exchange_blocks(src, dst, 0, 0, 2).unwrap();
    let now = (0..2).map(|i| v.mapped_addr(dst, i).unwrap().unwrap()).collect::<Vec<_>>();
    assert_ne!(now, was, "the block should have been copied, not repointed");
    for i in 0..2 { assert_eq!(v.mapped_addr(src, i).unwrap(), None); }
    v.stamp_inode(dst, |b| crate::volume::dnode::put64(b, crate::uapi::I_SIZE, 2 * BLK))
        .unwrap();
    let v = remount(v);
    assert_eq!(tags(&v, dst, 2), vec![1, 2]);
}

#[test]
fn a_volume_that_never_overwrites_in_place_refuses_to_repoint() {
    // Repointing rewrites a summary entry. A mount asked never to overwrite
    // anything is told so rather than quietly doing it.
    let mut opts = Options::defaults();
    opts.mode = crate::opts::Mode::Lfs;
    let mut v = test_image::with_root().mount_opts(opts).unwrap();
    let src = file(&mut v, b"a", &[1, 2]);
    let dst = v.create(ROOT_INO, b"b", &spec(), None).unwrap();
    v.convert_inline(dst).unwrap();
    assert_eq!(v.exchange_blocks(src, dst, 0, 0, 1), Err(Errno::Eopnotsupp));
}
