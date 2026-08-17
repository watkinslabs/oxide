//! The address a rewrite lands on, against a real volume.
//!
//! The property under test is the ADDRESS. A test that only checked the bytes
//! would pass whether the write went in place or out of it, which is the one
//! thing these decisions change — so every test here asserts the block address
//! the file's own node names, before and after.

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::place::bits;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{Holder, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A writable volume holding one file with one placed block, that file's
/// number, and the address the block landed on.
fn with_placed_block(policy: u32) -> (Volume<MemImage>, u32, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.set_ipu_policy(bits::DISABLE).unwrap();
    v.write_file(ino, 0, &alloc::vec![0xA1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let at = slot(&v, ino, 0);
    assert!(at > 1, "the first write did not place a block");
    v.set_ipu_policy(policy).unwrap();
    (v, ino, at)
}

/// What the file's node says about block `index`.
fn slot(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    v.holder_addr(ino, Holder::Inode, index as usize).unwrap()
}

fn rewrite(v: &mut Volume<MemImage>, ino: u32, byte: u8) {
    v.write_file(ino, 0, &alloc::vec![byte; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
}

/// The control for every test below: with nothing armed the rewrite MOVES, so
/// an assertion that the address is unchanged is one that can fail.
#[test]
fn an_unarmed_mount_moves_the_block_on_a_rewrite() {
    let (mut v, ino, first) = with_placed_block(bits::DISABLE);
    rewrite(&mut v, ino, 0xB2);
    assert_ne!(slot(&v, ino, 0), first, "the rewrite kept the address with nothing armed");
}

/// Armed, the rewrite lands back on the same block — and the bytes that come
/// back are the new ones, so the write went somewhere that is read.
#[test]
fn an_armed_mount_rewrites_the_block_where_it_lies() {
    let (mut v, ino, first) = with_placed_block(bits::bit(bits::FORCE));
    rewrite(&mut v, ino, 0xB2);
    assert_eq!(slot(&v, ino, 0), first, "the rewrite moved the block");
    let i = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&i, ino).unwrap()[0], 0xB2, "the bytes did not land");
    assert_eq!(v.counters().inplace_count, 1, "the in-place write was not counted");
}

/// A rewrite in place leaves the block where the last checkpoint put it, so the
/// bytes survive a mount that reads nothing but the medium.
#[test]
fn the_bytes_of_an_in_place_rewrite_are_on_the_medium() {
    let (mut v, ino, first) = with_placed_block(bits::bit(bits::FORCE));
    rewrite(&mut v, ino, 0xB2);
    v.commit().unwrap();
    let bytes = v.source_ref().snapshot();
    let again = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                   crate::opts::Options::defaults(), true).unwrap();
    assert_eq!(slot(&again, ino, 0), first);
    let i = again.read_inode(ino).unwrap();
    assert_eq!(again.read_whole(&i, ino).unwrap()[0], 0xB2);
}

/// The `fsync` policy — the default on a volume big enough not to be tuned —
/// fires for the call that armed it and for nothing else.
#[test]
fn the_fsync_policy_reaches_the_flush_that_armed_it() {
    let (mut v, ino, first) = with_placed_block(bits::bit(bits::FSYNC));
    // An ordinary flush is not an fsync: the write moves.
    rewrite(&mut v, ino, 0xB2);
    let moved = slot(&v, ino, 0);
    assert_ne!(moved, first, "an unarmed flush kept the address");
    // A data sync of a short tail arms it, and the block stays put.
    v.write_file(ino, 0, &alloc::vec![0xC3u8; BLKSIZE]).unwrap();
    v.fdatasync(ino).unwrap();
    assert_eq!(slot(&v, ino, 0), moved, "the fsync policy did not reach the flush");
}

/// A directory's data is refused whatever is armed: its blocks are what makes
/// the volume navigable, and the previous checkpoint's copy is the only one a
/// replay has.
#[test]
fn a_directory_is_refused_in_place_writes() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.set_ipu_policy(bits::bit(bits::FORCE)).unwrap();
    let i = v.read_inode(ROOT_INO).unwrap();
    assert!(!v.writes_in_place(ROOT_INO, &i, v.super_block().main_blkaddr, true).unwrap());
}

/// The tuning is LIVE on a real mount: the fixture's image is sixteen
/// megabytes, and a mount of it that the fixture has not overridden arms the
/// whole in-place set. This is what makes the fixture's own override necessary
/// and what proves it is an override rather than the default.
#[test]
fn a_small_volume_arms_the_in_place_set_at_mount() {
    let v = Volume::mount_with(test_image::with_root().image(),
                               crate::opts::Options::defaults(), true).unwrap();
    assert_eq!(v.ipu_policy(), bits::bit(bits::FORCE) | bits::bit(bits::HONOR_OPU_WRITE));
    // A mount that never overwrites in place arms nothing, and refuses to be
    // told otherwise.
    let mut lfs = crate::opts::Options::defaults();
    lfs.mode = crate::opts::Mode::Lfs;
    let mut v = Volume::mount_with(test_image::with_root().image(), lfs, true).unwrap();
    assert_eq!(v.ipu_policy(), bits::DISABLE);
    assert!(v.set_ipu_policy(bits::bit(bits::FORCE)).is_err());
    assert!(v.set_ipu_policy(bits::bit(bits::NOCACHE)).is_ok());
    assert!(v.set_ipu_policy(bits::bit(bits::MAX)).is_err());
}

/// The recycling decision reads the VOLUME, not a mount option: the counts it
/// compares are the ones the volume answers with, and the fixture — eight
/// segments, six of them held open by logs — is genuinely under pressure.
#[test]
fn the_recycling_decision_reads_the_volumes_own_counts() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    v.load_segments().unwrap();
    let n = v.ssr_state();
    assert_eq!(n.free_sections, v.free_section_count());
    assert_eq!(n.reserved_sections, v.reserved_sections());
    assert_eq!(n.min_ssr_sections, v.reserved_sections());
    assert!(!n.lfs);
    assert!(v.need_ssr(), "two free sections against a floor of two is not pressure");
    // The mount's own mode reaches the same decision: an append-only volume
    // never recycles, however little room it has.
    let mut lfs = crate::opts::Options::defaults();
    lfs.mode = crate::opts::Mode::Lfs;
    let mut v = test_image::with_root().mount_opts(lfs).unwrap();
    v.load_segments().unwrap();
    assert!(!v.need_ssr());
}

/// The cleaner's mode reaches the allocator. Read from the background state the
/// mount shares with its threads rather than copied into the volume, so a knob
/// turned after the mount is seen by the next allocation.
#[test]
fn the_cleaners_urgency_reaches_the_allocator() {
    use crate::bg::gc::GcMode;
    let mut v = test_image::with_root().mount_rw().unwrap();
    assert!(!v.gc_urgent_high(), "nothing is cleaning and something was urgent");
    let bg = alloc::sync::Arc::new(crate::bg::Bg::new(crate::opts::BackgroundGc::On,
                                                     crate::opts::DiscardUnit::Block, 1));
    v.attach_bg(alloc::sync::Arc::clone(&bg));
    assert!(!v.gc_urgent_high());
    bg.set_gc_mode(GcMode::UrgentHigh);
    assert!(v.gc_urgent_high(), "the knob did not reach the volume");
    bg.set_gc_mode(GcMode::Normal);
    assert!(!v.gc_urgent_high());
}

/// The decision reaches the ALLOCATOR: under pressure, with a partly-used
/// segment to take, a log that has to reopen recycles instead of appending —
/// and an append-only mount of the same volume opens a fresh segment.
#[test]
fn a_log_under_pressure_recycles_a_partly_used_segment() {
    use crate::uapi::{ALLOC_LFS, ALLOC_SSR, CURSEG_WARM_DATA};
    let (mut v, ino) = fragmented();
    assert!(v.need_ssr());
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    assert_eq!(v.curseg[CURSEG_WARM_DATA].alloc_type, ALLOC_SSR,
               "the log opened a fresh segment while the volume was out of sections");
    assert!(v.curseg[CURSEG_WARM_DATA].next_blkoff > 0,
             "a recycled segment was entered at its first block");
    let _ = ino;

    // The same volume, mounted append-only: no recycling, whatever the
    // pressure. The named line is `place::ssr::need_ssr`'s first arm.
    let mut lfs = crate::opts::Options::defaults();
    lfs.mode = crate::opts::Mode::Lfs;
    let bytes = v.source_ref().snapshot();
    let mut w = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), lfs, true)
        .unwrap();
    w.load_segments().unwrap();
    w.open_segment(CURSEG_WARM_DATA).unwrap();
    assert_eq!(w.curseg[CURSEG_WARM_DATA].alloc_type, ALLOC_LFS);
}

/// A volume with a segment that is partly live: a file long enough to fill one,
/// with its first half released.
fn fragmented() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    let blocks = crate::uapi::BLKS_PER_SEG as usize + 8;
    v.write_file(ino, 0, &alloc::vec![0xD4u8; blocks * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    v.truncate_file(ino, (blocks as u64 / 2) * BLKSIZE as u64).unwrap();
    v.commit().unwrap();
    v.load_segments().unwrap();
    (v, ino)
}
