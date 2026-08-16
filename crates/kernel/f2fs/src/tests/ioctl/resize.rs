//! Shrinking the volume, through the real command.
//!
//! The proof a resize worked is not that the call returned: it is that the
//! shrunk volume MOUNTS, that its three accounts of its own size agree, and
//! that the files it still holds read back. Every case here remounts the image
//! and asks it, because a superblock and a checkpoint that disagree are
//! exactly what a mount refuses and what an in-memory check cannot see.

use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::*;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 13);

fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

fn resize(v: &mut Volume<MemImage>, blocks: u64) -> Result<Answer, Errno> {
    handle(v, ROOT_INO, RESIZE_FS, &blocks.to_le_bytes(), &Extra::default(), &root())
}

/// A fixture volume whose recorded size lands on a section boundary.
///
/// A volume a formatter made always does: its first segment starts a section,
/// so its block count is a whole number of them. The shared fixture's areas
/// start two blocks in and its count therefore does not, and the rule the
/// command applies is the FORMAT's — a size that does not land on a section
/// boundary is refused — so the fixture is corrected here rather than the rule
/// bent around it.
/// # C: O(1 image)
fn vol() -> Volume<MemImage> {
    let img = MemImage::from_bytes(BLKSIZE as u32, test_image::with_root().finish());
    let (mut raw, sb) = crate::sbwrite::read_raw(&img).unwrap();
    let per = u64::from(sb.segs_per_sec) * u64::from(sb.blks_per_seg());
    let aligned = (sb.block_count / per) * per;
    crate::volume::dnode::put64(raw.bytes_mut(), crate::uapi::SB_BLOCK_COUNT, aligned);
    let mut flags = crate::sbflags::SbFlags::new();
    crate::sbwrite::commit_super(&img, &mut raw, false, false, &mut flags).unwrap();
    Volume::mount_with(img, Options::defaults(), true).unwrap()
}

/// # C: O(image)
fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// Blocks per section, which is the unit every size here is stated in.
/// # C: O(1)
fn per_sec(v: &Volume<MemImage>) -> u64 {
    u64::from(v.super_block().segs_per_sec) * u64::from(v.super_block().blks_per_seg())
}

#[test]
fn shrinking_by_one_section_moves_every_account_together() {
    let mut v = vol();
    let sb = v.super_block();
    let (was, secs, segs) = (sb.block_count, sb.section_count, sb.segment_count_main);
    let step = per_sec(&v);
    let user = v.checkpoint().user_block_count;
    resize(&mut v, was - step).unwrap();

    let sb = v.super_block();
    assert_eq!(sb.block_count, was - step);
    assert_eq!(sb.section_count, secs - 1);
    assert_eq!(sb.segment_count_main, segs - v.super_block().segs_per_sec);
    assert_eq!(v.checkpoint().user_block_count, user - step,
               "the checkpoint kept the space the superblock gave up");

    // And the same volume, read back off the medium by a fresh mount.
    let v = remount(v);
    assert_eq!(v.super_block().block_count, was - step);
    assert_eq!(v.super_block().section_count, secs - 1);
    assert_eq!(v.checkpoint().user_block_count, user - step);
}

#[test]
fn a_file_written_before_the_resize_still_reads_afterwards() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    let data: Vec<u8> = (0..3 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    v.write_file(ino, 0, &data).unwrap();
    let was = v.super_block().block_count;
    let step = per_sec(&v);
    resize(&mut v, was - step).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), data);
}

#[test]
fn nothing_live_is_left_in_the_sections_that_went() {
    // The whole point of emptying them first: an address past the volume's own
    // end is a file pointing at medium the volume no longer covers.
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    v.write_file(ino, 0, &vec![7u8; 2 * BLKSIZE]).unwrap();
    let was = v.super_block().block_count;
    let step = per_sec(&v);
    resize(&mut v, was - step).unwrap();
    let mut v = remount(v);
    v.load_segments().unwrap();
    let end = v.super_block().segment_count_main;
    let live: u32 = (0..end).map(|s| u32::from(v.seg_valid(s))).sum();
    assert_eq!(live as u64, v.valid_block_count,
               "the table and the volume's count disagree after the resize");
    // Every address the file holds is inside what the volume still covers.
    let inode = v.read_inode(ino).unwrap();
    for index in 0..2u64 {
        let a = v.stored_addr(&inode, ino, index).unwrap();
        assert!(v.sb_main_contains(a), "block {index} at {a} is past the new end");
    }
}

#[test]
fn growing_is_refused() {
    // The medium behind the volume is whatever it was; a bigger count would
    // hand out addresses nothing answers for.
    let mut v = vol();
    let was = v.super_block().block_count;
    let step = per_sec(&v);
    assert_eq!(resize(&mut v, was + step).map(|_| ()), Err(Errno::Einval));
    assert_eq!(v.super_block().block_count, was, "a refused resize changed the volume");
}

#[test]
fn a_size_that_is_not_a_whole_number_of_sections_is_refused() {
    let mut v = vol();
    let was = v.super_block().block_count;
    assert_eq!(resize(&mut v, was - 1).map(|_| ()), Err(Errno::Einval));
    assert_eq!(v.super_block().block_count, was);
}

#[test]
fn resizing_to_the_size_it_already_is_changes_nothing() {
    let mut v = vol();
    let was = v.super_block().block_count;
    let version = v.checkpoint().version;
    resize(&mut v, was).unwrap();
    assert_eq!(v.super_block().block_count, was);
    assert_eq!(v.checkpoint().version, version, "a no-op resize wrote a checkpoint");
}

#[test]
fn a_volume_that_cannot_spare_the_space_is_refused() {
    let mut v = vol();
    let was = v.super_block().block_count;
    let user = v.checkpoint().user_block_count;
    // Everything but a section's worth is in use, so giving a section up would
    // leave the volume over full.
    v.valid_block_count = user;
    let step = per_sec(&v);
    assert_eq!(resize(&mut v, was - step).map(|_| ()), Err(Errno::Enospc));
    assert_eq!(v.super_block().block_count, was);
}

#[test]
fn a_volume_already_needing_a_check_is_refused() {
    let mut v = vol();
    let was = v.super_block().block_count;
    v.sbi.set(crate::sbflags::bits::NEED_FSCK);
    let step = per_sec(&v);
    assert_eq!(resize(&mut v, was - step).map(|_| ()), Err(Errno::Euclean));
    assert_eq!(v.super_block().block_count, was);
}

#[test]
fn an_unprivileged_caller_is_refused() {
    let mut v = vol();
    let was = v.super_block().block_count;
    let c = Ctx { cap_sys_admin: false, ..root() };
    let p = (was - per_sec(&v)).to_le_bytes();
    assert_eq!(handle(&mut v, ROOT_INO, RESIZE_FS, &p, &Extra::default(), &c).map(|_| ()),
               Err(Errno::Eperm));
    assert_eq!(v.super_block().block_count, was);
}

#[test]
fn a_read_only_mount_is_refused() {
    let v = remount(vol());
    let bytes = v.into_source().snapshot();
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                   Options::defaults(), false).unwrap();
    let was = v.super_block().block_count;
    let p = (was - per_sec(&v)).to_le_bytes();
    assert_eq!(handle(&mut v, ROOT_INO, RESIZE_FS, &p, &Extra::default(), &root()).map(|_| ()),
               Err(Errno::Erofs));
}

/// Put the log that a file's data goes to at the top of the main area, so the
/// section a shrink gives up is one that is genuinely in use.
///
/// Without this the fixture's data and logs all sit at the bottom and a shrink
/// has nothing to empty: the test would pass whether or not the emptying
/// happened at all.
/// # C: O(1)
fn write_into_the_top_section(v: &mut Volume<MemImage>, ino: u32, bytes: &[u8]) -> u32 {
    v.load_segments().unwrap();
    let top = v.super_block().segment_count_main - 1;
    let log = v.logs().iter().position(|c| c.segno == 1).expect("a log at segment one");
    v.curseg[log].segno = top;
    v.curseg[log].next_blkoff = 0;
    v.curseg[log].alloc_type = crate::uapi::ALLOC_LFS;
    v.write_file(ino, 0, bytes).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let a = v.stored_addr(&inode, ino, 0).unwrap();
    assert_eq!(v.super_block().segno_of(a), Some(top), "the write did not land in the top section");
    top
}

#[test]
fn a_section_that_is_in_use_is_emptied_before_it_is_given_up() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f",
                       &NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW },
                       None).unwrap();
    let data: Vec<u8> = (0..2 * BLKSIZE).map(|i| (i % 241) as u8).collect();
    write_into_the_top_section(&mut v, ino, &data);
    let was = v.super_block().block_count;
    let step = per_sec(&v);
    resize(&mut v, was - step).unwrap();

    let mut v = remount(v);
    // The bytes are still there, and every block of them is inside what the
    // volume now covers.
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), data);
    for index in 0..2u64 {
        let a = v.stored_addr(&inode, ino, index).unwrap();
        assert!(v.sb_main_contains(a), "block {index} at {a} is past the new end");
    }
    // No log is left pointing into the section that went, either.
    let end = v.super_block().segment_count_main;
    assert!(v.logs().iter().all(|c| c.segno == crate::uapi::NULL_SEGNO || c.segno < end),
            "a log is still open in a section the volume gave up");
    v.load_segments().unwrap();
    let live: u32 = (0..end).map(|s| u32::from(v.seg_valid(s))).sum();
    assert_eq!(u64::from(live), v.valid_block_count,
               "the table and the volume's count disagree after the resize");
}
