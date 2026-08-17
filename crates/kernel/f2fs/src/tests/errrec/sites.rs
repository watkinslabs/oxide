//! That the error record is REACHED by ordinary operations.
//!
//! `handle.rs` proves the machinery works when called. These cases call
//! nothing in `errrec` except to read the result: each one damages a volume's
//! BYTES or issues a command, drives the operation a caller would drive, then
//! reads the SUPERBLOCK back through a fresh mount. So each test fails if the
//! detection site stops recording, and fails if the record stops reaching the
//! medium — which is what the row these close was about: every piece worked
//! and nothing called it.
//!
//! The damage is done to the image bytes between two mounts rather than
//! through the live volume, because a mount serves its own caches: a block
//! scribbled behind a mount that already holds it is never re-read.

use super::*;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::Volume;
use sectors::MemImage;
use syscall::errno::Errno;

fn mount(bytes: alloc::vec::Vec<u8>) -> Volume<MemImage> {
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .expect("mount")
}

/// Remount the bytes a volume left behind, read-write.
fn remounted(v: Volume<MemImage>) -> Volume<MemImage> { mount(v.into_source().snapshot()) }

fn spec() -> crate::volume::NewInode {
    crate::volume::NewInode { mode: crate::mode::S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0,
                              now: (1_800_000_000, 3) }
}

/// A committed image holding one file with one block of data, that file's
/// number, and the block address of its inode.
fn image_with_file() -> (alloc::vec::Vec<u8>, u32, u32) {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec(), None).expect("create");
    v.write_file(ino, 0, &alloc::vec![0xA5u8; BLKSIZE]).expect("write");
    v.commit().expect("commit");
    let at = v.node_addr(ino).expect("node address");
    (v.into_source().snapshot(), ino, at)
}

/// Flip a byte inside the block at `addr`. # C: O(1)
fn scribble(bytes: &mut [u8], addr: u32, offset: usize) {
    bytes[addr as usize * BLKSIZE + offset] ^= 0xFF;
}

#[test]
fn an_inode_whose_checksum_fails_is_recorded_by_the_read_that_finds_it() {
    let (mut bytes, ino, at) = image_with_file();
    // A byte inside the inode's own fields, so the checksum no longer matches
    // while the footer still names this node.
    scribble(&mut bytes, at, BLKSIZE / 2);
    let mut v = mount(bytes);

    // The operation a caller drives. It must fail, AND leave a record.
    assert!(v.read_inode(ino).is_err(), "a damaged inode was handed out");
    v.commit().expect("commit");

    let again = remounted(v);
    assert!(again.error_record().has_error(Error::CorruptedInode),
            "the read that rejected the inode recorded nothing, so the next \
             mount and fsck see a clean volume");
}

#[test]
fn an_address_outside_the_main_area_is_recorded_by_the_read_that_refuses_it() {
    let (bytes, _ino, _at) = image_with_file();
    let mut v = mount(bytes);
    // The superblock area: a real address, and never one a file may name.
    assert_eq!(v.read_main_block(0), Err(Errno::Eio));
    v.commit().expect("commit");
    let again = remounted(v);
    assert!(again.error_record().has_error(Error::InvalidBlkaddr));
}

#[test]
fn a_corrupt_directory_block_is_recorded_by_the_read_that_finds_it() {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let at = v.node_addr(ROOT_INO).expect("node address");
    let inode = v.read_inode(ROOT_INO).expect("root");
    let (span_at, span_len) = inode.inline_data_span();
    let mut block = v.read_main_block(at).expect("read");
    // The root directory is inline, so its records live in the inode's own
    // block. Fill the record area so the bitmap claims slots the name area
    // cannot hold, then RE-SEAL the inode: the checksum covers the whole
    // block, so without resealing the inode itself fails first and the case
    // would measure `CorruptedInode` while claiming to measure the directory.
    for b in &mut block[span_at..span_at + span_len] { *b = 0xFF; }
    v.seal_inode(&mut block);
    v.write_block(at, &block).expect("scribble");
    v.commit().expect("commit");
    // A fresh mount, so the read goes to the medium rather than to the cache
    // that still holds the sound block.
    let mut v = remounted(v);

    let inode = v.read_inode(ROOT_INO).expect("the inode itself still parses");
    let listed = v.read_dir(&inode, ROOT_INO);
    let looked = v.lookup(&inode, ROOT_INO, b"nothing");
    assert!(listed.is_err() || looked.is_err(),
            "damaged directory bytes were read as if they were sound");
    v.commit().expect("commit");

    let again = remounted(v);
    assert!(again.error_record().has_error(Error::CorruptedDirent),
            "a directory read off damaged bytes recorded nothing");
    assert!(!again.error_record().has_error(Error::CorruptedInode),
            "the inode was sound, so this case measures the directory");
}

#[test]
fn a_shutdown_stops_the_volume_and_says_why_on_the_medium() {
    let (bytes, _ino, _at) = image_with_file();
    let mut v = mount(bytes);
    assert!(!v.sbi_flags().shutdown());
    v.stop_checkpoint(StopReason::Shutdown, false);
    assert!(v.sbi_flags().shutdown(), "the volume kept running");
    assert_ne!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0,
               "checkpointing was left enabled");
    let again = remounted(v);
    assert_eq!(again.error_record().stops(StopReason::Shutdown), 1,
               "no reason was recorded for the next mount");
}

#[test]
fn a_sync_pushes_a_record_a_read_path_left_behind_with_nothing_else_dirty() {
    // The driver for every `&self` detection site: a read cannot write, so the
    // record it adds to reaches the medium at the next commit — and must do so
    // whether or not the checkpoint has anything of its own to write.
    let (bytes, _ino, _at) = image_with_file();
    let mut v = mount(bytes);
    assert!(!v.error_record().dirty(), "the fixture starts clean");
    assert!(v.note_error(Error::InconsistentSit), "news");
    assert!(v.error_record().dirty(), "still only in memory");
    v.commit().expect("commit");
    assert!(!v.error_record().dirty(), "the commit did not push the record");
    let again = remounted(v);
    assert!(again.error_record().has_error(Error::InconsistentSit));
}

#[test]
fn a_checkpoint_that_cannot_be_written_stops_checkpointing_and_records_why() {
    // The site that makes `errors=` reachable from a real failure. Before it,
    // a failed checkpoint reported an errno and left the mount live, writing
    // on top of a checkpoint it had not placed, with nothing on the medium to
    // tell the next mount or fsck.
    let (bytes, ino, _at) = image_with_file();
    let mut v = mount(bytes);
    v.write_file(ino, 0, &alloc::vec![0x5Au8; BLKSIZE]).expect("write");
    // Every write to the medium now fails, so the checkpoint cannot land.
    v.set_fault(1, u32::MAX, crate::fault::Which::RATE).ok();
    v.set_fault(0, crate::fault::Fault::WriteIo.bit(), crate::fault::Which::TYPE).ok();
    assert!(v.commit().is_err(), "the checkpoint was expected to fail");
    assert_ne!(v.checkpoint().flags & crate::flags::CP_ERROR_FLAG, 0,
               "a mount that could not checkpoint kept checkpointing");
    assert_eq!(v.error_record().stops(StopReason::MetaPage), 1,
               "no reason was counted for the failed checkpoint");
}

#[test]
fn errors_remount_ro_stops_the_writes_when_a_real_checkpoint_fails() {
    // `errors=` was decided and never reached from anything but a shutdown,
    // which forces its own behaviour whatever the option says. This drives the
    // option from a genuine failure.
    let (bytes, ino, _at) = image_with_file();
    let opts = Options { errors: crate::opts::Errors::RemountRo, ..Options::defaults() };
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), opts, true)
        .expect("mount");
    v.write_file(ino, 0, &alloc::vec![0x5Au8; BLKSIZE]).expect("write");
    assert!(v.writable());
    v.set_fault(1, u32::MAX, crate::fault::Which::RATE).ok();
    v.set_fault(0, crate::fault::Fault::WriteIo.bit(), crate::fault::Which::TYPE).ok();
    assert!(v.commit().is_err());
    assert!(!v.writable(), "errors=remount-ro did not stop the writes");
}
