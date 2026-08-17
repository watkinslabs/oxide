//! Buffered writes: what a write costs, when it costs it, and what a crash
//! before the flush leaves behind.
//!
//! The property under test is that ALLOCATION MOVED. A write no longer picks
//! a block; it takes the room, writes a reservation into the file's node and
//! leaves the bytes in the mapping, and the address is chosen when the page is
//! placed. Every test here is written so that reverting one of those moves
//! turns it red — the named line is in each test's own comment.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, NEW_ADDR, NULL_ADDR};
use crate::volume::map::Mapped;
use crate::volume::{Holder, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A writable volume holding one empty file, and that file's number.
fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    (v, ino)
}

/// One block of `byte`.
fn filled(byte: u8) -> Vec<u8> { vec![byte; BLKSIZE] }

fn read_all(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let i = v.read_inode(ino).unwrap();
    v.read_whole(&i, ino).unwrap()
}

/// The volume as a crash would leave it: the bytes that are ON THE MEDIUM,
/// mounted again. Nothing in memory survives, which is the whole point.
fn as_after_a_crash(v: &Volume<MemImage>) -> Volume<MemImage> {
    let bytes = v.source_ref().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// What the file's node says about block `index`.
fn slot(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    v.holder_addr(ino, Holder::Inode, index as usize).unwrap()
}

// ------------------------------------------------------- the deferred window

#[test]
fn a_write_leaves_a_reservation_and_no_block() {
    // Allocation moved. Put the address back at the write — have
    // `write_one_block` allocate instead of reserving — and the slot names a
    // block here and this is red.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(slot(&v, ino, 0), NEW_ADDR, "the write chose a block");
    assert_eq!(v.dirty_data_pages(ino), 1, "the bytes are not in the mapping");
}

#[test]
fn a_write_not_yet_placed_is_still_readable() {
    // The read consults the mapping before the node tree. Remove that peek in
    // `read_file_inner` and the reservation reads as a hole: this comes back
    // as a block of zeroes and the assertion below names it.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    let i = v.read_inode(ino).unwrap();
    assert_eq!(v.map_block(&i, ino, 0).unwrap(), Mapped::Hole,
               "the fixture depends on the tree having no address yet");
    assert_eq!(read_all(&v, ino), filled(0xA1));
}

#[test]
fn a_write_over_a_write_that_is_still_pending_keeps_both() {
    // The read-modify-write reads the MAPPING's page, not the medium. Make it
    // read the medium and the first write is lost, because the medium has
    // never seen it.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.write_file(ino, 4, b"ZZZZ").unwrap();
    let got = read_all(&v, ino);
    assert_eq!(&got[..4], &[0xA1; 4]);
    assert_eq!(&got[4..8], b"ZZZZ");
    assert_eq!(&got[8..12], &[0xA1; 4]);
}

#[test]
fn placing_a_page_does_not_forget_it() {
    // Writeback is the one address change that must NOT drop the page: it is
    // putting the page it holds at the new address. Give it the ordinary
    // `set_holder_addr` and the page goes, so this read fetches from the
    // medium and the hit count does not move.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let before = v.data_cache_hits();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    assert!(v.data_cache_hits() > before, "the placed page was dropped from the mapping");
}

// ------------------------------------------------------------ what a flush is

#[test]
fn a_flush_chooses_a_block_and_puts_the_bytes_in_it() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let addr = slot(&v, ino, 0);
    assert_ne!(addr, NEW_ADDR, "the flush chose no block");
    assert!(v.sb_main_contains(addr));
    assert_eq!(v.source_ref().peek(addr as usize * BLKSIZE, BLKSIZE), filled(0xA1),
               "the block does not hold the bytes");
    assert_eq!(v.dirty_data_pages(ino), 0, "the page is still dirty");
}

#[test]
fn a_second_flush_places_nothing_and_moves_no_block() {
    // Placed exactly once. A flush that re-wrote a clean page would move the
    // block every time anything called one — a checkpoint, an fsync, a
    // truncate — and burn the medium for no state change.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let addr = slot(&v, ino, 0);
    v.sync_data().unwrap();
    v.sync_data().unwrap();
    assert_eq!(slot(&v, ino, 0), addr, "an idle flush moved the block");
}

#[test]
fn a_pending_write_is_placed_by_the_files_own_sync() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.fsync(ino).unwrap();
    assert_eq!(v.dirty_data_pages(ino), 0, "fsync left the page pending");
    assert_ne!(slot(&v, ino, 0), NEW_ADDR);
}

#[test]
fn a_pending_write_is_placed_by_a_checkpoint() {
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.commit().unwrap();
    assert_eq!(v.dirty_data_pages(ino), 0, "the checkpoint left the page pending");
    let v = as_after_a_crash(&v);
    assert_eq!(read_all(&v, ino), filled(0xA1));
}

// ------------------------------------------------------------------- a crash

#[test]
fn a_crash_before_the_flush_loses_exactly_what_was_not_synced() {
    // The promise the deferred path has to keep. What a checkpoint covered is
    // on the medium; what was written after it and never placed is not, and
    // the file must come back consistent rather than half-written.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.write_file(ino, BLKSIZE as u64, &filled(0xB2)).unwrap();
    v.commit().unwrap();
    // Past the checkpoint: taken, reserved, filed, and never placed.
    v.write_file(ino, 2 * BLKSIZE as u64, &filled(0xC3)).unwrap();
    assert_eq!(v.dirty_data_pages(ino), 1);
    let v = as_after_a_crash(&v);
    let got = read_all(&v, ino);
    assert_eq!(&got[..BLKSIZE], &filled(0xA1)[..], "a synced block was lost");
    assert_eq!(&got[BLKSIZE..2 * BLKSIZE], &filled(0xB2)[..], "a synced block was lost");
    let i = v.read_inode(ino).unwrap();
    assert_eq!(v.map_block(&i, ino, 2).unwrap(), Mapped::Hole,
               "an unsynced write reached the medium");
}

#[test]
fn a_crash_leaves_no_reservation_charged_to_a_block_that_never_landed() {
    // The counts the recovered volume comes up with have to be the ones the
    // checkpoint recorded, not the ones the lost write left in memory.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.commit().unwrap();
    let counted = v.checkpoint().valid_block_count;
    v.write_file(ino, 2 * BLKSIZE as u64, &filled(0xC3)).unwrap();
    let v = as_after_a_crash(&v);
    assert_eq!(v.checkpoint().valid_block_count, counted);
    assert_eq!(v.valid_block_count, counted,
               "the recovered mount counts a block the crash never let land");
}

// ------------------------------------------------------------- what refuses

#[test]
fn a_full_volume_refuses_the_write_and_not_the_flush() {
    // ENOSPC belongs at the write. Move the room check to writeback and the
    // write below succeeds — the caller is told its bytes are safe — and the
    // flush fails afterwards with nobody left to report it to.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(1)).unwrap();
    v.sync_data().unwrap();
    let left = v.checkpoint().user_block_count - v.valid_block_count;
    v.cp.user_block_count -= left;
    assert_eq!(v.write_file(ino, BLKSIZE as u64, &filled(2)), Err(Errno::Enospc));
    assert_eq!(v.dirty_data_pages(ino), 0, "a refused write still filed its page");
    assert_eq!(slot(&v, ino, 1), NULL_ADDR, "a refused write still took the slot");
    assert_eq!(v.sync_data(), Ok(()), "the flush inherited the refusal");
}

#[test]
fn a_flush_of_a_reserved_slot_needs_no_further_room() {
    // The reservation already holds the room. Ask for it again at writeback
    // and a volume with exactly one block left cannot place the write it just
    // accepted.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(1)).unwrap();
    v.sync_data().unwrap();
    // One block left for the next write and nothing beyond it.
    // The volume's own count, not the root reserve: the reserve is now
    // conditional on who is asking, and a hosted caller reaches it.
    let left = v.checkpoint().user_block_count - v.valid_block_count;
    v.cp.user_block_count -= left - 1;
    v.write_file(ino, BLKSIZE as u64, &filled(2)).unwrap();
    assert_eq!(v.sync_data(), Ok(()), "the placement asked for room it already held");
    assert_ne!(slot(&v, ino, 1), NEW_ADDR);
}

#[test]
fn a_read_only_volume_takes_no_reservation() {
    let bytes = test_image::with_root().finish();
    let v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                               Options::defaults(), false);
    let mut v = v.unwrap();
    assert_eq!(v.write_file(ROOT_INO, 0, b"x"), Err(Errno::Erofs));
}

// -------------------------------------------------------------- the accounts

#[test]
fn the_owner_is_charged_at_the_write_and_not_at_the_flush() {
    // Quota is decided where the reservation is taken, which is the only
    // point at which the caller can still be told no.
    let (mut v, ino) = with_file();
    let before = v.valid_block_count;
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(v.valid_block_count, before + 1, "the reservation was not counted");
    v.sync_data().unwrap();
    assert_eq!(v.valid_block_count, before + 1, "placing the block counted it twice");
}

#[test]
fn shortening_a_file_gives_back_what_a_reservation_took() {
    // A reservation is charged to the owner now, so releasing one has to give
    // both halves back. Release only the volume's half and the file is paid
    // for forever.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let base = v.valid_block_count;
    v.write_file(ino, BLKSIZE as u64, &filled(0xB2)).unwrap();
    assert_eq!(v.valid_block_count, base + 1);
    v.truncate_file(ino, BLKSIZE as u64).unwrap();
    assert_eq!(v.valid_block_count, base, "the released block is still counted");
}

#[test]
fn a_files_block_count_includes_what_it_has_only_reserved() {
    // The count is what the file HOLDS, and a reservation is held space. A
    // count that waited for the address would report a file smaller than the
    // volume says it is between the write and the flush.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    let held = v.read_inode(ino).unwrap().blocks;
    v.sync_data().unwrap();
    assert_eq!(v.read_inode(ino).unwrap().blocks, held, "placing changed what the file holds");
}

#[test]
fn unlinking_gives_back_the_owners_charge_for_a_reservation_too() {
    // A reservation is charged to the OWNER when it is taken, so releasing one
    // has to give both halves back. Release only the volume's half — leave
    // `release_slot`'s `NEW_ADDR` arm returning without an uncharge — and the
    // file is paid for forever, one block per write that never landed.
    const UID: u32 = 4242;
    const QUOTA_INO: u32 = 9;
    let file = crate::test_image::quota_image::user_file(UID, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[crate::volume::quotas::USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    crate::test_image::nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = b.mount_opts(o).unwrap();
    v.set_clock(NOW.0);
    let owned = NewInode { mode: S_IFREG | 0o644, uid: UID, gid: UID, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"q", &owned, None).unwrap();
    let charge = |v: &mut Volume<MemImage>| {
        v.quota_record(crate::volume::quotas::USRQUOTA, UID).unwrap().curspace
    };
    let before = charge(&mut v);
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(charge(&mut v), before + BLKSIZE as u64,
               "the reservation charged the owner nothing");
    assert_eq!(v.dirty_data_pages(ino), 1, "the fixture depends on the write being pending");
    // Unlinked rather than truncated: a truncate places what is pending
    // before it reads the addresses, so the slot it meets names a block. The
    // last name going is the one path that meets a RESERVATION and has to
    // give it back — the file is gone and its bytes were never written.
    v.remove(ROOT_INO, b"q", false, NOW).unwrap();
    // The name going parks the inode; the EVICTION is what frees it and
    // gives back what it held. The two are separate events, and a descriptor
    // may sit between them.
    v.evict_inode(ino).unwrap();
    assert_eq!(charge(&mut v), before,
               "the owner is still paying for a block that never landed");
}

#[test]
fn the_cleaner_places_a_pending_write_before_it_moves_the_block() {
    // The cleaner moves blocks by ADDRESS, and moving one goes through the
    // notification that drops the mapping's page for that offset. A page
    // dirtied over a block the cleaner is about to relocate is the only copy
    // of that write — take the flush out of `gc_segment` and the relocation
    // throws it away and puts the PREVIOUS contents back in its place.
    let (mut v, ino) = with_file();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let addr = slot(&v, ino, 0);
    let victim = (addr - v.super_block().main_blkaddr) / v.super_block().blks_per_seg();
    // The log leaves the segment, so it is a candidate at all.
    v.open_segment(crate::uapi::CURSEG_WARM_DATA).unwrap();
    // Written over the placed block and left pending.
    v.write_file(ino, 0, &filled(0xB2)).unwrap();
    assert_eq!(v.dirty_data_pages(ino), 1);
    v.gc_segment(victim).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xB2), "the cleaner threw the pending write away");
    let v = as_after_a_crash(&{ let mut v = v; v.commit().unwrap(); v });
    assert_eq!(read_all(&v, ino), filled(0xB2));
}
