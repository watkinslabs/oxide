//! Pinned files: the ladder that admits one, and what one does afterwards.

use super::policy::{self, GcPinned, PinAction, PinFacts, SetPinGate};
use super::section;
use super::state;
use crate::flags::PIN_FILE;
use crate::mode::S_IFREG;
use crate::opts::{Mode, Options};
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, I_CURRENT_DEPTH};
use crate::volume::map::Mapped;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn dir_spec() -> NewInode {
    NewInode { mode: crate::mode::S_IFDIR | 0o755, uid: 0, gid: 0, rdev: 0, now: NOW }
}

fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    (v, ino)
}

fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

fn ok_gate() -> SetPinGate {
    SetPinGate { is_reg: true, ro_mount: false, device_alias: false }
}

fn ok_facts() -> PinFacts {
    PinFacts { threshold: policy::GC_PIN_FILE_THRESHOLD, ..PinFacts::default() }
}

// ------------------------------------------------------------------- ladder

#[test]
fn only_a_regular_file_may_be_pinned() {
    let g = SetPinGate { is_reg: false, ..ok_gate() };
    assert_eq!(policy::set_pin_file(&g, &ok_facts(), 1), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_refuses_both_directions() {
    let g = SetPinGate { ro_mount: true, ..ok_gate() };
    assert_eq!(policy::set_pin_file(&g, &ok_facts(), 1), Err(Errno::Erofs));
    assert_eq!(policy::set_pin_file(&g, &ok_facts(), 0), Err(Errno::Erofs));
}

#[test]
fn the_type_refusal_comes_before_the_mounts() {
    let g = SetPinGate { is_reg: false, ro_mount: true, device_alias: false };
    assert_eq!(policy::set_pin_file(&g, &ok_facts(), 1), Err(Errno::Einval));
}

#[test]
fn a_device_alias_may_not_be_unpinned() {
    let g = SetPinGate { device_alias: true, ..ok_gate() };
    assert_eq!(policy::set_pin_file(&g, &ok_facts(), 0), Err(Errno::Eopnotsupp));
    // Pinning one is fine; it is already the state the format requires.
    assert_eq!(policy::set_pin_file(&g, &ok_facts(), 1), Ok(PinAction::Pin));
}

#[test]
fn an_atomic_file_may_not_be_pinned_in_either_direction() {
    let f = PinFacts { atomic: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 1), Err(Errno::Einval));
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 0), Err(Errno::Einval));
}

#[test]
fn unpinning_precedes_every_refusal_about_pinning() {
    let f = PinFacts { has_blocks: true, update_outplace: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 0), Ok(PinAction::Unpin));
}

#[test]
fn pinning_an_already_pinned_file_is_not_a_refusal() {
    let f = PinFacts { already_pinned: true, has_blocks: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 1), Ok(PinAction::AlreadyPinned));
}

#[test]
fn a_file_that_already_has_blocks_is_too_big_to_pin() {
    let f = PinFacts { has_blocks: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 1), Err(Errno::Efbig));
}

#[test]
fn a_file_that_must_be_rewritten_elsewhere_cannot_be_pinned() {
    let f = PinFacts { update_outplace: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 1), Err(Errno::Einval));
    // A zoned volume rewrites everything elsewhere, so the test says nothing.
    let z = PinFacts { update_outplace: true, blkzoned: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &z, 1), Ok(PinAction::Pin));
}

#[test]
fn the_size_refusal_comes_before_the_placement_one() {
    let f = PinFacts { has_blocks: true, update_outplace: true, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 1), Err(Errno::Efbig));
}

#[test]
fn a_file_that_has_cost_too_much_cleaning_is_refused() {
    let f = PinFacts { gc_failures: 2048, ..ok_facts() };
    assert_eq!(policy::set_pin_file(&ok_gate(), &f, 1), Err(Errno::Eagain));
}

#[test]
fn compression_that_cannot_come_off_refuses_the_pin() {
    assert_eq!(policy::pin_compression(true), Err(Errno::Eopnotsupp));
    assert_eq!(policy::pin_compression(false), Ok(()));
}

#[test]
fn the_failure_counter_stops_at_its_threshold() {
    assert_eq!(policy::pin_file_control(0, 4, true), Ok(1));
    assert_eq!(policy::pin_file_control(3, 4, true), Ok(4));
    assert_eq!(policy::pin_file_control(4, 4, true), Err(Errno::Eagain));
    assert_eq!(policy::pin_file_control(4, 4, false), Err(Errno::Eagain));
    assert_eq!(policy::pin_file_control(3, 4, false), Ok(3));
}

#[test]
fn the_cleaner_never_moves_a_pinned_block() {
    assert_eq!(policy::gc_pinned_control(false, true), GcPinned::Proceed);
    assert_eq!(policy::gc_pinned_control(false, false), GcPinned::Proceed);
    assert_eq!(policy::gc_pinned_control(true, false), GcPinned::Busy);
    assert_eq!(policy::gc_pinned_control(true, true), GcPinned::Blocked);
}

#[test]
fn a_pinned_file_shrinks_only_to_a_section_boundary() {
    assert_eq!(policy::truncate(true, 8192, 4096, 4096), Ok(()));
    assert_eq!(policy::truncate(true, 8192, 4097, 4096), Err(Errno::Einval));
    // Growing is unrestricted, and an unpinned file is unrestricted either way.
    assert_eq!(policy::truncate(true, 8192, 9001, 4096), Ok(()));
    assert_eq!(policy::truncate(false, 8192, 4097, 4096), Ok(()));
}

#[test]
fn only_an_overwrite_reaches_a_pinned_file() {
    assert_eq!(policy::write_allowed(true, true), Ok(()));
    assert_eq!(policy::write_allowed(true, false), Err(Errno::Eio));
    assert_eq!(policy::write_allowed(false, false), Ok(()));
}

// -------------------------------------------------------------------- state

#[test]
fn the_failure_count_shares_its_bytes_with_a_directorys_depth() {
    let mut b = vec![0u8; BLKSIZE];
    b[I_CURRENT_DEPTH..I_CURRENT_DEPTH + 4].copy_from_slice(&9u32.to_le_bytes());
    // A directory's nine levels are not nine collisions.
    assert_eq!(state::gc_failures(&b, crate::mode::S_IFDIR | 0o755), 0);
    assert_eq!(state::gc_failures(&b, S_IFREG | 0o644), 9);
    state::set_gc_failures(&mut b, crate::mode::S_IFDIR | 0o755, 3);
    assert_eq!(crate::uapi::le32(&b, I_CURRENT_DEPTH), Some(9));
    state::set_gc_failures(&mut b, S_IFREG | 0o644, 3);
    assert_eq!(crate::uapi::le32(&b, I_CURRENT_DEPTH), Some(3));
}

// ------------------------------------------------------------------- volume

#[test]
fn the_mark_survives_a_remount() {
    let (mut v, ino) = with_file();
    assert_eq!(v.set_pin_file(ino, 1).unwrap(), 0);
    let v = remount(v);
    assert!(v.is_pinned_ino(ino).unwrap());
    assert!(v.read_inode(ino).unwrap().inline & PIN_FILE != 0);
}

#[test]
fn unpinning_survives_a_remount_too() {
    let (mut v, ino) = with_file();
    v.set_pin_file(ino, 1).unwrap();
    let mut v = remount(v);
    v.set_pin_file(ino, 0).unwrap();
    let v = remount(v);
    assert!(!v.is_pinned_ino(ino).unwrap());
    assert_eq!(v.get_pin_file(ino).unwrap(), 0);
}

#[test]
fn a_file_with_blocks_cannot_be_pinned() {
    let (mut v, ino) = with_file();
    let region = v.read_inode(ino).unwrap().inline_data_span().1;
    v.write_file(ino, 0, &vec![7u8; region + 1]).unwrap();
    assert_eq!(v.set_pin_file(ino, 1), Err(Errno::Efbig));
}

#[test]
fn a_directory_cannot_be_pinned() {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let d = v.create(ROOT_INO, b"d", &dir_spec(), None).unwrap();
    assert_eq!(v.set_pin_file(d, 1), Err(Errno::Einval));
}

#[test]
fn a_read_only_mount_pins_nothing() {
    let (mut v, ino) = with_file();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut ro = Volume::mount_with(
        MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), false).unwrap();
    assert_eq!(ro.set_pin_file(ino, 1), Err(Errno::Erofs));
}

#[test]
fn a_strictly_out_of_place_mount_pins_nothing() {
    let mut opts = Options::defaults();
    opts.mode = Mode::Lfs;
    let mut v = test_image::with_root().mount_opts(opts).unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    assert_eq!(v.set_pin_file(ino, 1), Err(Errno::Einval));
}

#[test]
fn the_recorded_collisions_come_back_from_the_medium() {
    let (mut v, ino) = with_file();
    v.set_pin_file(ino, 1).unwrap();
    v.pin_file_control(ino, true).unwrap();
    v.pin_file_control(ino, true).unwrap();
    let v = remount(v);
    assert_eq!(v.get_pin_file(ino).unwrap(), 2);
}

#[test]
fn an_unpinned_file_reports_no_collisions_whatever_the_field_holds() {
    let (mut v, ino) = with_file();
    v.set_pin_file(ino, 1).unwrap();
    v.pin_file_control(ino, true).unwrap();
    v.set_pin_file(ino, 0).unwrap();
    assert_eq!(v.get_pin_file(ino).unwrap(), 0);
}

#[test]
fn a_file_past_the_threshold_loses_its_mark() {
    let (mut v, ino) = with_file();
    v.set_pin_file(ino, 1).unwrap();
    let m = v.read_inode(ino).unwrap().mode;
    v.stamp_inode(ino, |b| state::set_gc_failures(b, m, policy::GC_PIN_FILE_THRESHOLD)).unwrap();
    assert_eq!(v.pin_file_control(ino, true), Err(Errno::Eagain));
    assert!(!v.is_pinned_ino(ino).unwrap());
}

// ---------------------------------------------------------------- allocation

/// A pinned file with one whole section of blocks, and the addresses it got.
fn pinned_section() -> (Volume<MemImage>, u32, Vec<u32>) {
    let (mut v, ino) = with_file();
    v.set_pin_file(ino, 1).unwrap();
    let sec = u64::from(v.blks_per_sec());
    v.expand_pinned(ino, 0, sec * BLKSIZE as u64).unwrap();
    let addrs = addresses(&v, ino, sec);
    (v, ino, addrs)
}

fn addresses(v: &Volume<MemImage>, ino: u32, count: u64) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    (0..count)
        .map(|i| match v.map_block(&inode, ino, i).unwrap() {
            Mapped::At(a) => a,
            other => panic!("block {i} is {other:?}, not an address"),
        })
        .collect()
}

/// The summary entry recorded for the block at `addr`, wherever it lives:
/// still in the open log, or already written out to the summary area.
fn summary_at(v: &Volume<MemImage>, addr: u32) -> crate::volume::curseg::Summary {
    let sb = v.super_block();
    let segno = sb.segno_of(addr).unwrap();
    let slot = (addr - sb.main_blkaddr - segno * crate::uapi::BLKS_PER_SEG) as usize;
    if let Some(log) = v.logs().iter().find(|c| c.segno == segno) { return log.summary(slot); }
    let block = v.read_block(crate::uapi::sum_block_addr(sb.ssa_blkaddr, segno)).unwrap();
    crate::volume::gc::live::entry(&block, slot).unwrap()
}

#[test]
fn a_pinned_file_gets_a_contiguous_section_aligned_run() {
    let (v, _ino, addrs) = pinned_section();
    let per = u64::from(v.blks_per_sec());
    assert_eq!(addrs.len() as u64, per);
    for w in addrs.windows(2) { assert_eq!(w[1], w[0] + 1); }
    assert_eq!(u64::from(addrs[0] - v.super_block().main_blkaddr) % per, 0);
}

#[test]
fn the_run_is_still_there_after_a_remount() {
    let (v, ino, addrs) = pinned_section();
    let per = u64::from(v.blks_per_sec());
    let v = remount(v);
    assert!(v.is_pinned_ino(ino).unwrap());
    assert_eq!(addresses(&v, ino, per), addrs);
}

#[test]
fn a_write_to_a_pinned_file_does_not_move_its_block() {
    let (mut v, ino, addrs) = pinned_section();
    v.pinned_write(ino, 0, b"held in place").unwrap();
    v.pinned_write(ino, BLKSIZE as u64, b"second block").unwrap();
    let per = u64::from(v.blks_per_sec());
    assert_eq!(addresses(&v, ino, per), addrs, "a pinned write moved a block");
    let v = remount(v);
    assert_eq!(addresses(&v, ino, per), addrs);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 13];
    v.read_file(&inode, ino, 0, &mut buf).unwrap();
    assert_eq!(&buf, b"held in place");
    let mut second = vec![0u8; 12];
    v.read_file(&inode, ino, BLKSIZE as u64, &mut second).unwrap();
    assert_eq!(&second, b"second block");
}

#[test]
fn a_write_a_pinned_file_has_no_block_for_is_refused() {
    let (mut v, ino, _) = pinned_section();
    let past = u64::from(v.blks_per_sec()) * BLKSIZE as u64;
    assert_eq!(v.pinned_write(ino, past, b"nowhere to put this"), Err(Errno::Eio));
}

#[test]
fn expanding_a_file_that_is_not_pinned_is_refused() {
    let (mut v, ino) = with_file();
    assert_eq!(v.expand_pinned(ino, 0, 4096), Err(Errno::Einval));
}

#[test]
fn the_pinned_log_is_not_one_the_checkpoint_records() {
    let (v, _ino, addrs) = pinned_section();
    let pinned_seg = v.super_block().segno_of(addrs[0]).unwrap();
    // Every persisted log is somewhere else: a pinned section shared with an
    // ordinary log would take blocks the cleaner is free to move.
    for log in v.logs().iter().take(crate::uapi::NR_CURSEG_PERSIST_TYPE) {
        assert_ne!(log.segno, pinned_seg);
    }
    let v = remount(v);
    // Nothing reopens it, and nothing else has taken it either: its blocks
    // are live, so it is not free.
    assert!(v.block_is_live(addrs[0]).unwrap());
}

#[test]
fn the_cleaner_is_told_a_pinned_files_blocks_belong_to_it() {
    let (v, ino, addrs) = pinned_section();
    let sum = summary_at(&v, addrs[0]);
    assert_eq!(v.pinned_owner_ino(&sum).unwrap(), Some(ino));
    // An ordinary file's block is not reported as pinned, so the cleaner's
    // question can answer both ways.
    let other = {
        let mut v2 = v;
        let plain = v2.create(ROOT_INO, b"plain", &spec(), None).unwrap();
        let region = v2.read_inode(plain).unwrap().inline_data_span().1;
        v2.write_file(plain, 0, &vec![1u8; region + 1]).unwrap();
        let a = addresses(&v2, plain, 1)[0];
        let s = summary_at(&v2, a);
        v2.pinned_owner_ino(&s).unwrap()
    };
    assert_eq!(other, None);
}

/// The cleaner LEAVES a pinned file's blocks where they are.
///
/// The query above proves the cleaner can find out who owns a block. This
/// proves it asks. The distinction matters because something outside the
/// filesystem — a swap area — is holding these addresses: moving the block
/// would leave that holder reading whatever landed there next, and nothing
/// in the filesystem would look wrong afterwards.
#[test]
fn the_cleaner_leaves_a_pinned_files_blocks_where_they_are() {
    let (mut v, ino, addrs) = pinned_section();
    let before = addrs.to_vec();
    let seg = v.super_block().segno_of(before[0]).expect("a main-area block");
    // Ask the cleaner to empty the very segment the pinned blocks sit in.
    let _ = v.gc_segment(seg);
    let after = addresses(&v, ino, before.len() as u64);
    assert_eq!(after, before, "a pinned file's blocks did not move");
    // And the collision is charged to the file, which is what eventually
    // takes the pin away from a file that keeps costing the cleaner work.
    assert!(v.get_pin_file(ino).unwrap() > 0,
            "the collision is recorded against the file that caused it");
}

// ------------------------------------------------------------------ sections

/// A main area of `n` segments where the ones in `used` are not free.
fn free_map(used: &[u32]) -> impl Fn(u32) -> bool + Copy + '_ {
    move |s: u32| !used.contains(&s)
}

#[test]
fn a_section_is_named_by_its_first_segment() {
    assert_eq!(section::section_first(0, 4), 0);
    assert_eq!(section::section_first(3, 4), 0);
    assert_eq!(section::section_first(4, 4), 4);
    assert_eq!(section::section_first(7, 4), 4);
    // A volume whose sections are one segment each cannot tell the two apart,
    // which is why the width is a parameter here.
    assert_eq!(section::section_first(7, 1), 7);
}

#[test]
fn one_used_segment_makes_the_whole_section_unusable() {
    assert!(section::section_is_free(0, 4, 16, free_map(&[])));
    assert!(!section::section_is_free(0, 4, 16, free_map(&[2])));
    // Not a section boundary at all.
    assert!(!section::section_is_free(1, 4, 16, free_map(&[])));
    // Runs off the end of the main area.
    assert!(!section::section_is_free(16, 4, 16, free_map(&[])));
    assert!(!section::section_is_free(12, 8, 16, free_map(&[])));
}

#[test]
fn the_search_skips_a_section_with_anything_in_it() {
    // Segment 5 is used, so the whole of section one is unavailable even
    // though three of its four segments are free — the segment-wise search
    // this replaces would have taken segment 4.
    assert_eq!(section::find_free_section(0, 4, 16, free_map(&[0, 5])), Some(8));
    assert_eq!(section::find_free_section(0, 4, 16, free_map(&[0])), Some(4));
    assert_eq!(section::find_free_section(0, 4, 16, free_map(&[0, 5, 9, 13])), None);
}

#[test]
fn the_search_wraps_once_and_starts_where_it_was_told() {
    assert_eq!(section::find_free_section(9, 4, 16, free_map(&[])), Some(8));
    assert_eq!(section::find_free_section(9, 4, 16, free_map(&[8, 12])), Some(0));
}

#[test]
fn the_pinned_log_rolls_inside_its_section_and_stops_at_the_end() {
    assert_eq!(section::next_in_section(0, 4, 16), Some(1));
    assert_eq!(section::next_in_section(2, 4, 16), Some(3));
    // The last segment of a section has no next segment here.
    assert_eq!(section::next_in_section(3, 4, 16), None);
    assert_eq!(section::next_in_section(14, 4, 16), Some(15));
    // Nor does the last segment of the main area.
    assert_eq!(section::next_in_section(15, 4, 16), None);
    // Nor one whose section runs past the end of a short main area.
    assert_eq!(section::next_in_section(12, 4, 14), Some(13));
    assert_eq!(section::next_in_section(13, 4, 14), None);
    // A one-segment section is always at its own end.
    assert_eq!(section::next_in_section(5, 1, 16), None);
}
