//! The sections the cleaner remembers between searches, and `victim_bits`.
//!
//! The map only earns its keep when a clean does NOT empty the section it
//! chose — an emptied section stops being a candidate, and the map drops it.
//! Every fixture here therefore leaves the victim with a block the cleaner
//! cannot move: one the segment table calls live and no file names. That state
//! is reachable through the consistency site, which is exactly what the site
//! is for, and is what an interrupted release leaves behind on real media.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::fault::{Fault, Which};
use crate::mode::S_IFREG;
use crate::procfs::victim_bits_body;
use crate::stats::counters::gc_mode;
use crate::test_image::{self, MAIN_BLKADDR, ROOT_INO};
use crate::uapi::{BLKSIZE, BLKS_PER_SEG, CURSEG_WARM_DATA};
use crate::volume::gc::victim::Policy;
use crate::volume::{map::Mapped, NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 3);
const FILE_BLOCKS: usize = 4;

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// # C: O(1)
fn seg_of(addr: u32) -> u32 { (addr - MAIN_BLKADDR) / BLKS_PER_SEG }

/// # C: O(1 block)
fn addr_of(v: &Volume<MemImage>, ino: u32, index: u64) -> u32 {
    match v.map_block(&v.read_inode(ino).unwrap(), ino, index).unwrap() {
        Mapped::At(a) => a,
        _ => panic!("the file's block is not a block"),
    }
}

/// A volume whose one dirty section holds blocks the cleaner cannot move.
///
/// The file is truncated with the consistency site armed, so the addresses
/// leave the file while the segment table goes on calling the blocks live.
/// Cleaning that section moves nothing and empties nothing, which is the state
/// a remembered victim has to survive.
fn stuck_victim() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![5u8; FILE_BLOCKS * BLKSIZE]).unwrap();
    let victim = seg_of(addr_of(&v, ino, 0));
    // Sealing the log writes the summary block out and moves the log off the
    // segment, which is what makes it a candidate at all.
    v.open_segment(CURSEG_WARM_DATA).unwrap();
    v.set_fault(1, 0, Which::RATE).unwrap();
    v.set_fault(0, Fault::BlkaddrConsistence.bit(), Which::TYPE).unwrap();
    v.truncate_file(ino, 0).unwrap();
    v.set_fault(0, 0, Which::ALL).unwrap();
    assert!(v.seg_valid(victim) > 0, "the fixture left the cleaner nothing stuck");
    (v, victim)
}

/// A section the cleaner has never looked at is not remembered, and the report
/// says so for every section rather than for none.
#[test]
fn a_fresh_mount_remembers_no_section() {
    let v = test_image::with_root().mount_rw().unwrap();
    assert!(v.victim_sections().is_empty());
    let body = victim_bits_body(v.section_count(), &v.victim_sections());
    assert_eq!(body.lines().next().unwrap(), "format: victim_secmap bitmaps");
    let digits: Vec<char> =
        body.lines().skip(1).flat_map(|l| l.chars().skip(10)).filter(|c| *c != ' ').collect();
    assert_eq!(digits.len(), v.section_count() as usize, "one digit per section");
    assert!(digits.iter().all(|&c| c == '0'));
}

/// An ahead-of-demand search records what it chose, and the record outlives
/// the clean when the clean did not empty the section.
#[test]
fn an_ahead_of_demand_search_records_the_section_it_chose() {
    let (mut v, victim) = stuck_victim();
    let found = v.gc_background_as(Policy::Greedy, gc_mode::NORMAL).unwrap();
    assert_eq!(found, Some(victim), "the fixture's section is the only candidate");
    let secno = v.secno_of_seg(victim);
    assert!(v.victim_section_marked(secno), "the search forgot what it chose");
    let body = victim_bits_body(v.section_count(), &v.victim_sections());
    assert_eq!(digit(&body, secno), '1', "{body}");
}

/// One digit of the report, by section number. # C: O(len)
fn digit(body: &str, secno: u32) -> char {
    let line = body.lines().skip(1).nth((secno / 10) as usize).expect("the line");
    line.chars().skip(10).filter(|c| *c != ' ').nth((secno % 10) as usize).expect("the digit")
}

/// A bounded search must not settle on what the last one settled on. Without
/// the exclusion it would re-cost the same cheapest section every round and
/// the rest of the volume would never be reached.
#[test]
fn a_second_ahead_of_demand_search_passes_over_what_the_first_chose() {
    let (mut v, victim) = stuck_victim();
    assert_eq!(v.gc_background_as(Policy::Greedy, gc_mode::NORMAL).unwrap(), Some(victim));
    assert_eq!(v.gc_background_as(Policy::Greedy, gc_mode::NORMAL).unwrap(), None,
               "the only candidate was chosen twice");
}

/// A caller that needs space now takes what the ahead-of-demand search already
/// costed, and the record comes down when it does — a second caller taking the
/// same section would clean one that is already being cleaned.
#[test]
fn a_blocked_caller_takes_the_remembered_section_and_clears_the_record() {
    let (mut v, victim) = stuck_victim();
    v.gc_background_as(Policy::Greedy, gc_mode::NORMAL).unwrap();
    let secno = v.secno_of_seg(victim);
    assert!(v.victim_section_marked(secno));
    let taken = v.take_bg_victim();
    assert_eq!(taken, Some(v.first_seg_of_sec(secno)));
    assert!(!v.victim_section_marked(secno), "the record outlived the caller that took it");
    assert_eq!(v.take_bg_victim(), None, "the same section was handed out twice");
}

/// A section with a log open inside it is passed over and LEFT recorded: the
/// log moves on, and the costing that put it there is still good afterwards.
#[test]
fn a_section_a_log_is_writing_to_is_passed_over_but_not_forgotten() {
    let (mut v, victim) = stuck_victim();
    v.gc_background_as(Policy::Greedy, gc_mode::NORMAL).unwrap();
    let secno = v.secno_of_seg(victim);
    // Aim a log at the remembered section, which is what makes it unusable.
    v.curseg[CURSEG_WARM_DATA].segno = victim;
    assert_eq!(v.take_bg_victim(), None, "a section under a log was handed out");
    assert!(v.victim_section_marked(secno), "a section merely busy was forgotten");
}

/// A section with nothing live in it is not a candidate — there is nothing to
/// move out — so remembering it would send the next blocked caller to a
/// section that yields no space, and would make the bounded search exclude it
/// forever.
#[test]
fn a_section_that_empties_stops_being_remembered() {
    let (mut v, victim) = stuck_victim();
    v.gc_background_as(Policy::Greedy, gc_mode::NORMAL).unwrap();
    let secno = v.secno_of_seg(victim);
    assert!(v.victim_section_marked(secno));
    // Release what the fixture stranded, which is what empties the section.
    let base = MAIN_BLKADDR + victim * BLKS_PER_SEG;
    for off in 0..BLKS_PER_SEG {
        if v.block_is_live(base + off).unwrap_or(false) { v.release_block(base + off).unwrap(); }
    }
    assert_eq!(v.seg_valid(victim), 0);
    assert!(!v.victim_section_marked(secno), "an empty section is still remembered");
    let body = victim_bits_body(v.section_count(), &v.victim_sections());
    assert_eq!(digit(&body, secno), '0', "{body}");
}

/// The report's shape is what a tool parses: ten sections to a line, each line
/// labelled with the number of the section it starts at.
#[test]
fn the_report_lays_ten_sections_per_line() {
    let body = victim_bits_body(23, &[0, 11, 22]);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], "format: victim_secmap bitmaps");
    assert_eq!(lines[1], "0         1 0 0 0 0 0 0 0 0 0");
    assert_eq!(lines[2], "10        0 1 0 0 0 0 0 0 0 0");
    assert_eq!(lines[3], "20        0 0 1");
    assert_eq!(lines.len(), 4, "the last line ends at the last section");
}
