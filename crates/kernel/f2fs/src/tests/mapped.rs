//! What a MAPPING of a file asks the volume for.
//!
//! Asserted against the rendered report and against the MEDIUM, never against
//! an internal counter: the report is what a tool reads, and an edit made to
//! the image behind the mapping's back is the only way to tell an answer that
//! came from the mapping from one that came from the device.
//!
//! Two of these are the reason this layer exists rather than the fault simply
//! calling `read_file`. A fault charged as a buffered read would report a
//! program that never called `read` as having done so, and the mapped figure —
//! the only way to see how much of a volume's traffic is faults — would stay
//! at zero however many there were. A window charged to the mapped layer would
//! do the reverse and report faults nothing took.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::mode::S_IFREG;
use crate::stats::iostat_info_body;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, I_COMPRESS_ALGORITHM, I_FLAGS, I_LOG_CLUSTER_SIZE};
use crate::volume::map::Mapped;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }
fn filled(byte: u8) -> Vec<u8> { vec![byte; BLKSIZE] }

/// A writable volume with accounting on and one empty regular file.
fn measured() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.set_iostat_enabled(true);
    (v, ino)
}

fn body(v: &Volume<MemImage>) -> String {
    String::from_utf8(iostat_info_body(&v.counters().iostat, 7)).expect("utf-8")
}

/// One row's `(bytes, count)` from the named section. The labels repeat across
/// sections, so the lookup is scoped or a write answers for a read.
fn row(body: &str, section: &str, label: &str) -> (u64, u64) {
    let mut in_section = false;
    for line in body.lines() {
        if line.starts_with('[') { in_section = line == section; continue; }
        if !in_section { continue; }
        let Some(rest) = line.strip_prefix(&alloc::format!("{label}:")) else { continue };
        let f: Vec<&str> = rest.split_whitespace().collect();
        return (f[0].parse().unwrap(), f[1].parse().unwrap());
    }
    panic!("no row {label} in {section}\n{body}");
}

/// Overwrite file page `index` ON THE MEDIUM under whatever the mapping holds.
fn poke_page(v: &Volume<MemImage>, ino: u32, index: u64, byte: u8) {
    let i = v.read_inode(ino).unwrap();
    let Mapped::At(addr) = v.map_block(&i, ino, index).unwrap() else { panic!("no block") };
    v.source_ref().poke(addr as usize * BLKSIZE, &filled(byte));
}

/// The report's mapped-read row is raised by a fault's fill and by nothing
/// else. Before this layer existed the row could not be raised at all: the one
/// site that reads a file's bytes charged every read to the buffered kind.
#[test]
fn a_faults_fill_is_charged_to_the_mapped_layer_and_not_the_buffered_one() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let before = row(&body(&v), "[READ]", "app buffered data");

    let mut got = vec![0u8; BLKSIZE];
    assert_eq!(v.read_mapped(ino, 0, &mut got).unwrap(), BLKSIZE);
    assert_eq!(got, filled(0xA1), "the fault got the file's bytes");

    let b = body(&v);
    assert_eq!(row(&b, "[READ]", "app mapped data"), (BLKSIZE as u64, 1));
    assert_eq!(row(&b, "[READ]", "app buffered data"), before,
               "a fault is not a read(2) and must not be counted as one");
}

/// A fault and a `read` resolve through ONE copy of the page. Proved by
/// editing the medium under it: whichever way the second reader comes, it gets
/// what the first reader filed and not what the device now holds.
#[test]
fn a_fault_and_a_read_see_one_copy_of_the_page() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let mut got = vec![0u8; BLKSIZE];
    v.read_mapped(ino, 0, &mut got).unwrap();

    poke_page(&v, ino, 0, 0xB2);
    let i = v.read_inode(ino).unwrap();
    let mut via_read = vec![0u8; BLKSIZE];
    v.read_file(&i, ino, 0, &mut via_read).unwrap();
    assert_eq!(via_read, filled(0xA1), "the read fetched a second copy from the device");

    let mut via_fault = vec![0u8; BLKSIZE];
    v.read_mapped(ino, 0, &mut via_fault).unwrap();
    assert_eq!(via_fault, filled(0xA1), "the fault fetched a second copy from the device");
}

/// A compressed file's fault appears under both its kinds, because the
/// compressed figure answers what share of the traffic was compressed and a
/// partition of the total could not.
#[test]
fn a_compressed_files_fault_is_counted_under_both_its_kinds() {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        crate::volume::dnode::put32(b, I_FLAGS, f);
        b[I_COMPRESS_ALGORITHM] = crate::compress::algo::COMPRESS_LZ4;
        b[I_LOG_CLUSTER_SIZE] = 2;
    })
    .unwrap();
    let data = vec![9u8; 4 * BLKSIZE];
    v.write_file(ino, 0, &data).unwrap();
    v.sync_data().unwrap();
    v.set_iostat_enabled(true);

    let mut got = vec![0u8; BLKSIZE];
    v.read_mapped(ino, 0, &mut got).unwrap();
    let b = body(&v);
    assert_eq!(row(&b, "[READ]", "app mapped data"), (BLKSIZE as u64, 1));
    assert_eq!(row(&b, "[READ]", "app mapped cdata"), (BLKSIZE as u64, 1),
               "the fault was over a compressed file and is compressed traffic too");
}

/// A window is the filesystem's traffic, not the application's: nothing has
/// faulted over these pages yet, and charging them to the mapped layer would
/// report faults that have not happened.
#[test]
fn a_window_is_charged_to_the_filesystem_and_not_to_faults() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &vec![0xA1; 4 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    // The write left the pages in the mapping; a window over held pages must
    // fetch nothing at all.
    let quiet = row(&body(&v), "[READ]", "fs data");
    v.populate_mapped(ino, 0, 4);
    assert_eq!(row(&body(&v), "[READ]", "fs data"), quiet, "a held page was fetched again");

    // Drop them, then ask for the window: now it fetches, and the charge lands
    // on the filesystem.
    for i in 0..4 { v.data_cache().forget(ino, i); }
    v.populate_mapped(ino, 0, 4);
    let b = body(&v);
    assert!(row(&b, "[READ]", "fs data").1 >= 4, "the window fetched nothing");
    assert_eq!(row(&b, "[READ]", "app mapped data"), (0, 0),
               "a window is not a fault and must not be counted as one");
    for i in 0..4 { assert!(v.page_held(ino, i), "page {i} was not brought in"); }
}

/// A window stops at the end of the file rather than fetching past it.
#[test]
fn a_window_running_past_the_end_stops_there() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    v.data_cache().forget(ino, 0);
    v.populate_mapped(ino, 0, 64);
    assert!(v.page_held(ino, 0));
    assert!(!v.page_held(ino, 1), "a page past the end was brought in");
}

/// Residency and backing are different questions. A page the mapping does not
/// hold is not a hole: the block is on the medium, and calling a fault over it
/// a fault over a hole would answer it with zeroes.
#[test]
fn a_page_not_held_is_still_backed_when_the_block_exists() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    v.data_cache().forget(ino, 0);
    assert!(!v.page_held(ino, 0), "the fixture did not drop the page");
    assert!(v.page_backed(ino, 0), "the block is on the medium");
    assert!(!v.page_backed(ino, 99), "past the end nothing is backed");
}

/// A page dirtied by a write is backed before it has any address at all: its
/// slot holds a reservation, which the tree reports as a hole.
#[test]
fn a_page_awaiting_placement_is_backed_though_it_has_no_address() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert!(v.page_held(ino, 0));
    assert!(v.page_backed(ino, 0));
}

/// A truncate's range takes WHOLE pages only. A page straddling either
/// boundary keeps its contents, because the caller is zeroing part of it and
/// dropping the page would throw away the bytes on the other side of the cut.
#[test]
fn a_range_invalidation_spares_a_page_it_only_partly_covers() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &vec![0xA1; 4 * BLKSIZE]).unwrap();
    let blk = BLKSIZE as u64;
    // [half of page 0 .. half of page 3): pages 1 and 2 are whole, 0 and 3 are not.
    assert_eq!(v.forget_whole_pages(ino, blk / 2, 3 * blk + blk / 2), 2);
    assert!(v.page_held(ino, 0) && v.page_held(ino, 3), "a partly covered page went");
    assert!(!v.page_held(ino, 1) && !v.page_held(ino, 2));
    // To the end of the file drops everything from the rounded-up page on.
    assert_eq!(v.forget_whole_pages(ino, blk / 2, u64::MAX), 1, "page 3, not page 0");
    assert!(v.page_held(ino, 0));
    assert!(!v.page_held(ino, 3));
}

/// A hint is a hint. A dirty page is the only copy of a write, so it stays;
/// the clean pages beside it go.
#[test]
fn a_hint_leaves_the_page_that_holds_the_only_copy_of_a_write() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &vec![0xA1; 4 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    // Page 2 alone is dirty again; the rest are placed and clean.
    v.write_file(ino, 2 * BLKSIZE as u64, &filled(0xC3)).unwrap();
    assert_eq!(v.try_forget_pages(ino, 0, 3), 3, "the three clean pages");
    assert!(v.page_held(ino, 2), "the unplaced write was dropped");
    let i = v.read_inode(ino).unwrap();
    let mut got = vec![0u8; BLKSIZE];
    v.read_file(&i, ino, 2 * BLKSIZE as u64, &mut got).unwrap();
    assert_eq!(got, filled(0xC3), "the write did not survive the hint");
}

/// The census reports what the file holds and in what state, and visits only
/// pages that exist — which is what makes an unbounded range answerable.
#[test]
fn the_census_reports_held_pages_and_their_dirtiness() {
    let (mut v, ino) = measured();
    v.write_file(ino, 0, &vec![0xA1; 3 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.write_file(ino, BLKSIZE as u64, &filled(0xC3)).unwrap();
    let seen = v.page_states(ino, 0, u64::MAX);
    assert_eq!(seen.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 1, 2]);
    assert_eq!(seen.iter().filter(|s| s.dirty).map(|s| s.index).collect::<Vec<_>>(), vec![1]);
    assert!(v.page_states(ino, 50, 60).is_empty());
}

/// The length the mapping answers with is the file's length NOW, not the one
/// it had when the handle was made.
#[test]
fn the_length_follows_the_file() {
    let (mut v, ino) = measured();
    assert_eq!(v.mapped_size(ino), 0);
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(v.mapped_size(ino), BLKSIZE as u64);
    v.truncate_file(ino, 7).unwrap();
    assert_eq!(v.mapped_size(ino), 7);
}
