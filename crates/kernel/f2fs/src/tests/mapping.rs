//! The address space a mounted file's inode carries.
//!
//! These are WIRING tests, and the wiring is the whole deliverable: the
//! operations below are reached by the memory manager only through
//! `inode->i_mapping`, so an inode built without one sends every fault down the
//! manager's own byte cache instead — a second copy of every page, filled by
//! `read`, that stops agreeing with the file the moment either side writes. An
//! implementation nothing installs is indistinguishable from no implementation.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use vfs::{CachestatRange, FileType};

use crate::mount::F2fs;
use crate::opts::Options;
use crate::stats::iostat_info_body;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;

const FILE_INO: u32 = 11;

fn filled(byte: u8) -> Vec<u8> { vec![byte; BLKSIZE] }

/// A mounted volume holding one two-block regular file, with accounting on.
fn mounted() -> Arc<F2fs> {
    let mut b = test_image::with_root();
    let data: Vec<(u64, Vec<u8>)> = (0..2u64).map(|i| (i, filled(0xA0 + i as u8))).collect();
    test_image::nodes::add_sparse_file(&mut b, FILE_INO, 2 * BLKSIZE as u64, &data);
    let bytes = b.finish();
    let blocks = bytes.len() as u64 / BLKSIZE as u64;
    let dev: Arc<block::MemDisk<sync::TaskList>> = block::MemDisk::new(BLKSIZE as u32, blocks);
    let mut req = block::BlockRequest::new_write(0, blocks as u32, bytes);
    block::BlockDevice::submit_sync(&*dev, &mut req).expect("device write");
    let fs = F2fs::open_with(dev, "/dev/fake", true, Options::defaults()).expect("mount");
    fs.volume.lock().set_iostat_enabled(true);
    fs
}

fn inode_of(fs: &Arc<F2fs>, ino: u32) -> vfs::InodeRef {
    crate::mount::node::node_inode(Arc::clone(fs), ino).expect("inode")
}

fn body(fs: &Arc<F2fs>) -> String {
    String::from_utf8(iostat_info_body(&fs.volume.lock().counters().iostat, 7)).expect("utf-8")
}

/// One row's `(bytes, count)` from the named section.
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

/// The wire itself. Without this the rest of the file is unreachable code.
#[test]
fn a_regular_files_inode_carries_an_address_space() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    assert_eq!(f.file_type(), FileType::Regular);
    assert!(f.i_mapping().is_some(), "a regular file's faults have nowhere to resolve");
}

#[test]
fn the_inode_time_owner_persists_a_write_stamp() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let stamp = vfs::Timespec64::new(1_700_000_123, 456);
    f.update_time(stamp, vfs::S_MTIME | vfs::S_CTIME | vfs::S_VERSION)
        .expect("writable f2fs inode owns write timestamps");
    assert_eq!(f.mtime(), Some(stamp));
    assert_eq!(f.ctime(), Some(stamp));
    let stored = fs.volume.lock().read_inode(FILE_INO).expect("stored inode");
    assert_eq!(stored.mtime, (stamp.sec as u64, stamp.nsec));
    assert_eq!(stored.ctime, (stamp.sec as u64, stamp.nsec));
}

/// A directory does not get one. Its blocks are read through the listing path,
/// so offering the memory manager something to fault would offer it something
/// the object does not have.
#[test]
fn a_directory_carries_none() {
    let fs = mounted();
    let d = inode_of(&fs, ROOT_INO);
    assert_eq!(d.file_type(), FileType::Directory);
    assert!(d.i_mapping().is_none());
}

/// Every opener of one file reaches ONE set of pages. The handles differ — a
/// handle is built per lookup — so this is a property of where the pages live,
/// not of the handle, and it is the property that makes two mappings of a file
/// see each other.
#[test]
fn two_handles_of_one_file_resolve_through_the_same_pages() {
    let fs = mounted();
    let a = inode_of(&fs, FILE_INO);
    let b = inode_of(&fs, FILE_INO);
    let ma = a.i_mapping().expect("a");
    let mb = b.i_mapping().expect("b");
    let mut first = vec![0u8; BLKSIZE];
    ma.read_at(0, &mut first).expect("read a");
    assert_eq!(first, filled(0xA0));
    // Drop what the FILESYSTEM holds behind the other handle; both handles then
    // report the page gone, because there is one place it could have been.
    assert!(ma.mincore_page(0));
    assert!(mb.mincore_page(0), "the second handle sees a different set of pages");
    assert_eq!(mb.invalidate_range(0, BLKSIZE as u64), 1);
    assert!(!ma.mincore_page(0), "the drop reached only one handle's pages");
}

/// The fault's fill answers with the file's bytes and is charged to the mapped
/// layer — the report row that could not be raised at all before this existed.
#[test]
fn a_fill_through_the_address_space_reads_the_file_and_is_counted_as_mapped() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    assert_eq!(m.size(), 2 * BLKSIZE as u64);

    let mut got = vec![0u8; BLKSIZE];
    assert_eq!(m.read_at(BLKSIZE as u64, &mut got), Ok(BLKSIZE));
    assert_eq!(got, filled(0xA1));

    let b = body(&fs);
    assert_eq!(row(&b, "[READ]", "app mapped data"), (BLKSIZE as u64, 1));
    assert_eq!(row(&b, "[READ]", "app buffered data"), (0, 0),
               "a fault was reported as a read(2)");
}

/// A fill past the end of the file is short, and the caller zero-fills the
/// tail. Answering it as a full page would hand back bytes the file has not
/// got.
#[test]
fn a_fill_past_the_end_is_short() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    let mut got = vec![0u8; BLKSIZE];
    assert_eq!(m.read_at(2 * BLKSIZE as u64, &mut got), Ok(0));
}

/// Residency, backing and the census are all answered from the filesystem's
/// own pages rather than from the trait's defaults, which report nothing held
/// and no page backed.
#[test]
fn the_address_space_answers_residency_from_the_filesystems_pages() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    assert!(!m.mincore_page(0), "nothing has been read yet");
    // A page absent from the mapping is still BACKED: the block is on the
    // medium. The trait's default answers false, which would call a fault over
    // a real block a fault over a hole.
    assert!(m.backing_holds_page(0));
    assert!(!m.backing_holds_page(4 * BLKSIZE as u64));

    let mut got = vec![0u8; BLKSIZE];
    m.read_at(0, &mut got).expect("fill");
    assert!(m.mincore_page(0));

    let c = m.cachestat(CachestatRange { first: 0, last: u64::MAX });
    assert_eq!(c.nr_cache, 1, "the census reports what the file holds");
    assert_eq!(c.nr_dirty, 0);
    assert_eq!(c.nr_evicted, 0);
}

/// A hint drops what can be spared; the census then says so.
#[test]
fn a_hint_drops_the_pages_the_census_then_stops_reporting() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    let mut got = vec![0u8; 2 * BLKSIZE];
    m.read_at(0, &mut got).expect("fill");
    assert_eq!(m.cachestat(CachestatRange { first: 0, last: u64::MAX }).nr_cache, 2);
    assert_eq!(m.try_invalidate_pages(0, 1), 2);
    assert_eq!(m.cachestat(CachestatRange { first: 0, last: u64::MAX }).nr_cache, 0);
}

/// A window brought in through the address space populates the filesystem's
/// pages, and is not counted as a fault.
#[test]
fn a_window_through_the_address_space_populates_the_filesystems_pages() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    m.readahead(0, 2);
    assert!(m.mincore_page(0) && m.mincore_page(BLKSIZE as u64));
    assert_eq!(row(&body(&fs), "[READ]", "app mapped data"), (0, 0),
               "a window is not a fault");
}

/// The flush and the durability leg are reachable from the mapping, which is
/// the point: an `msync` and inode eviction arrive with no open file, so
/// `f_op->fsync` is not reachable from there.
#[test]
fn the_flush_and_the_durability_leg_are_reachable_without_a_file() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    assert_eq!(m.writeback(), Ok(()));
    assert_eq!(m.writeback_range(0, u64::MAX), Ok(()));
    assert_eq!(m.sync_backing(), Ok(()));
    assert!(!m.is_shmem(), "these pages are a cache of a medium, not the store");
}

/// The hint's load-bearing rule, at the layer the memory manager reaches: a
/// page holding a write the filesystem has not placed is the only copy of those
/// bytes, so the hint leaves it and the write survives.
#[test]
fn a_hint_reached_through_the_address_space_spares_an_unplaced_write() {
    let fs = mounted();
    let f = inode_of(&fs, FILE_INO);
    let m = f.i_mapping().expect("mapping");
    let mut got = vec![0u8; 2 * BLKSIZE];
    m.read_at(0, &mut got).expect("fill");
    // Page 1 alone now holds bytes the medium does not have.
    fs.write(FILE_INO, BLKSIZE as u64, &filled(0xC3)).expect("write");
    assert_eq!(m.try_invalidate_pages(0, 1), 1, "only the clean page was droppable");
    assert!(m.mincore_page(BLKSIZE as u64), "the unplaced write was dropped");
    let mut back = vec![0u8; BLKSIZE];
    m.read_at(BLKSIZE as u64, &mut back).expect("re-read");
    assert_eq!(back, filled(0xC3), "the write did not survive the hint");
}
