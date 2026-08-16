//! `/proc/fs/f2fs` — the report formats, and that they render live state.
//!
//! These files are parsed by tools, so the tests pin the shape: the header
//! lines, the column widths, how many entries a line carries, and where the
//! newlines fall. A body that carries the right numbers in the wrong columns
//! is a file nothing can read.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::summary::SitEntry;
use crate::test_image;
use crate::uapi::{BLKSIZE, SIT_VBLOCK_MAP_SIZE};

use super::{disk_map_body, discard_plist_body, mount_dir, mount_files, plist_idx,
            segment_bits_body, segment_info_body, FS_NAME, MAX_PLIST_NUM};

const BS: u32 = BLKSIZE as u32;

fn mounted(source: &str) -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    F2fs::open_with(dev, source, true, Options::defaults()).expect("mount")
}

fn find<'a>(files: &'a [Attr], name: &str) -> &'a Attr {
    files.iter().find(|a| a.name == name).unwrap_or_else(|| panic!("no file {name}"))
}

fn show(files: &[Attr], name: &str) -> String {
    String::from_utf8((find(files, name).show)().expect("show")).expect("utf-8")
}

fn entry(seg_type: u8, valid: u16, mtime: u64) -> SitEntry {
    let mut e = SitEntry { vblocks: 0, valid_map: [0u8; SIT_VBLOCK_MAP_SIZE], mtime };
    e.vblocks = (u16::from(seg_type) << 10) | valid;
    e
}

#[test]
fn the_directory_is_named_for_the_filesystem_and_the_device() {
    assert_eq!(FS_NAME, "f2fs");
    assert_eq!(mount_dir("/dev/vda"), "vda");
    let fs = mounted("/dev/vda");
    assert!(mount_files(&fs).iter().all(|a| a.dir == "vda"));
}

/// The four files this build publishes, and no placeholder for the four whose
/// state does not exist.
#[test]
fn a_mount_publishes_exactly_the_files_it_can_fill() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    let mut names: Vec<&str> = files.iter().map(|a| a.name).collect();
    names.sort();
    assert_eq!(names, ["discard_plist_info", "disk_map", "segment_bits", "segment_info"]);
    for a in files.iter() { assert!(a.store.is_none(), "{} accepts a write", a.name); }
}

/// `segment_info` puts ten segments on a line, each `type|valid_blocks`, with
/// the line's first segment number in a ten-wide column.
#[test]
fn segment_info_lays_ten_segments_per_line() {
    let entries: Vec<SitEntry> = (0..12).map(|i| entry((i % 6) as u8, i as u16, 0)).collect();
    let body = segment_info_body(12, &entries);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], "format: segment_type|valid_blocks");
    assert_eq!(lines[1], "segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)");
    assert_eq!(lines[2], "0         0|0   1|1   2|2   3|3   4|4   5|5   0|6   1|7   2|8   3|9  ");
    assert_eq!(lines[3], "10        4|10  5|11 ");
    assert_eq!(lines.len(), 4, "no trailing blank line");
}

/// A count that is not a multiple of ten still ends its last line.
#[test]
fn segment_info_terminates_a_short_last_line() {
    let entries: Vec<SitEntry> = (0..3).map(|_| entry(0, 1, 0)).collect();
    let body = segment_info_body(3, &entries);
    assert!(body.ends_with("0|1  \n"), "{body:?}");
}

/// `segment_bits` gives one segment per line and the whole validity bitmap.
#[test]
fn segment_bits_prints_the_whole_bitmap_and_the_timestamp() {
    let mut e = entry(2, 3, 0x1f);
    e.valid_map[0] = 0x07;
    e.valid_map[SIT_VBLOCK_MAP_SIZE - 1] = 0xa0;
    let body = segment_bits_body(1, &[e]);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines[0], "format: segment_type|valid_blocks|bitmaps|mtime");
    assert_eq!(lines[1], "segment_type(0:HD, 1:WD, 2:CD, 3:HN, 4:WN, 5:CN)");
    assert!(lines[2].starts_with("0         2|3  | 07 00"), "{:?}", lines[2]);
    assert!(lines[2].ends_with(" a0| 1f"), "{:?}", lines[2]);
    // Ten leading columns, then `d|%-3u|`, then one three-character group per
    // bitmap byte, then the timestamp.
    assert_eq!(lines[2].len(), 10 + 6 + 3 * SIT_VBLOCK_MAP_SIZE + 2 + 2);
    assert_eq!(lines.len(), 3);
}

/// Both segment reports must come from the live table, not from a snapshot:
/// the fixture's own segment count and types have to appear.
#[test]
fn the_segment_reports_render_the_mounted_volume() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    let total = fs.volume.lock().super_block().segment_count_main;
    let info = show(&files, "segment_info");
    let bits = show(&files, "segment_bits");
    // One line per segment in `segment_bits`, plus the two header lines.
    assert_eq!(bits.lines().count(), total as usize + 2);
    // Ten segments per line in `segment_info`, plus the two header lines.
    let want = (total as usize).div_ceil(10) + 2;
    assert_eq!(info.lines().count(), want);
    // The fixture holds a root directory, so some segment must report live
    // blocks. A report of all-zero occupancy is what an unread table looks
    // like, and it is indistinguishable from an empty volume.
    let live: u32 = (0..total)
        .map(|s| u32::from(fs.volume.lock().seg_entry(s).expect("entry").valid_blocks()))
        .sum();
    assert!(live > 0, "the segment table reported no live block anywhere");
    assert!(info.contains("|1 ") || info.contains("|2 ") || info.contains("|3 "),
        "segment_info reported no non-zero occupancy");
}

/// `disk_map` reports the volume's real addresses. Every area must appear
/// with the address the superblock carries, or the report describes a
/// different volume.
#[test]
fn disk_map_reports_every_area_at_its_real_address() {
    let fs = mounted("/dev/vda");
    let body = {
        let v = fs.volume.lock();
        disk_map_body(v.super_block(), v.devices(), v.zones())
    };
    let sb = fs.volume.lock();
    let sb = sb.super_block();
    assert!(body.contains(&alloc::format!(" seg0_blkaddr  : 0x{:010x}\n", sb.segment0_blkaddr)));
    assert!(body.contains(&alloc::format!(" SIT           : 0x{:010x} ({:10})\n",
        sb.sit_blkaddr, sb.segment_count_sit)));
    assert!(body.contains(&alloc::format!(" NAT           : 0x{:010x} ({:10})\n",
        sb.nat_blkaddr, sb.segment_count_nat)));
    assert!(body.contains(&alloc::format!(" SSA           : 0x{:010x} ({:10})\n",
        sb.ssa_blkaddr, sb.segment_count_ssa)));
    assert!(body.contains(&alloc::format!(" Main          : 0x{:010x} ({:10})\n",
        sb.main_blkaddr, sb.segment_count_main)));
    assert!(body.contains(&alloc::format!(" # of Sections : {:12}\n", sb.section_count)));
    assert!(body.starts_with("Address Layout   :  4096B Block address (# of Segments)\n"));
    assert!(body.contains(" Block size    :            4 KB\n"));
    // A single-device volume ends at the section count; the multi-device
    // section belongs only to a volume that has one.
    assert!(!body.contains("Disk Map for multi devices"));
}

/// A run's bucket is its length minus one, and everything at or past the last
/// bucket lands in it so the report keeps a fixed width.
#[test]
fn a_runs_bucket_is_its_length_and_the_last_bucket_absorbs_the_rest() {
    assert_eq!(plist_idx(1), 0);
    assert_eq!(plist_idx(2), 1);
    assert_eq!(plist_idx(MAX_PLIST_NUM as u32 - 1), MAX_PLIST_NUM - 2);
    assert_eq!(plist_idx(MAX_PLIST_NUM as u32), MAX_PLIST_NUM - 1);
    assert_eq!(plist_idx(u32::MAX), MAX_PLIST_NUM - 1);
}

/// A mount that does not announce discards prints the header and stops: the
/// queue would mean nothing, which is a different statement from empty.
#[test]
fn the_discard_report_stops_at_the_header_when_discard_is_off() {
    let body = discard_plist_body(false, &[(10, 3)]);
    assert_eq!(body.lines().count(), 1);
    assert!(body.starts_with("Discard pend list("));
}

/// Every bucket appears, eight to a line, each either its count or a dot.
#[test]
fn the_discard_report_shows_every_bucket_eight_to_a_line() {
    let body = discard_plist_body(true, &[(10, 1), (20, 1), (30, 3)]);
    let lines: Vec<&str> = body.lines().collect();
    // Header, sixty-four bucket lines, and the blank line that closes the report.
    assert_eq!(lines.len(), 1 + MAX_PLIST_NUM / 8 + 1);
    // Bucket 0 holds the two one-block runs, bucket 2 the three-block run.
    assert_eq!(lines[1], "  0         2       .       1       .       .       .       .       .");
    assert_eq!(lines[2], "  8         .       .       .       .       .       .       .       .");
}

/// The report must come off the live queue.
#[test]
fn the_discard_report_follows_the_live_queue() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    let empty = show(&files, "discard_plist_info");
    assert!(empty.contains("  0         .       ."), "{:?}", empty.lines().nth(1));

    fs.volume.lock().pending_discard.extend_from_slice(&[100, 200, 201]);

    let after = show(&files, "discard_plist_info");
    assert_ne!(empty, after, "the report did not follow the queue");
    assert!(after.contains("  0         1       1"), "{:?}", after.lines().nth(1));
}
