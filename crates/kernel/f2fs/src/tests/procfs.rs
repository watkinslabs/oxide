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

/// The seven files this build publishes, and no placeholder for the one whose
/// state does not exist. `donation_list` is absent because there is no
/// page-donation machinery for it to report on, and an empty list would say
/// that nothing has donated rather than that nothing can.
#[test]
fn a_mount_publishes_exactly_the_files_it_can_fill() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    let mut names: Vec<&str> = files.iter().map(|a| a.name).collect();
    names.sort();
    assert_eq!(names, ["discard_plist_info", "disk_map", "inject_stats", "iostat_info",
                       "segment_bits", "segment_info", "victim_bits"]);
    assert!(!names.contains(&"donation_list"), "nothing here can fill it");
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

/// The measurement switch is off at mount, so the report is EMPTY rather than
/// a table of zeroes: the two say different things, and only one of them is
/// true of a mount nobody asked to measure.
#[test]
fn the_iostat_report_is_empty_until_the_control_turns_it_on() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    assert!(show(&files, "iostat_info").is_empty());
    enable_iostat(&fs);
    let body = show(&files, "iostat_info");
    assert!(body.starts_with("time:"), "{body}");
    assert!(body.contains("\n[WRITE]\n") && body.contains("\n[READ]\n"));
}

/// The published file follows the live mount, not a snapshot taken when the
/// file was built.
#[test]
fn the_iostat_report_follows_what_the_mount_does() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    enable_iostat(&fs);
    let ino = make_file(&fs, "f");
    fs.write(ino, 0, &alloc::vec![3u8; BLKSIZE]).expect("write");
    let row = row_in(&show(&files, "iostat_info"), "[WRITE]", "app buffered data");
    assert_eq!(row, (BLKSIZE as u64, 1));
}

/// The blocks a checkpoint hands back to the device are charged where the
/// device is actually told about them, which is above the volume.
#[test]
fn announced_discards_reach_the_iostat_report() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    assert!(fs.options().discard, "the fixture must be announcing freed space");
    let ino = make_file(&fs, "f");
    fs.write(ino, 0, &alloc::vec![3u8; 8 * BLKSIZE]).expect("write");
    fs.checkpoint().expect("checkpoint");
    enable_iostat(&fs);
    // The guard is bound rather than passed inline: a lock taken in an
    // argument lives until the end of the statement, and the call would take
    // it again.
    let root = fs.volume.lock().root_ino();
    fs.remove(root, "f", false).expect("remove");
    fs.checkpoint().expect("checkpoint");
    let (bytes, count) = row_in(&show(&files, "iostat_info"), "[OTHER]", "fs discard");
    assert!(count > 0, "nothing was charged for the runs handed to the device");
    assert!(bytes >= BLKSIZE as u64, "a discard of no bytes was counted");
}

/// Every site is listed whether or not it is armed: a report of only the armed
/// ones would make "never fired" and "never asked to fire" the same absence.
#[test]
fn the_injection_report_lists_every_site_and_counts_what_fired() {
    use crate::fault::{Fault, Which};
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    let before = show(&files, "inject_stats");
    assert_eq!(before.lines().next().unwrap(), "fault_type\t\tinjected_count");
    assert_eq!(before.lines().count(), 1 + crate::fault::FAULT_MAX as usize);
    assert!(before.lines().skip(1).all(|l| l.split_whitespace().last() == Some("0")));

    {
        let v = fs.volume.lock();
        v.set_fault(1, 0, Which::RATE).expect("rate");
        v.set_fault(0, Fault::ReadIo.bit(), Which::TYPE).expect("type");
        assert!(v.read_block(crate::test_image::MAIN_BLKADDR).is_err(), "the site did not fire");
    }
    let after = show(&files, "inject_stats");
    let row = after.lines().find(|l| l.starts_with(Fault::ReadIo.name())).expect("the row");
    assert_eq!(row.split_whitespace().last(), Some("1"));
}

/// The cleaner's memory is published as one digit per section, and it follows
/// the live map rather than a copy taken when the file was built.
#[test]
fn the_victim_report_follows_the_cleaners_memory() {
    let fs = mounted("/dev/vda");
    let files = mount_files(&fs);
    let sections = fs.volume.lock().section_count();
    let empty = show(&files, "victim_bits");
    assert_eq!(empty.lines().next().unwrap(), "format: victim_secmap bitmaps");
    // The line labels are digits too, so the count is taken over the report's
    // BITS — everything past the ten-wide label column — rather than over the
    // whole text, which would count a section number as a section's state.
    assert_eq!(bits_of(&empty), alloc::vec!['0'; sections as usize]);

    fs.volume.lock().mark_victim_section(0);
    let after = show(&files, "victim_bits");
    assert_ne!(empty, after, "the report did not follow the map");
    let digits = bits_of(&after);
    assert_eq!(digits[0], '1');
    assert_eq!(digits.len(), sections as usize);
    assert!(digits[1..].iter().all(|&c| c == '0'));
}

/// Turn the published measurement control on, through the control itself
/// rather than around it — a test that reached past it would pass while the
/// control did nothing.
fn enable_iostat(fs: &Arc<F2fs>) {
    let attrs = crate::sysfs::mount_attrs(fs);
    let a = attrs.iter().find(|a| a.name == "iostat_enable").expect("published");
    (a.store.as_ref().expect("writable"))(b"1\n").expect("accepted");
    assert!(fs.volume.lock().iostat_enabled());
}

/// # C: O(depth) blocks
fn make_file(fs: &Arc<F2fs>, name: &str) -> u32 {
    let root = fs.volume.lock().root_ino();
    fs.make(root, name, crate::mode::S_IFREG | 0o644, 0, 0, 0, None, true).expect("create").ino() as u32
}

/// One row's `(bytes, count)` from the named section of the iostat report.
/// The labels repeat across sections, so the section is part of the lookup.
/// # C: O(len)
fn row_in(body: &str, section: &str, label: &str) -> (u64, u64) {
    let mut here = false;
    for line in body.lines() {
        if line.starts_with('[') { here = line == section; continue; }
        if !here { continue; }
        let Some(rest) = line.strip_prefix(&alloc::format!("{label}:")) else { continue };
        let f: Vec<&str> = rest.split_whitespace().collect();
        return (f[0].parse().unwrap(), f[1].parse().unwrap());
    }
    panic!("no row {label} in {section}\n{body}");
}

/// The report's bits, without the section numbers that label each line.
/// # C: O(len)
fn bits_of(body: &str) -> Vec<char> {
    body.lines().skip(1).flat_map(|l| l.chars().skip(10)).filter(|c| *c != ' ').collect()
}
