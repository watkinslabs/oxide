// `FAN_PRE_ACCESS` / `FAN_EVENT_INFO_TYPE_RANGE` hosted tests.
//
// The pre-content gate is what a pre-content group exists for: it is asked
// BEFORE the bytes are looked at, and it is told which bytes. The tests drive it
// through `fs::truncate::do_ftruncate` — a real production entry point — and
// through the gate the read/write/mmap/fallocate slots call, then read the
// queued record back off the wire.
//
// Included as a child module of `inotify` via `#[path]`, so `use super::*`
// reaches the module-private mark/dispatch items.

use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::inotify::fan_layout::FAN_EVENT_METADATA_LEN;
use crate::inotify::fan_range::{aligned_range, FAN_EVENT_INFO_TYPE_RANGE, RANGE_INFO_LEN};
use crate::inotify::syscalls::apply_mark;
use crate::inotify::types::FAN_ACCESS_PERM;
use crate::inotify::validate::FAN_CLASS_PRE_CONTENT;
use vfs::{default_inode_ops, mk_mode, FileType, InodeBuilder, OpenFlags};

/// One decoded event: its mask and the byte range it names, if any.
#[derive(Debug, PartialEq, Eq)]
struct RangeRecord { mask: u32, range: Option<(u64, u64)> }

fn file_on(fsid: u64, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(InotifyFileOps))
        .fsid(fsid).build()
}

/// A pre-content group with an inode mark for `mask`. Only a pre-content class
/// group may hold `FAN_PRE_ACCESS`, which is what makes the gate reachable.
/// # C: O(1)
fn pre_group(ino: &InodeRef, mask: u32) -> Arc<InotifyData> {
    let g = InotifyData::new_fanotify(FAN_CLASS_PRE_CONTENT);
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(ino), ino.fsid(), mask, true, false, 0), 0);
    g
}

fn drop_mark(g: &Arc<InotifyData>, ino: &InodeRef, mask: u32) {
    apply_mark(g, MarkScope::Inode, inode_key(ino), ino.fsid(), mask, false, false, 0);
}

/// Drain the group and decode each event as `(mask, range)`. The range record,
/// when present, is the LAST record of the event. # C: O(records)
fn read_ranges(g: &InotifyData) -> Vec<RangeRecord> {
    let mut buf = [0u8; 1024];
    let Ok(n) = g.read_fanotify(&mut buf) else { return Vec::new() };
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < n {
        let ev_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let mask = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap()) as u32;
        let range = if ev_len == FAN_EVENT_METADATA_LEN + RANGE_INFO_LEN {
            let r = off + FAN_EVENT_METADATA_LEN;
            assert_eq!(buf[r], FAN_EVENT_INFO_TYPE_RANGE);
            assert_eq!(buf[r + 1], 0, "pad byte is zero");
            assert_eq!(u16::from_le_bytes([buf[r + 2], buf[r + 3]]), RANGE_INFO_LEN as u16);
            assert_eq!(u32::from_le_bytes(buf[r + 4..r + 8].try_into().unwrap()), 0, "pad word");
            Some((u64::from_le_bytes(buf[r + 8..r + 16].try_into().unwrap()),
                  u64::from_le_bytes(buf[r + 16..r + 24].try_into().unwrap())))
        } else {
            assert_eq!(ev_len, FAN_EVENT_METADATA_LEN, "bare metadata or metadata plus one range");
            None
        };
        out.push(RangeRecord { mask, range });
        off += ev_len;
    }
    out
}

/// THE production-path test: `ftruncate(2)`'s work function asks the
/// pre-content gate BEFORE it changes the size, and the record names the range
/// holding the new end of the file.
/// # C: O(1)
#[test]
fn a_real_ftruncate_asks_the_pre_content_gate_with_a_range() {
    let ino = file_on(0xA101, 0xA101_0001);
    let g = pre_group(&ino, FAN_PRE_ACCESS);
    let dentry = vfs::dcache::d_alloc_pseudo("trunc", ino.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let file = vfs::File::new(ino.clone(), dentry, OpenFlags::O_RDWR);
    let len = 5000u64;
    // The size change itself has no backend here; the gate runs first, which is
    // the whole point — a pre-content watcher fills content BEFORE it is cut.
    let _ = crate::truncate::do_ftruncate(&file, len, &vfs::Cred::root());
    assert_eq!(read_ranges(&g),
               [RangeRecord { mask: FAN_PRE_ACCESS, range: Some(aligned_range(len, 0)) }]);
    drop_mark(&g, &ino, FAN_PRE_ACCESS);
}

/// A read asks BOTH content gates, in order: the pre-content watcher fills the
/// bytes, then the scanner inspects what is now there. A write asks only the
/// first — there is nothing to inspect yet.
/// # C: O(1)
#[test]
fn a_read_asks_both_content_gates_and_a_write_only_the_first() {
    let ino = file_on(0xA102, 0xA102_0001);
    let g = pre_group(&ino, FAN_PRE_ACCESS | FAN_ACCESS_PERM);
    assert_eq!(crate::inotify::check_file_area_perm(&ino, false, Some(0), 1), Ok(()));
    assert_eq!(read_ranges(&g), [
        RangeRecord { mask: FAN_PRE_ACCESS, range: Some(aligned_range(0, 1)) },
        RangeRecord { mask: FAN_ACCESS_PERM, range: None },
    ]);
    assert_eq!(crate::inotify::check_file_area_perm(&ino, true, Some(0), 1), Ok(()));
    assert_eq!(read_ranges(&g),
               [RangeRecord { mask: FAN_PRE_ACCESS, range: Some(aligned_range(0, 1)) }],
               "a write is not inspected by a content scanner");
    drop_mark(&g, &ino, FAN_PRE_ACCESS | FAN_ACCESS_PERM);
}

/// An access that names no offset carries NO range record: the event asks about
/// the file as a whole, and a fabricated range would be a lie about which bytes
/// the watcher has to fill.
/// # C: O(1)
#[test]
fn an_access_with_no_offset_carries_no_range_record() {
    let ino = file_on(0xA103, 0xA103_0001);
    let g = pre_group(&ino, FAN_PRE_ACCESS);
    assert_eq!(crate::inotify::check_file_area_perm(&ino, false, None, 0), Ok(()));
    assert_eq!(read_ranges(&g), [RangeRecord { mask: FAN_PRE_ACCESS, range: None }]);
    drop_mark(&g, &ino, FAN_PRE_ACCESS);
}

/// `mmap` asks the pre-content gate and nothing else: the mapping promises the
/// bytes will be readable at a point where no syscall is left to refuse, so the
/// content must exist now — but nothing has been inspected.
/// # C: O(1)
#[test]
fn an_mmap_asks_only_the_pre_content_gate() {
    let ino = file_on(0xA104, 0xA104_0001);
    let g = pre_group(&ino, FAN_PRE_ACCESS | FAN_ACCESS_PERM);
    assert_eq!(crate::inotify::check_mmap_perm(&ino, 8192, 4096), Ok(()));
    assert_eq!(read_ranges(&g),
               [RangeRecord { mask: FAN_PRE_ACCESS, range: Some(aligned_range(8192, 4096)) }]);
    drop_mark(&g, &ino, FAN_PRE_ACCESS | FAN_ACCESS_PERM);
}

/// The reported window always COVERS the access, widened outward to whole
/// granules — a watcher fills pages, and a byte-exact window would leave the
/// rest of the page unfilled.
/// # C: O(1)
#[test]
fn the_reported_window_covers_the_whole_access() {
    let ino = file_on(0xA105, 0xA105_0001);
    let g = pre_group(&ino, FAN_PRE_ACCESS);
    // An access straddling a granule boundary reports both granules.
    assert_eq!(crate::inotify::check_file_area_perm(&ino, true, Some(4095), 2), Ok(()));
    let recs = read_ranges(&g);
    let (start, count) = recs[0].range.expect("a range record");
    assert!(start <= 4095, "the window starts at or before the access");
    assert!(start + count >= 4097, "and ends at or after it");
    drop_mark(&g, &ino, FAN_PRE_ACCESS);
}

/// A group with no pre-content mark pays nothing and blocks nothing: the gate
/// is a single counter load on a system with no watcher, which is every system
/// that is not running one.
/// # C: O(1)
#[test]
fn a_file_with_no_pre_content_mark_is_never_gated() {
    let ino = file_on(0xA106, 0xA106_0001);
    let g = InotifyData::new_fanotify(FAN_CLASS_PRE_CONTENT);
    assert_eq!(crate::inotify::check_file_area_perm(&ino, false, Some(0), 4096), Ok(()));
    assert_eq!(crate::inotify::check_mmap_perm(&ino, 0, 4096), Ok(()));
    assert_eq!(crate::inotify::check_truncate_perm(&ino, 0), Ok(()));
    assert!(g.events.lock().is_empty());
}

/// `FAN_PRE_ACCESS` belongs to the pre-content class alone, and never combines
/// with `FAN_ONDIR`: a directory has no content to fill.
/// # C: O(1)
#[test]
fn pre_access_is_a_pre_content_class_mask_and_never_names_a_directory() {
    use syscall::errno::Errno;
    let pre = InotifyData::new_fanotify(FAN_CLASS_PRE_CONTENT);
    assert_eq!(validate_fanotify_mark_group(&pre, MarkScope::Inode, FAN_PRE_ACCESS, 0, true), Ok(()));
    assert_eq!(validate_fanotify_mark_group(&pre, MarkScope::Inode,
                                            FAN_PRE_ACCESS | FAN_ONDIR, 0, true),
               Err(Errno::Einval));
    let content = InotifyData::new_fanotify(FAN_CLASS_CONTENT);
    assert_eq!(validate_fanotify_mark_group(&content, MarkScope::Inode, FAN_PRE_ACCESS, 0, true),
               Err(Errno::Einval));
    let notif = InotifyData::new_fanotify(0);
    assert_eq!(validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_PRE_ACCESS, 0, true),
               Err(Errno::Einval));
}

/// Two pre-content events are two records: each is the one record its blocked
/// accessor is waiting for, so neither can be folded into the other however
/// alike they look.
/// # C: O(1)
#[test]
fn pre_content_events_are_never_merged() {
    let ino = file_on(0xA107, 0xA107_0001);
    let g = pre_group(&ino, FAN_PRE_ACCESS);
    assert_eq!(crate::inotify::check_file_area_perm(&ino, true, Some(0), 1), Ok(()));
    assert_eq!(crate::inotify::check_file_area_perm(&ino, true, Some(0), 1), Ok(()));
    assert_eq!(read_ranges(&g).len(), 2);
    drop_mark(&g, &ino, FAN_PRE_ACCESS);
}
