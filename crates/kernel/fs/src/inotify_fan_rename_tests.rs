// `FAN_RENAME` hosted tests. Every test drives `fire_move` — the rename
// notification entry point the rename syscall calls — so the whole-rename
// record, its ordering against the MOVED_FROM/MOVED_TO pair, the per-mark half
// selection and the wire encoding all execute on the production path.
//
// Included as a child module of `inotify` via `#[path]`, so `use super::*`
// reaches the module-private mark/dispatch items.

use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::inotify::fan_layout::{FAN_EVENT_METADATA_LEN, FAN_NOFD, FANOTIFY_FID_LEN, fid_info_len};
use crate::inotify::fan_rename::{FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
    FAN_EVENT_INFO_TYPE_OLD_DFID_NAME};
use crate::inotify::syscalls::apply_mark;
use crate::inotify::validate::{FAN_REPORT_DIR_FID, FAN_REPORT_FID, FAN_REPORT_NAME};
use vfs::{default_inode_ops, mk_mode, FileType, InodeBuilder};

/// The report mode a `FAN_RENAME` mark requires. `FAN_REPORT_NAME` is checked
/// by `fanotify_mark` itself — both records carry a name, so a group that never
/// asked for names could not be told what was renamed.
const RENAME_MODE: u32 = FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;

/// One decoded info record of a rename event.
#[derive(Debug, PartialEq, Eq)]
struct Rec { info_type: u8, ino: u64, name: Vec<u8> }

fn dir_on(fsid: u64, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
                      default_inode_ops(), Arc::new(InotifyFileOps))
        .fsid(fsid).build()
}

fn file_on(fsid: u64, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(InotifyFileOps))
        .fsid(fsid).build()
}

fn group() -> Arc<InotifyData> { InotifyData::new_fanotify(RENAME_MODE) }

/// The masks currently queued, without draining. # C: O(queued)
fn masks(g: &InotifyData) -> Vec<u32> { g.events.lock().iter().map(|e| e.mask).collect() }

/// Drain the group and decode the FIRST event's info records. Every record is a
/// fid record of the fixed handle length, so each one's span is known from the
/// name it carries. # C: O(records)
fn read_rename_records(g: &InotifyData) -> (u32, i32, Vec<Rec>) {
    let mut buf = [0u8; 1024];
    let n = g.read_fanotify(&mut buf).expect("a queued event");
    let ev_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    assert!(ev_len <= n);
    let mask = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as u32;
    let fd = i32::from_le_bytes(buf[16..20].try_into().unwrap());
    let mut recs = Vec::new();
    let mut off = FAN_EVENT_METADATA_LEN;
    while off < ev_len {
        let info_type = buf[off];
        let len = u16::from_le_bytes([buf[off + 2], buf[off + 3]]) as usize;
        // `fanotify_event_info_fid`: 4-byte header, 8-byte fsid, 8-byte
        // `file_handle` header, then the handle and the NUL-terminated name.
        let h = off + 20;
        let ino = u64::from_le_bytes(buf[h..h + 8].try_into().unwrap());
        let name_at = h + FANOTIFY_FID_LEN;
        let name: Vec<u8> = buf[name_at..off + len].iter().copied()
            .take_while(|b| *b != 0).collect();
        recs.push(Rec { info_type, ino, name });
        off += len;
    }
    (mask, fd, recs)
}

/// THE ordering test: a rename fires the whole-rename record FIRST, ahead of
/// both halves of the cookie pair, and the record names the source parent and
/// old name then the destination parent and new name.
/// # C: O(1)
#[test]
fn a_rename_reports_both_ends_in_one_record_before_the_moved_pair() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF001;
    let old = dir_on(fsid, 0xF001_0001);
    let new = dir_on(fsid, 0xF001_0002);
    let moved = file_on(fsid, 0xF001_0003);
    let g = group();
    // A filesystem mark watches the rename as a whole, so it hears BOTH ends
    // and also both halves of the legacy pair.
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, fsid,
                          FAN_RENAME | FAN_MOVED_FROM | FAN_MOVED_TO, true, false, 0), 0);
    fire_move(&old, &new, Some(&moved), "before", "after");

    assert_eq!(masks(&g), [FAN_RENAME, FAN_MOVED_FROM, FAN_MOVED_TO],
               "the whole-rename record precedes the cookie pair");
    let (mask, fd, recs) = read_rename_records(&g);
    assert_eq!(mask, FAN_RENAME);
    assert_eq!(fd, FAN_NOFD, "a fid-reporting group is handed no descriptor");
    assert_eq!(recs, [
        Rec { info_type: FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, ino: old.ino(), name: b"before".to_vec() },
        Rec { info_type: FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, ino: new.ino(), name: b"after".to_vec() },
    ]);
    apply_mark(&g, MarkScope::Filesystem, 0, fsid,
               FAN_RENAME | FAN_MOVED_FROM | FAN_MOVED_TO, false, false, 0);
}

/// A mark on the SOURCE directory is told the source half alone: it never
/// watched the destination, and reporting it would leak a directory the watcher
/// has no mark on.
/// # C: O(1)
#[test]
fn a_mark_on_the_source_directory_gets_the_old_half_only() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF002;
    let old = dir_on(fsid, 0xF002_0001);
    let new = dir_on(fsid, 0xF002_0002);
    let g = group();
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&old), fsid, FAN_RENAME, true, false, 0), 0);
    fire_move(&old, &new, None, "src", "dst");
    let (_, _, recs) = read_rename_records(&g);
    assert_eq!(recs, [Rec { info_type: FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
                            ino: old.ino(), name: b"src".to_vec() }]);
}

/// A mark on the DESTINATION directory is told the destination half alone — and
/// that half is reported as the NEW record type, not silently promoted to the
/// old one just because it is the only record present.
/// # C: O(1)
#[test]
fn a_mark_on_the_destination_directory_gets_the_new_half_only() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF003;
    let old = dir_on(fsid, 0xF003_0001);
    let new = dir_on(fsid, 0xF003_0002);
    let g = group();
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&new), fsid, FAN_RENAME, true, false, 0), 0);
    fire_move(&old, &new, None, "src", "dst");
    let (_, _, recs) = read_rename_records(&g);
    assert_eq!(recs, [Rec { info_type: FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
                            ino: new.ino(), name: b"dst".to_vec() }]);
}

/// A rename INSIDE one directory names that directory at both ends, so a mark
/// on it is told both halves — which is how a watcher sees a plain "file was
/// renamed here" as one fact with both names.
/// # C: O(1)
#[test]
fn a_rename_within_one_directory_reports_both_halves_to_that_mark() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF004;
    let dir = dir_on(fsid, 0xF004_0001);
    let g = group();
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&dir), fsid, FAN_RENAME, true, false, 0), 0);
    fire_move(&dir, &dir, None, "a", "b");
    let (_, _, recs) = read_rename_records(&g);
    assert_eq!(recs, [
        Rec { info_type: FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, ino: dir.ino(), name: b"a".to_vec() },
        Rec { info_type: FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, ino: dir.ino(), name: b"b".to_vec() },
    ]);
}

/// A renamed DIRECTORY is reported with `FAN_ONDIR`, and a mark that did not ask
/// for directory events is not told about it at all.
/// # C: O(1)
#[test]
fn a_renamed_directory_needs_ondir_and_is_reported_with_it() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF005;
    let old = dir_on(fsid, 0xF005_0001);
    let new = dir_on(fsid, 0xF005_0002);
    let kid = dir_on(fsid, 0xF005_0003);
    let g = group();
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&old), fsid, FAN_RENAME, true, false, 0), 0);
    fire_move(&old, &new, Some(&kid), "d1", "d2");
    assert!(masks(&g).is_empty(), "a directory rename needs FAN_ONDIR");

    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&old), fsid,
                          FAN_RENAME | FAN_ONDIR, true, false, 0), 0);
    fire_move(&old, &new, Some(&kid), "d1", "d2");
    assert_eq!(masks(&g), [FAN_RENAME | FAN_ONDIR]);
}

/// An inotify group never receives `FAN_RENAME`: its record shape has one wd,
/// one name and no room for a second parent, so a rename reaches it only as the
/// MOVED_FROM/MOVED_TO pair it has always had.
/// # C: O(1)
#[test]
fn an_inotify_group_still_sees_only_the_moved_pair() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF006;
    let old = dir_on(fsid, 0xF006_0001);
    let new = dir_on(fsid, 0xF006_0002);
    let g = InotifyData::new(0);
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&old), fsid,
                          FAN_RENAME | IN_MOVED_FROM, true, false, 0), 0);
    fire_move(&old, &new, None, "a", "b");
    assert_eq!(masks(&g), [IN_MOVED_FROM]);
}

/// The two records are sized from the names they carry, so the event length is
/// exactly the metadata plus both fid records — no padding slack a reader would
/// walk into.
/// # C: O(1)
#[test]
fn the_event_length_is_the_metadata_plus_both_named_records() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF007;
    let old = dir_on(fsid, 0xF007_0001);
    let new = dir_on(fsid, 0xF007_0002);
    let g = group();
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, fsid, FAN_RENAME, true, false, 0), 0);
    fire_move(&old, &new, None, "x", "longer-name");
    let mut buf = [0u8; 512];
    let n = g.read_fanotify(&mut buf).expect("a queued event");
    let want = FAN_EVENT_METADATA_LEN
        + fid_info_len(FANOTIFY_FID_LEN, 1)
        + fid_info_len(FANOTIFY_FID_LEN, "longer-name".len());
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize, want);
    assert_eq!(n, want, "the reader got exactly the event and nothing more");
    apply_mark(&g, MarkScope::Filesystem, 0, fsid, FAN_RENAME, false, false, 0);
}

/// Two renames of DIFFERENT entries stay two records. The merge key includes
/// both names and the destination parent, so folding them would report one
/// rename and lose the other entirely.
/// # C: O(1)
#[test]
fn two_different_renames_stay_two_records() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xF008;
    let old = dir_on(fsid, 0xF008_0001);
    let new = dir_on(fsid, 0xF008_0002);
    let g = group();
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, fsid, FAN_RENAME, true, false, 0), 0);
    fire_move(&old, &new, None, "a", "b");
    fire_move(&old, &new, None, "c", "d");
    assert_eq!(masks(&g), [FAN_RENAME, FAN_RENAME]);
    apply_mark(&g, MarkScope::Filesystem, 0, fsid, FAN_RENAME, false, false, 0);
}

/// `FAN_RENAME` needs `FAN_REPORT_NAME`: both its records carry a name, and a
/// group that never asked for names has nowhere to put them.
/// # C: O(1)
#[test]
fn a_rename_mark_requires_the_name_reporting_mode() {
    let _notify = crate::inotify::test_claim::claim_notify();
    use syscall::errno::Errno;
    let named = InotifyData::new_fanotify(RENAME_MODE);
    assert_eq!(validate_fanotify_mark_group(&named, MarkScope::Inode, FAN_RENAME, 0, true), Ok(()));
    let unnamed = InotifyData::new_fanotify(FAN_REPORT_FID | FAN_REPORT_DIR_FID);
    assert_eq!(validate_fanotify_mark_group(&unnamed, MarkScope::Inode, FAN_RENAME, 0, true),
               Err(Errno::Einval));
}
