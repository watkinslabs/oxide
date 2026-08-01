// `FAN_FS_ERROR` hosted tests. The notification is driven through the VFS
// filesystem-error hook — the same call a filesystem makes when it discovers
// its own state is wrong — after the production hook installer has run, so the
// installed subscriber, the mark match, the queue admission, the merge rule and
// the wire encoding all execute. Nothing here calls the fire function by name.
//
// Included as a child module of `inotify` via `#[path]`, so `use super::*`
// reaches the module-private mark/dispatch items.

use super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::inotify::fan_err::{ERROR_INFO_LEN, FAN_EVENT_INFO_TYPE_ERROR};
use crate::inotify::fan_layout::{FAN_EVENT_INFO_TYPE_FID, FAN_EVENT_METADATA_LEN, FAN_NOFD};
use crate::inotify::syscalls::apply_mark;
use crate::inotify::validate::FAN_REPORT_FID;
use vfs::{default_inode_ops, mk_mode, FileType, InodeBuilder};

/// The errno a corrupt filesystem surfaces as, and the number the record
/// carries — POSITIVE, as userspace reads it.
const REPORTED_ERRNO: i32 = vfs::VfsError::Eio as i32;

/// One decoded error record: the descriptor and filesystem the event names,
/// plus the errno and the number of errors the record stands for.
#[derive(Debug, PartialEq, Eq)]
struct ErrRecord { fd: i32, fsid: u64, error: i32, count: u32 }

/// Run the PRODUCTION hook installer exactly once. It takes a close-hook slot
/// out of a fixed table, so calling it per test exhausts the table — which is
/// not a property of the notification path, just of a test that installs boot
/// wiring repeatedly. # C: O(1)
fn install_hooks_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(crate::inotify::install_write_hook);
}

fn inode_on(fsid: u64, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), Arc::new(InotifyFileOps))
        .fsid(fsid).build()
}

/// A `FAN_REPORT_FID` group with a filesystem-scope mark on `fsid`. Fid mode is
/// not optional: an error names no path, so a group with no fid mode could not
/// be told which object failed and `fanotify_mark` refuses the combination.
/// # C: O(1)
fn err_group(fsid: u64) -> Arc<InotifyData> {
    install_hooks_once();
    let g = InotifyData::new_fanotify(FAN_REPORT_FID);
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, fsid, FAN_FS_ERROR, true, false, 0), 0);
    g
}

/// Retire a filesystem mark so the process-wide mark count returns to where it
/// started. # C: O(N_watches)
fn drop_mark(g: &Arc<InotifyData>, fsid: u64, mask: u32) {
    apply_mark(g, MarkScope::Filesystem, 0, fsid, mask, false, false, 0);
}

/// Drain the group and decode each record as metadata + one fid record + one
/// error record. # C: O(records)
fn read_err_records(g: &InotifyData) -> Vec<ErrRecord> {
    let mut buf = [0u8; 1024];
    let Ok(n) = g.read_fanotify(&mut buf) else { return Vec::new() };
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < n {
        let ev_len = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let mask = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap()) as u32;
        assert_eq!(mask, FAN_FS_ERROR, "the record reports the error bit and nothing else");
        let fd = i32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap());
        // The fid record comes first; the error record is the LAST thing in the
        // event, so it starts where the event ends minus its own length.
        let fid = off + FAN_EVENT_METADATA_LEN;
        assert_eq!(buf[fid], FAN_EVENT_INFO_TYPE_FID);
        let fsid = u32::from_le_bytes(buf[fid + 4..fid + 8].try_into().unwrap()) as u64
            | ((u32::from_le_bytes(buf[fid + 8..fid + 12].try_into().unwrap()) as u64) << 32);
        let e = off + ev_len - ERROR_INFO_LEN;
        assert_eq!(buf[e], FAN_EVENT_INFO_TYPE_ERROR);
        assert_eq!(buf[e + 1], 0, "pad byte is zero");
        assert_eq!(u16::from_le_bytes([buf[e + 2], buf[e + 3]]), ERROR_INFO_LEN as u16);
        out.push(ErrRecord {
            fd, fsid,
            error: i32::from_le_bytes(buf[e + 4..e + 8].try_into().unwrap()),
            count: u32::from_le_bytes(buf[e + 8..e + 12].try_into().unwrap()),
        });
        off += ev_len;
    }
    out
}

/// THE hook test: a filesystem reporting an error through the VFS hook reaches
/// a filesystem-scope mark, and the record carries the errno, a count of one,
/// the filesystem's identity — and NO descriptor, because a filesystem error
/// names no file to open.
/// # C: O(1)
#[test]
fn a_reported_filesystem_error_reaches_a_filesystem_mark() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xE001;
    let g = err_group(fsid);
    let ino = inode_on(fsid, 0xE001_0001);
    vfs::fire_fs_error(fsid, Some(&ino), REPORTED_ERRNO);
    assert_eq!(read_err_records(&g),
               [ErrRecord { fd: FAN_NOFD, fsid, error: REPORTED_ERRNO, count: 1 }]);
    drop_mark(&g, fsid, FAN_FS_ERROR);
}

/// A filesystem too damaged to name an inode still reports. Its file handle is
/// zeroed and the fsid comes off the record itself, so the watcher is still
/// told WHICH filesystem failed.
/// # C: O(1)
#[test]
fn an_error_with_no_inode_still_names_the_filesystem() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xE002;
    let g = err_group(fsid);
    vfs::fire_fs_error(fsid, None, REPORTED_ERRNO);
    assert_eq!(read_err_records(&g),
               [ErrRecord { fd: FAN_NOFD, fsid, error: REPORTED_ERRNO, count: 1 }]);
    drop_mark(&g, fsid, FAN_FS_ERROR);
}

/// Errors on ONE filesystem always fold into one record with a rising count,
/// whichever inodes they were discovered on — a failing filesystem produces
/// them faster than any daemon drains them, and the queue must not fill.
/// # C: O(1)
#[test]
fn repeated_errors_on_one_filesystem_fold_into_one_counted_record() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xE003;
    let g = err_group(fsid);
    let a = inode_on(fsid, 0xE003_0001);
    let b = inode_on(fsid, 0xE003_0002);
    vfs::fire_fs_error(fsid, Some(&a), REPORTED_ERRNO);
    vfs::fire_fs_error(fsid, Some(&b), REPORTED_ERRNO);
    vfs::fire_fs_error(fsid, None, REPORTED_ERRNO);
    assert_eq!(read_err_records(&g),
               [ErrRecord { fd: FAN_NOFD, fsid, error: REPORTED_ERRNO, count: 3 }],
               "three errors, one record, count three");
    drop_mark(&g, fsid, FAN_FS_ERROR);
}

/// Two filesystems are two facts. The merge is keyed on filesystem identity, so
/// a failure on one is never reported as a failure on the other.
/// # C: O(1)
#[test]
fn errors_on_different_filesystems_stay_separate_records() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let (one, two) = (0xE004, 0xE005);
    let g = err_group(one);
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, two, FAN_FS_ERROR, true, false, 0), 0);
    vfs::fire_fs_error(one, None, REPORTED_ERRNO);
    vfs::fire_fs_error(two, None, REPORTED_ERRNO);
    let recs = read_err_records(&g);
    assert_eq!(recs.len(), 2, "one record per filesystem");
    assert_eq!(recs[0].fsid, one);
    assert_eq!(recs[1].fsid, two);
    assert!(recs.iter().all(|r| r.count == 1));
    drop_mark(&g, one, FAN_FS_ERROR);
    drop_mark(&g, two, FAN_FS_ERROR);
}

/// A mark on a DIFFERENT filesystem hears nothing, and a mark that did not ask
/// for errors hears nothing either.
/// # C: O(1)
#[test]
fn an_unrelated_or_unsubscribed_mark_hears_nothing() {
    let _notify = crate::inotify::test_claim::claim_notify();
    install_hooks_once();
    let g = InotifyData::new_fanotify(FAN_REPORT_FID);
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, 0xE006, FAN_FS_ERROR, true, false, 0), 0);
    assert_eq!(apply_mark(&g, MarkScope::Filesystem, 0, 0xE007, FAN_MODIFY, true, false, 0), 0);
    vfs::fire_fs_error(0xE008, None, REPORTED_ERRNO);   // no mark at all
    vfs::fire_fs_error(0xE007, None, REPORTED_ERRNO);   // mark, wrong mask
    assert!(read_err_records(&g).is_empty());
    drop_mark(&g, 0xE006, FAN_FS_ERROR);
    drop_mark(&g, 0xE007, FAN_MODIFY);
}

/// The event is metadata, then the fid record naming the filesystem, then the
/// error record — nothing between them and nothing after.
/// # C: O(1)
#[test]
fn the_error_record_is_the_last_record_of_the_event() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let fsid = 0xE009;
    let g = err_group(fsid);
    vfs::fire_fs_error(fsid, None, REPORTED_ERRNO);
    let mut buf = [0u8; 256];
    let n = g.read_fanotify(&mut buf).expect("one record");
    let ev_len = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    assert_eq!(ev_len, n, "the event fills exactly what was written");
    let fid = FAN_EVENT_METADATA_LEN;
    let fid_len = ev_len - FAN_EVENT_METADATA_LEN - ERROR_INFO_LEN;
    assert_eq!(buf[fid], FAN_EVENT_INFO_TYPE_FID);
    assert_eq!(u16::from_le_bytes([buf[fid + 2], buf[fid + 3]]), fid_len as u16,
               "the fid record fills the whole span between metadata and the error record");
    drop_mark(&g, fsid, FAN_FS_ERROR);
}

/// `FAN_FS_ERROR` is a filesystem-scope mask, and needs a fid-reporting group:
/// the dispatch above cannot be reached any other way.
/// # C: O(1)
#[test]
fn only_a_fid_reporting_filesystem_mark_may_ask_for_errors() {
    let _notify = crate::inotify::test_claim::claim_notify();
    use syscall::errno::Errno;
    let g = InotifyData::new_fanotify(FAN_REPORT_FID);
    assert_eq!(validate_fanotify_mark_group(&g, MarkScope::Inode, FAN_FS_ERROR, 0, true),
               Err(Errno::Einval));
    assert_eq!(validate_fanotify_mark_group(&g, MarkScope::Mount, FAN_FS_ERROR, 0, true),
               Err(Errno::Einval));
    assert_eq!(validate_fanotify_mark_group(&g, MarkScope::Filesystem, FAN_FS_ERROR, 0, true),
               Ok(()));
    let plain = InotifyData::new_fanotify(0);
    assert_eq!(validate_fanotify_mark_group(&plain, MarkScope::Filesystem, FAN_FS_ERROR, 0, true),
               Err(Errno::Einval));
}
