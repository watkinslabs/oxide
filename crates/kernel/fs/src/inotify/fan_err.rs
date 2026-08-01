// fanotify FILESYSTEM-ERROR events (`FAN_FS_ERROR`) and the
// `FAN_EVENT_INFO_TYPE_ERROR` info record that carries one.
//
// An error record is about a FILESYSTEM, not about a process and often not even
// about an inode: a corrupt extent tree or a failed metadata read is discovered
// while walking structures that may name nothing the caller asked for. Three
// consequences run through this module:
//   * only a filesystem-scope mark can receive one (`validate`);
//   * the record reports no descriptor, and its file handle is zeroed when no
//     inode could be named;
//   * two errors on one filesystem ALWAYS fold together, with a count, instead
//     of queueing separately — a filesystem that has started failing produces
//     errors faster than any daemon drains them.
//
// Deliberately free of any target gate so the record layout, the dispatch
// decision and the merge rule are hosted-testable.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::InodeRef;

use crate::inotify::dispatch::instances;
use crate::inotify::types::{Event, MarkScope, FAN_FS_ERROR, MARK_COUNT};

/// `FAN_EVENT_INFO_TYPE_ERROR` — the info record naming the error and how many
/// errors it stands for.
pub(crate) const FAN_EVENT_INFO_TYPE_ERROR: u8 = 5;

/// `sizeof(struct fanotify_event_info_error)`: the 4-byte shared
/// `fanotify_event_info_header {info_type u8, pad u8, len u16}`, then
/// `__s32 error` and `__u32 error_count`. Already a multiple of the record
/// alignment.
pub(crate) const ERROR_INFO_LEN: usize = 4 + 4 + 4;

/// The count a freshly reported error record starts at. Every fold into it adds
/// one, so the value userspace reads is the number of errors the record stands
/// for and never zero.
pub(crate) const ERR_COUNT_FIRST: u32 = 1;

/// A record about a filesystem is attributable to no process — the failure is
/// the device's or the image's, and the task that happened to touch it first is
/// not the cause. Reporting a fixed id is also what lets two errors on one
/// filesystem fold together at all, since the acting process is part of every
/// other family's merge key.
pub(crate) const FS_ERROR_PID: u32 = 0;

/// Does this reported mask describe a filesystem error? Such an event takes the
/// error-record path and merges on filesystem identity alone. # C: O(1)
pub(crate) fn is_error_event(mask: u32) -> bool { mask & FAN_FS_ERROR != 0 }

/// Encode one `fanotify_event_info_error`. Returns the bytes written, or 0 when
/// `dst` cannot hold the whole record (a reader never sees a partial record).
/// # C: O(1)
pub(crate) fn encode_error_info(dst: &mut [u8], error: i32, err_count: u32) -> usize {
    if dst.len() < ERROR_INFO_LEN { return 0; }
    dst[0] = FAN_EVENT_INFO_TYPE_ERROR;
    dst[1] = 0;
    dst[2..4].copy_from_slice(&(ERROR_INFO_LEN as u16).to_le_bytes());
    dst[4..8].copy_from_slice(&error.to_le_bytes());
    dst[8..12].copy_from_slice(&err_count.to_le_bytes());
    ERROR_INFO_LEN
}

/// The filesystem-error notification hook body: report one error on the
/// filesystem `fsid` to every group holding a filesystem-scope mark on it.
///
/// There is no parent leg, no child gate and no directory gate: the object is a
/// filesystem, and none of those concepts apply to one. `inode` is the inode the
/// failure was discovered on when there is one; a record with none still
/// reports, with a zeroed file handle, because the fact that the filesystem
/// failed is the information the watcher asked for.
/// # C: O(N_groups × N_watches)
pub(crate) fn fire_fs_error(fsid: u64, inode: Option<&InodeRef>, error: i32) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let g = instances().lock();
    for w in g.iter() {
        let Some(arc) = w.upgrade() else { continue };
        if !arc.fanotify { continue; }
        let hits: Vec<i32> = {
            let watches = arc.watches.lock();
            watches.iter()
                .filter(|wi| wi.scope == MarkScope::Filesystem && wi.fsid == fsid)
                .filter(|wi| error_reported(wi.mask, wi.ignored))
                .map(|wi| wi.wd)
                .collect()
        };
        for wd in hits {
            arc.enqueue_event(Event {
                wd, mask: FAN_FS_ERROR, pid: FS_ERROR_PID,
                obj: inode.cloned(), fsid, error, err_count: ERR_COUNT_FIRST,
                ..Default::default()
            });
        }
    }
}

/// Does this mark report filesystem errors? The only filter an error event
/// passes through: the mark asked for the bit and did not ignore it.
/// # C: O(1)
pub(crate) fn error_reported(mark_mask: u32, ignored: u32) -> bool {
    mark_mask & FAN_FS_ERROR != 0 && ignored & FAN_FS_ERROR == 0
}

/// Install the filesystem-error notification hook into vfs. Called once at
/// kernel_main alongside the inode hooks. # C: O(1)
pub(crate) fn install_fs_error_hook() { vfs::set_fs_error_hook(fire_fs_error); }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inotify::types::FAN_MODIFY;

    #[test]
    fn the_record_is_a_header_an_errno_and_a_count() {
        let mut buf = [0xAAu8; 16];
        assert_eq!(encode_error_info(&mut buf, 117, 42), ERROR_INFO_LEN);
        assert_eq!(buf[0], FAN_EVENT_INFO_TYPE_ERROR);
        assert_eq!(buf[1], 0, "pad byte is zero");
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), ERROR_INFO_LEN as u16);
        assert_eq!(i32::from_le_bytes(buf[4..8].try_into().unwrap()), 117);
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 42);
        assert_eq!(buf[12], 0xAA, "nothing written past the record");
        assert_eq!(ERROR_INFO_LEN % 4, 0, "record needs no trailing alignment padding");
    }

    #[test]
    fn encode_refuses_to_write_a_partial_record() {
        let mut buf = [0xAAu8; 11];
        assert_eq!(encode_error_info(&mut buf, 5, 1), 0);
        assert_eq!(buf, [0xAAu8; 11], "nothing written");
    }

    #[test]
    fn only_the_error_bit_makes_an_error_event() {
        assert!(is_error_event(FAN_FS_ERROR));
        assert!(!is_error_event(FAN_MODIFY));
        assert!(!is_error_event(0));
    }

    #[test]
    fn a_mark_that_did_not_ask_for_errors_or_ignored_them_reports_nothing() {
        assert!(error_reported(FAN_FS_ERROR, 0));
        assert!(!error_reported(FAN_MODIFY, 0));
        assert!(!error_reported(FAN_FS_ERROR, FAN_FS_ERROR));
    }
}
