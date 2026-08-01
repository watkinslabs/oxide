// fanotify MOUNT-NAMESPACE marks (`FAN_MARK_MNTNS`) and the mount events they
// receive (`FAN_REPORT_MNT` / `FAN_MNT_ATTACH` / `FAN_MNT_DETACH`).
//
// A mount event is unlike every other fanotify record: it names no inode, no
// path and no file handle, so it carries neither a descriptor nor a fid. What
// it does carry is the unique id of the mount that moved, in a
// `FAN_EVENT_INFO_TYPE_MNT` info record.
//
// Deliberately free of any target gate so the record layout, the mark match
// and the dispatch decision are hosted-testable.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::inotify::dispatch::instances;
use crate::inotify::types::{Event, MarkScope, FAN_MNT_EVENTS, MNTNS_MARK_COUNT};

/// `FAN_EVENT_INFO_TYPE_MNT` — the info record naming the mount an event is
/// about.
pub(crate) const FAN_EVENT_INFO_TYPE_MNT: u8 = 7;

/// `sizeof(struct fanotify_event_info_mnt)`: the 4-byte shared
/// `fanotify_event_info_header {info_type u8, pad u8, len u16}` followed by a
/// `__u64 mnt_id`. Already a multiple of the record alignment.
pub(crate) const MNT_INFO_LEN: usize = 4 + 8;

/// Does this reported mask describe a mount-tree change? Such an event takes
/// the mount record path instead of the fid/fd path, and is never merged with
/// anything. # C: O(1)
pub(crate) fn is_mnt_event(mask: u32) -> bool { mask & FAN_MNT_EVENTS != 0 }

/// Encode one `fanotify_event_info_mnt`. Returns the bytes written, or 0 when
/// `dst` cannot hold the whole record (a reader never sees a partial record).
/// # C: O(1)
pub(crate) fn encode_mnt_info(dst: &mut [u8], mnt_id: u64) -> usize {
    if dst.len() < MNT_INFO_LEN { return 0; }
    dst[0] = FAN_EVENT_INFO_TYPE_MNT;
    dst[1] = 0;
    dst[2..4].copy_from_slice(&(MNT_INFO_LEN as u16).to_le_bytes());
    dst[4..12].copy_from_slice(&mnt_id.to_le_bytes());
    MNT_INFO_LEN
}

/// Are any mount-namespace marks live anywhere in the system? The mount-tree
/// choke points consult this first, so a system with no mount watcher pays a
/// single relaxed load per attach/detach/move and touches no group state.
/// # C: O(1)
pub(crate) fn mntns_marks_present() -> bool {
    MNTNS_MARK_COUNT.load(Ordering::Acquire) != 0
}

/// The mount-notification hook body: report one mount-tree change to every
/// group holding a mount-namespace mark on `ns_id`.
///
/// A mount event reaches a group ONLY through a mark on the namespace the
/// change happened in. There is no parent leg, no child gate and no directory
/// gate — none of those concepts apply to an object with no inode — so the
/// only filter is the mark's own event mask.
/// # C: O(N_groups × N_watches)
pub(crate) fn fire_mnt(ns_id: u64, mnt_id: u64, mask: u32) {
    if !mntns_marks_present() { return; }
    let g = instances().lock();
    for w in g.iter() {
        let Some(arc) = w.upgrade() else { continue };
        let pid = crate::inotify::perm::reporting_pid(&arc);
        let hits: Vec<(i32, u32)> = {
            let watches = arc.watches.lock();
            watches.iter()
                .filter(|wi| wi.scope == MarkScope::MountNamespace && wi.ns_id == ns_id)
                .filter_map(|wi| mnt_report_mask(wi.mask, wi.ignored, mask).map(|m| (wi.wd, m)))
                .collect()
        };
        for (wd, report) in hits {
            arc.enqueue_event(Event { wd, mask: report, cookie: 0, name: Vec::new(),
                                      obj: None, pid, perm: None, mnt_id });
        }
    }
}

/// What a mark reports for one mount-tree change, or `None` when it reports
/// nothing.
///
/// A relocation inside a namespace sets BOTH mount bits, and a mark that asked
/// for only one of them still hears about it — under the bit it asked for, not
/// under the bit it did not. A mark that asked for both is told it was a move,
/// which is exactly the information the two-bit record carries.
/// # C: O(1)
pub(crate) fn mnt_report_mask(mark_mask: u32, ignored: u32, event: u32) -> Option<u32> {
    let want = event & FAN_MNT_EVENTS & mark_mask & !ignored;
    if want == 0 { None } else { Some(want) }
}

/// Install the mount-tree notification hook into vfs. Called once at
/// kernel_main alongside the inode hooks. # C: O(1)
pub(crate) fn install_mnt_hook() { vfs::mount::set_mnt_notify_hook(fire_mnt); }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inotify::types::{FAN_MNT_ATTACH, FAN_MNT_DETACH};

    #[test]
    fn the_record_is_a_header_plus_a_64_bit_mount_id() {
        let mut buf = [0xAAu8; 16];
        assert_eq!(encode_mnt_info(&mut buf, 0x1234_5678_9abc_def0), MNT_INFO_LEN);
        assert_eq!(buf[0], FAN_EVENT_INFO_TYPE_MNT);
        assert_eq!(buf[1], 0, "pad byte is zero");
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), MNT_INFO_LEN as u16);
        assert_eq!(u64::from_le_bytes(buf[4..12].try_into().unwrap()), 0x1234_5678_9abc_def0);
        assert_eq!(buf[12], 0xAA, "nothing written past the record");
        assert_eq!(MNT_INFO_LEN % 4, 0, "record needs no trailing alignment padding");
    }

    #[test]
    fn encode_refuses_to_write_a_partial_record() {
        let mut buf = [0xAAu8; 11];
        assert_eq!(encode_mnt_info(&mut buf, 1), 0);
        assert_eq!(buf, [0xAAu8; 11], "nothing written");
    }

    #[test]
    fn only_the_mount_bits_make_a_mount_event() {
        assert!(is_mnt_event(FAN_MNT_ATTACH));
        assert!(is_mnt_event(FAN_MNT_DETACH));
        assert!(!is_mnt_event(crate::inotify::types::FAN_OPEN));
        assert!(!is_mnt_event(0));
    }

    /// A mark hears about a relocation under the bit it subscribed to; a mark
    /// that subscribed to both is told the change was a move.
    /// # C: O(1)
    #[test]
    fn a_move_reports_under_whichever_bits_the_mark_asked_for() {
        let move_ev = FAN_MNT_ATTACH | FAN_MNT_DETACH;
        assert_eq!(mnt_report_mask(FAN_MNT_ATTACH, 0, move_ev), Some(FAN_MNT_ATTACH));
        assert_eq!(mnt_report_mask(FAN_MNT_DETACH, 0, move_ev), Some(FAN_MNT_DETACH));
        assert_eq!(mnt_report_mask(move_ev, 0, move_ev), Some(move_ev));
    }

    #[test]
    fn an_unsubscribed_or_ignored_change_reports_nothing() {
        assert_eq!(mnt_report_mask(FAN_MNT_ATTACH, 0, FAN_MNT_DETACH), None);
        assert_eq!(mnt_report_mask(FAN_MNT_ATTACH, FAN_MNT_ATTACH, FAN_MNT_ATTACH), None);
        assert_eq!(mnt_report_mask(0, 0, FAN_MNT_ATTACH), None);
    }

    /// The vfs-side bit values and the fanotify-side ones are the same
    /// numbers: the hook passes the mask straight through, and a mismatch
    /// would silently report every attach as a detach.
    /// # C: O(1)
    #[test]
    fn the_vfs_transition_bits_are_the_uapi_event_bits() {
        assert_eq!(vfs::mount::FS_MNT_ATTACH, FAN_MNT_ATTACH);
        assert_eq!(vfs::mount::FS_MNT_DETACH, FAN_MNT_DETACH);
        assert_eq!(vfs::mount::FS_MNT_MOVE, FAN_MNT_ATTACH | FAN_MNT_DETACH);
    }
}
