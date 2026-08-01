// Notification-queue ADMISSION rules — `fsnotify_add_event` plus each group
// kind's `merge` callback (inotify's `inotify_merge`, fanotify's
// `fanotify_merge`/`fanotify_should_merge`).
//
// Deliberately free of any target gate so the admission decision is
// hosted-testable; `group::enqueue_event` only sequences these helpers.

use crate::inotify::types::{Event, FAN_ONDIR, FAN_RENAME, IN_IGNORED, IN_Q_OVERFLOW, PERM_BITS};

/// How far back from the queue tail a fanotify insert looks for an event to
/// fold into. Linux bounds the same search by hashing the event and scanning at
/// most this many entries of the matching bucket; the bound, not the hash, is
/// what userspace can observe.
pub(crate) const FANOTIFY_MAX_MERGE_EVENTS: usize = 128;

/// Linux `event_compare` under `inotify_merge`: a new event is FOLDED INTO the
/// queue TAIL (dropped, since the tail already carries the same information)
/// when the two records are indistinguishable to a reader.
///
/// Exactly Linux's predicate, including its two surprises:
///   - an `IN_IGNORED` tail never absorbs anything (`old->mask & FS_IN_IGNORED`
///     short-circuits), so a watch's death record stays the last word on it;
///   - the rename `cookie` is NOT part of the comparison, so two moves that
///     agree on mask/wd/name collapse even with distinct cookies.
/// Only the TAIL is examined — Linux compares against `list->prev` alone, not
/// the whole queue.
/// # C: O(name_len)
pub(crate) fn merges_into_tail(tail: &Event, ev: &Event) -> bool {
    if tail.mask & IN_IGNORED != 0 { return false; }
    tail.mask == ev.mask && tail.wd == ev.wd && tail.name == ev.name
}

/// An event that is never hashed and therefore never merged with anything:
/// a permission event (the accessor blocked on it must be able to name the one
/// record it is waiting for) and the overflow marker.
/// # C: O(1)
pub(crate) fn is_mergeable_event(ev: &Event) -> bool {
    ev.perm.is_none() && (ev.mask & (PERM_BITS | IN_Q_OVERFLOW)) == 0
}

/// fanotify's `fanotify_should_merge`. An already-queued event absorbs a new
/// one — the reader sees a single record with the two masks OR-ed — when they
/// describe the same access to the same object by the same process.
///
/// Three of the four legs exist to keep distinguishable things distinguishable:
///   - the reporting process (`pid`) is part of the record, so two processes'
///     accesses never collapse into one;
///   - `FAN_ONDIR` must agree, or a `mkdir`+`unlink` pair and an
///     `rmdir`+`creat` pair would both read back as
///     `FAN_CREATE|FAN_DELETE|FAN_ONDIR` and become indistinguishable;
///   - `FAN_RENAME` must agree, because a rename is reported through info
///     records the other event types do not carry.
/// The fourth is object identity: the affected object plus, for a named event,
/// the directory entry it names.
/// # C: O(name_len)
pub(crate) fn fanotify_should_merge(old: &Event, new: &Event) -> bool {
    if !is_mergeable_event(old) || !is_mergeable_event(new) { return false; }
    if old.pid != new.pid { return false; }
    if (old.mask & FAN_ONDIR) != (new.mask & FAN_ONDIR) { return false; }
    if (old.mask & FAN_RENAME) != (new.mask & FAN_RENAME) { return false; }
    if old.name != new.name { return false; }
    same_object(old, new)
}

/// `fanotify_path_equal` / `fanotify_fid_event_equal`: two records name the
/// same object. Both sides carrying no object at all (an overflow-shaped
/// record) is NOT a match — such records are unmergeable anyway, and treating
/// "no object" as an identity would let two unrelated ones collapse.
/// # C: O(1)
fn same_object(old: &Event, new: &Event) -> bool {
    match (&old.obj, &new.obj) {
        (Some(a), Some(b)) => alloc::sync::Arc::ptr_eq(a, b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inotify::types::{FAN_ACCESS, FAN_CREATE, FAN_DELETE, FAN_MODIFY, FAN_OPEN, FAN_OPEN_PERM};
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    fn obj(ino: u64) -> vfs::InodeRef {
        vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Regular, 0o644),
            vfs::default_inode_ops(), vfs::default_file_ops()).build()
    }

    fn ev(mask: u32, pid: u32, o: Option<vfs::InodeRef>, name: &[u8]) -> Event {
        Event { wd: 1, mask, cookie: 0, name: name.to_vec(), obj: o, pid, perm: None }
    }

    #[test]
    fn identical_accesses_by_one_process_merge() {
        let o = obj(10);
        assert!(fanotify_should_merge(&ev(FAN_ACCESS, 7, Some(o.clone()), b""),
                                      &ev(FAN_MODIFY, 7, Some(o), b"")));
    }

    /// The record carries the acting pid, so two processes touching the same
    /// file must stay two records. # C: O(1)
    #[test]
    fn different_processes_never_merge() {
        let o = obj(10);
        assert!(!fanotify_should_merge(&ev(FAN_ACCESS, 7, Some(o.clone()), b""),
                                       &ev(FAN_ACCESS, 8, Some(o), b"")));
    }

    #[test]
    fn different_objects_never_merge() {
        assert!(!fanotify_should_merge(&ev(FAN_OPEN, 7, Some(obj(10)), b""),
                                       &ev(FAN_OPEN, 7, Some(obj(11)), b"")));
    }

    /// A dirent event names the entry it happened to; two different entries in
    /// one directory are two records. # C: O(1)
    #[test]
    fn different_entry_names_never_merge() {
        let d = obj(2);
        assert!(!fanotify_should_merge(&ev(FAN_CREATE, 7, Some(d.clone()), b"a"),
                                       &ev(FAN_CREATE, 7, Some(d), b"b")));
    }

    /// Without the ONDIR leg an `mkdir`+`unlink` pair and an `rmdir`+`creat`
    /// pair both read back as CREATE|DELETE|ONDIR and become indistinguishable.
    /// # C: O(1)
    #[test]
    fn a_directory_event_never_merges_with_a_file_event() {
        let d = obj(2);
        let mkdir = ev(FAN_CREATE | FAN_ONDIR, 7, Some(d.clone()), b"x");
        let unlink = ev(FAN_DELETE, 7, Some(d.clone()), b"x");
        assert!(!fanotify_should_merge(&mkdir, &unlink));
        assert!(fanotify_should_merge(&unlink, &ev(FAN_CREATE, 7, Some(d), b"x")),
                "two non-directory dirent events on the same entry still merge");
    }

    #[test]
    fn a_rename_never_merges_with_a_non_rename() {
        let d = obj(2);
        assert!(!fanotify_should_merge(&ev(FAN_RENAME, 7, Some(d.clone()), b"x"),
                                       &ev(FAN_CREATE, 7, Some(d), b"x")));
    }

    /// A permission event is the one record its blocked accessor is waiting
    /// for, so it can never be folded into another. # C: O(1)
    #[test]
    fn permission_events_are_never_merged() {
        let o = obj(10);
        let mut perm = ev(FAN_OPEN_PERM, 7, Some(o.clone()), b"");
        perm.perm = Some(Arc::new(crate::inotify::types::PermState::new()));
        assert!(!is_mergeable_event(&perm));
        assert!(!fanotify_should_merge(&perm, &ev(FAN_OPEN, 7, Some(o.clone()), b"")));
        assert!(!fanotify_should_merge(&ev(FAN_OPEN, 7, Some(o.clone()), b""), &perm));
        // ... and neither does a perm-masked record that lost its state.
        assert!(!is_mergeable_event(&ev(FAN_OPEN_PERM, 7, Some(o), b"")));
    }

    /// The overflow marker is never hashed, so it neither absorbs nor is
    /// absorbed. # C: O(1)
    #[test]
    fn the_overflow_marker_is_never_merged() {
        let ov = Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: Vec::new(), obj: None, pid: 0, perm: None };
        assert!(!is_mergeable_event(&ov));
        assert!(!fanotify_should_merge(&ov, &ov));
    }

    /// inotify's tail rule is unchanged by the fanotify one. # C: O(1)
    #[test]
    fn inotify_tail_merge_still_ignores_the_cookie_and_never_absorbs_ignored() {
        let a = Event { wd: 3, mask: FAN_ACCESS, cookie: 1, name: b"n".to_vec(), obj: None, pid: 0, perm: None };
        let b = Event { wd: 3, mask: FAN_ACCESS, cookie: 99, name: b"n".to_vec(), obj: None, pid: 0, perm: None };
        assert!(merges_into_tail(&a, &b));
        let ign = Event { wd: 3, mask: IN_IGNORED, cookie: 0, name: Vec::new(), obj: None, pid: 0, perm: None };
        assert!(!merges_into_tail(&ign, &ign));
    }
}
