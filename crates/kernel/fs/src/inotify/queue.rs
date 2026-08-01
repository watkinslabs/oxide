// Notification-queue ADMISSION rules — `fsnotify_add_event` plus each group
// kind's `merge` callback (inotify's `inotify_merge`, fanotify's
// `fanotify_merge`/`fanotify_should_merge`).
//
// Deliberately free of any target gate so the admission decision is
// hosted-testable; `group::enqueue_event` only sequences these helpers.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::inotify::types::{Event, FAN_ONDIR, FAN_RENAME, IN_IGNORED, IN_Q_OVERFLOW, PERM_BITS};

/// How many entries of the matching bucket a fanotify insert examines before
/// giving up, so one event's merge search costs a bounded amount of CPU
/// whatever the queue depth.
pub(crate) const FANOTIFY_MAX_MERGE_EVENTS: usize = 128;

/// Buckets a group hashes its queued events into. The bucket count is not
/// observable; what IS observable is that two mergeable events find each other
/// no matter how many unrelated records were queued between them.
const FANOTIFY_HTABLE_SIZE: usize = 128;

/// Bucket for one event: the identity of the object it happened to, which is
/// the one thing every leg of `fanotify_should_merge` requires to be equal.
/// The name, the pid and the event flags are NOT hashed — they filter
/// candidates inside the bucket, exactly as the mask does.
/// # C: O(1)
fn hash_bucket(ev: &Event) -> usize {
    // An error record's identity is its FILESYSTEM, so two errors on one
    // filesystem must land in the same bucket however different the inodes they
    // were found on — otherwise the merge rule that folds them can never find
    // the record to fold into.
    let id = if crate::inotify::fan_err::is_error_event(ev.mask) { ev.fsid }
             else { match &ev.obj { Some(o) => alloc::sync::Arc::as_ptr(o) as usize as u64, None => 0 } };
    // Fibonacci hashing: multiply by 2^64/phi and keep the high bits, so the
    // low-entropy alignment bits of a heap pointer do not all land in one
    // bucket.
    let mixed = id.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32;
    (mixed as usize) & (FANOTIFY_HTABLE_SIZE - 1)
}

/// One group's notification queue: the records in arrival order, plus the
/// merge index over them.
///
/// The index is what makes the merge search Linux's bounded HASHED scan rather
/// than a walk back from the tail. A daemon that is behind by hundreds of
/// events still gets its repeated access folded into the record already
/// describing it — with a backward scan, the same access reaches userspace
/// twice as soon as the queue is deeper than the scan bound.
///
/// Buckets hold arrival SEQUENCE numbers, not indices: a pop from the front
/// shifts every index but no sequence number, so the index survives draining
/// without a rewrite.
pub(crate) struct EventQueue {
    q: VecDeque<Event>,
    /// Per-bucket sequence numbers, most recently queued FIRST.
    buckets: Vec<VecDeque<u64>>,
    /// Sequence number of `q.front()`.
    head_seq: u64,
}

impl EventQueue {
    /// # C: O(FANOTIFY_HTABLE_SIZE)
    pub(crate) fn new() -> Self {
        let mut buckets = Vec::with_capacity(FANOTIFY_HTABLE_SIZE);
        for _ in 0..FANOTIFY_HTABLE_SIZE { buckets.push(VecDeque::new()); }
        Self { q: VecDeque::new(), buckets, head_seq: 0 }
    }

    /// # C: O(1)
    pub(crate) fn len(&self) -> usize { self.q.len() }
    /// # C: O(1)
    pub(crate) fn is_empty(&self) -> bool { self.q.is_empty() }
    /// # C: O(1)
    pub(crate) fn front(&self) -> Option<&Event> { self.q.front() }
    /// # C: O(1)
    pub(crate) fn back(&self) -> Option<&Event> { self.q.back() }
    /// # C: O(N)
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Event> { self.q.iter() }

    /// Queue `ev` as its own record and index it for later merges. An event
    /// that is never merged (a permission event, the overflow marker) is queued
    /// but not indexed, so it neither absorbs nor is absorbed.
    /// # C: O(1)
    pub(crate) fn push(&mut self, ev: Event) {
        let seq = self.head_seq + self.q.len() as u64;
        if is_mergeable_event(&ev) { self.buckets[hash_bucket(&ev)].push_front(seq); }
        self.q.push_back(ev);
    }

    /// Deliver the oldest record and drop it from the merge index.
    /// # C: O(bucket)
    pub(crate) fn pop_front(&mut self) -> Option<Event> {
        let ev = self.q.pop_front()?;
        let seq = self.head_seq;
        self.head_seq += 1;
        if is_mergeable_event(&ev) {
            let b = hash_bucket(&ev);
            self.buckets[b].retain(|s| *s != seq);
        }
        Some(ev)
    }

    /// # C: O(N + FANOTIFY_HTABLE_SIZE)
    pub(crate) fn clear(&mut self) {
        self.head_seq += self.q.len() as u64;
        self.q.clear();
        for b in self.buckets.iter_mut() { b.clear(); }
    }

    /// fanotify's merge callback: fold `ev` into an indexed record describing
    /// the same access, examining at most `FANOTIFY_MAX_MERGE_EVENTS` entries
    /// of its bucket, newest first. `true` when it was folded in and must not
    /// be queued again.
    /// # C: O(FANOTIFY_MAX_MERGE_EVENTS * name_len)
    pub(crate) fn merge_fanotify(&mut self, ev: &Event) -> bool {
        if !is_mergeable_event(ev) { return false; }
        let bucket = hash_bucket(ev);
        let mut hit = None;
        for seq in self.buckets[bucket].iter().take(FANOTIFY_MAX_MERGE_EVENTS) {
            let idx = (seq - self.head_seq) as usize;
            let Some(old) = self.q.get(idx) else { continue };
            if fanotify_should_merge(old, ev) { hit = Some(idx); break; }
        }
        let Some(idx) = hit else { return false };
        if let Some(old) = self.q.get_mut(idx) {
            old.mask |= ev.mask;
            // The record an error was folded into stands for one more error
            // than it did. The count is the only thing distinguishing "the
            // filesystem hiccuped once" from "the filesystem is disintegrating",
            // since the folded records themselves are gone.
            if crate::inotify::fan_err::is_error_event(old.mask) { old.err_count += 1; }
        }
        true
    }
}

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
/// record it is waiting for), the overflow marker, and a mount-tree change.
///
/// A mount event is unmergeable because each one names a DIFFERENT mount in its
/// own info record, and a merge keeps only one record while OR-ing the masks —
/// two attaches folded together would report one mount and lose the other
/// entirely. Two changes to the SAME mount stay separate for the same reason:
/// an attach and a later detach of one mount are two facts, not one mount that
/// is somehow both.
/// # C: O(1)
pub(crate) fn is_mergeable_event(ev: &Event) -> bool {
    ev.perm.is_none()
        && (ev.mask & (PERM_BITS | IN_Q_OVERFLOW)) == 0
        && !crate::inotify::fan_mnt::is_mnt_event(ev.mask)
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
    // An error record is about a FILESYSTEM, not about an object inside one, so
    // its identity is the filesystem alone: two errors on one filesystem ALWAYS
    // fold together, whichever inodes (if any) they were discovered on. That is
    // the point — a failing filesystem produces errors faster than a daemon can
    // drain them, and the queue must not fill with them.
    let (e_old, e_new) = (crate::inotify::fan_err::is_error_event(old.mask),
                          crate::inotify::fan_err::is_error_event(new.mask));
    if e_old || e_new { return e_old && e_new && old.fsid == new.fsid; }
    if old.name != new.name { return false; }
    // A rename carries a SECOND parent+name, and two renames that agree on the
    // source but not the destination are two different renames.
    if old.name2 != new.name2 { return false; }
    if !same_dir2(old, new) { return false; }
    same_object(old, new)
}

/// The destination halves of two rename records name the same directory (or
/// neither carries one). # C: O(1)
fn same_dir2(old: &Event, new: &Event) -> bool {
    match (&old.dir2, &new.dir2) {
        (None, None) => true,
        (Some(a), Some(b)) => alloc::sync::Arc::ptr_eq(a, b),
        _ => false,
    }
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
        Event { wd: 1, mask, cookie: 0, name: name.to_vec(), obj: o, pid, ..Default::default() }
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
        let ov = Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: Vec::new(), obj: None, pid: 0, ..Default::default() };
        assert!(!is_mergeable_event(&ov));
        assert!(!fanotify_should_merge(&ov, &ov));
    }

    /// inotify's tail rule is unchanged by the fanotify one. # C: O(1)
    #[test]
    fn inotify_tail_merge_still_ignores_the_cookie_and_never_absorbs_ignored() {
        let a = Event { wd: 3, mask: FAN_ACCESS, cookie: 1, name: b"n".to_vec(), obj: None, pid: 0, ..Default::default() };
        let b = Event { wd: 3, mask: FAN_ACCESS, cookie: 99, name: b"n".to_vec(), obj: None, pid: 0, ..Default::default() };
        assert!(merges_into_tail(&a, &b));
        let ign = Event { wd: 3, mask: IN_IGNORED, cookie: 0, name: Vec::new(), obj: None, pid: 0, ..Default::default() };
        assert!(!merges_into_tail(&ign, &ign));
    }
}
