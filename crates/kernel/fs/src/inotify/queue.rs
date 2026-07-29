// Notification-queue ADMISSION rules — Linux `fsnotify_add_event`
// (`fs/notify/notification.c`) plus inotify's `merge` callback
// (`fs/notify/inotify/inotify_fsnotify.c` `inotify_merge`/`event_compare`).
//
// Deliberately free of any target gate so the admission decision is
// hosted-testable; `group::enqueue_event` only sequences these helpers.

use crate::inotify::types::{Event, IN_IGNORED};

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
