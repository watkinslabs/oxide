// Mark LIFETIME against the object a mark is attached to — Linux
// `__fsnotify_inode_delete` (`fs/notify/fsnotify.c`), reached from
// `fsnotify_inoderemove` in `include/linux/fsnotify.h`:
//
//     static inline void fsnotify_inoderemove(struct inode *inode)
//     {
//             fsnotify_inode(inode, FS_DELETE_SELF);
//             __fsnotify_inode_delete(inode);
//     }
//
// which `fs/dcache.c` `dentry_unlink_inode` runs under `if (!inode->i_nlink)`.
//
// A mark on Linux hangs off the inode, so the inode dying takes the mark with
// it: `fsnotify_clear_marks_by_inode` destroys every mark, inotify's
// `freeing_mark` (`inotify_ignored_and_remove_idr`) queues `IN_IGNORED` and
// FREES THE WD from the group's idr.
//
// Our marks are keyed by inode IDENTITY (`inode_key` = fsid+ino) rather than by
// a pointer, so nothing retires them implicitly. Without this module a watch
// outlives the file it watched, with two user-visible consequences that are
// both wrong:
//   1. no `IN_IGNORED` — a watcher never learns the watch died, and
//      `inotify_rm_watch` on that wd SUCCEEDS where Linux returns EINVAL;
//   2. the stale mark keeps matching `inode_key`, so a LATER file that reuses
//      the ino resurrects it: `inotify_add_watch` takes the update path and
//      hands back the OLD wd for a NEW object. Userspace then holds two live
//      objects on one wd, removes it once successfully and once with EINVAL —
//      exactly the `inotify_rm_watch(fd, 1) = EINVAL` shape sd-event documents
//      as "the watch descriptor might already be invalidated".

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use vfs::InodeRef;

use crate::inotify::dispatch::instances;
use crate::inotify::types::{inode_key, perm_delta, Event, MarkScope, IN_IGNORED, IN_UNMOUNT, MARK_COUNT};

/// Linux `fsnotify_clear_marks_by_inode`: retire every INODE-scope mark on
/// `inode` across every live group. inotify groups additionally get the
/// `IN_IGNORED` record for each freed wd (Linux `inotify_freeing_mark` →
/// `inotify_ignored_and_remove_idr`); fanotify has no `freeing_mark` op, so its
/// marks go away silently. Mount- and filesystem-scope marks are untouched —
/// they are attached to the mount/superblock, not the inode.
/// # C: O(N_groups * N_watches)
pub(crate) fn destroy_inode_marks(inode: &InodeRef) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let key = inode_key(inode);
    let g = instances().lock();
    for w in g.iter() {
        let arc = match w.upgrade() { Some(a) => a, None => continue };
        let mut freed: Vec<i32> = Vec::new();
        {
            // Released before `enqueue_event` so the notification queue is
            // never taken under the watch list (same order `dispatch` needs).
            let mut watches = arc.watches.lock();
            let mut i = 0usize;
            while i < watches.len() {
                if watches[i].scope != MarkScope::Inode || watches[i].inode_key != key {
                    i += 1;
                    continue;
                }
                perm_delta(watches[i].mask, 0);
                freed.push(watches[i].wd);
                watches.remove(i);
                MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
            }
        }
        arc.release_marks(freed.len());
        if arc.is_fanotify() { continue; }
        for wd in freed {
            arc.enqueue_event(Event { wd, mask: IN_IGNORED, cookie: 0, name: Vec::new(), obj: None, pid: 0 });
        }
    }
}

/// Linux `fsnotify_unmount_inodes` + the mark teardown that follows it when a
/// superblock goes away: every inode on the dying filesystem that carries marks
/// is reported `FS_UNMOUNT`, and then its marks are destroyed — which for an
/// inotify group means an `IN_IGNORED` record per freed wd.
///
/// `IN_UNMOUNT` is NOT filtered on the mark's mask. `inotify_arg_to_mask` seeds
/// every mark with `FS_UNMOUNT` before OR-ing in whatever the caller asked for,
/// so a watch set up for `IN_MODIFY` alone still receives the unmount notice;
/// that record is a watcher's only signal that the object it was following is
/// unreachable rather than merely quiet.
///
/// Ordering is user-visible and matches the delete-self path: `IN_UNMOUNT`
/// first, `IN_IGNORED` second, both for the same wd, and the wd is gone
/// afterwards (a later `inotify_rm_watch` on it is `EINVAL`).
///
/// Mount- and filesystem-scope fanotify marks key on the same `fsid` and are
/// retired here too, silently — fanotify has no `freeing_mark` record.
/// # C: O(N_groups * N_watches)
pub(crate) fn unmount_fs_marks(fsid: u64) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    if fsid == 0 { return; }
    let g = instances().lock();
    for w in g.iter() {
        let arc = match w.upgrade() { Some(a) => a, None => continue };
        let mut freed: Vec<i32> = Vec::new();
        {
            let mut watches = arc.watches.lock();
            let mut i = 0usize;
            while i < watches.len() {
                if watches[i].fsid != fsid { i += 1; continue; }
                perm_delta(watches[i].mask, 0);
                freed.push(watches[i].wd);
                watches.remove(i);
                MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
            }
        }
        arc.release_marks(freed.len());
        if arc.is_fanotify() { continue; }
        for wd in freed {
            arc.enqueue_event(Event { wd, mask: IN_UNMOUNT, cookie: 0, name: Vec::new(), obj: None, pid: 0 });
            arc.enqueue_event(Event { wd, mask: IN_IGNORED, cookie: 0, name: Vec::new(), obj: None, pid: 0 });
        }
    }
}
