// Mark lifetime vs. the watched object, and notification-queue admission.
//
// Both halves used to be missing, and together they produced the
// `inotify_rm_watch(fd, 1) = EINVAL` a live boot logged against PID 1:
// a watch that outlives its file keeps matching `inode_key`, so the next file
// to land on that ino is handed the DEAD wd instead of a fresh one, and
// userspace then owns two objects on one wd — one removal succeeds, the next
// is EINVAL.
//
// Linux references: `include/linux/fsnotify.h` `fsnotify_inoderemove`,
// `fs/notify/fsnotify.c` `__fsnotify_inode_delete`,
// `fs/notify/inotify/inotify_fsnotify.c` `inotify_ignored_and_remove_idr` /
// `event_compare`.
//
// Included as a child module of `inotify` via `#[path]`.

use super::*;
use alloc::vec::Vec;
use vfs::{FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use crate::inotify::dispatch::fire_delete_self;
use crate::inotify::queue::merges_into_tail;
use crate::inotify::syscalls::{add_or_update_watch, apply_mark, remove_watch};
use crate::inotify::types::{inode_key, Event, MarkScope, FAN_DELETE_SELF, FAN_MODIFY, IN_IGNORED};

const FSID: u64 = 0x6C01;

fn mk(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .fsid(FSID).nlink(1).build()
}

fn masks(g: &InotifyData) -> Vec<u32> { g.events.lock().iter().map(|e| e.mask).collect() }
fn wds(g: &InotifyData) -> Vec<i32> { g.watches.lock().iter().map(|w| w.wd).collect() }
fn ev(wd: i32, mask: u32, cookie: u32, name: &[u8]) -> Event {
    Event { wd, mask, cookie, name: name.to_vec(), obj: None, pid: 0, ..Default::default() }
}

/// The core of `fsnotify_inoderemove`: the inode dying frees the wd, and the
/// wd's death is reported. `inotify_rm_watch` on it is then EINVAL — which is
/// exactly what sd-event tolerates explicitly ("the watch descriptor might
/// already be invalidated, because an IN_IGNORED event might be queued right
/// the moment we enter the syscall").
#[test]
fn deleting_the_watched_inode_frees_the_wd_and_queues_ignored() {
    let g = InotifyData::new(0);
    let f = mk(0x7001);
    let wd = add_or_update_watch(&g, inode_key(&f), f.fsid(), FAN_DELETE_SELF, false, None).unwrap();

    fire_delete_self(&f);

    assert_eq!(masks(&g), alloc::vec![FAN_DELETE_SELF, IN_IGNORED], "DELETE_SELF then IGNORED");
    assert_eq!(wds(&g), Vec::<i32>::new(), "the mark is gone from the group");
    assert_eq!(remove_watch(&g, wd), Err(syscall::errno::Errno::Einval), "wd freed like Linux's idr");
}

/// The EINVAL mechanism itself: a dead watch must not be resurrected by a new
/// file that reuses the ino. Linux allocates a fresh wd because the mark hangs
/// off the (new) inode; we must not let `add_or_update_watch` take its update
/// path against a retired mark.
#[test]
fn a_recycled_ino_gets_a_fresh_wd_not_the_dead_one() {
    let g = InotifyData::new(0);
    let old = mk(0x7002);
    let first = add_or_update_watch(&g, inode_key(&old), old.fsid(), FAN_MODIFY, false, None).unwrap();

    fire_delete_self(&old);

    // Same fsid + ino: a fresh file that landed on the recycled inode number.
    let new = mk(0x7002);
    let second = add_or_update_watch(&g, inode_key(&new), new.fsid(), FAN_MODIFY, false, None).unwrap();

    assert_ne!(second, first, "a new object never inherits a retired wd");
    assert_eq!(remove_watch(&g, first), Err(syscall::errno::Errno::Einval));
    assert_eq!(remove_watch(&g, second), Ok(()));
}

/// `fsnotify_clear_marks_by_inode` clears the INODE's marks only — mount- and
/// filesystem-scope marks hang off the mount/superblock and are untouched.
#[test]
fn mount_scope_marks_survive_an_inode_delete() {
    let g = InotifyData::new_fanotify(0);
    let f = mk(0x7003);
    assert_eq!(apply_mark(&g, MarkScope::Mount, 0, f.fsid(), FAN_MODIFY, true, false, 0), 0);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), FAN_MODIFY, false, None).unwrap();
    assert_eq!(wds(&g).len(), 2);

    fire_delete_self(&f);

    assert_eq!(wds(&g).len(), 1, "only the inode-scope mark is retired");
    assert_eq!(g.watches.lock()[0].scope == MarkScope::Mount, true);
}

/// fanotify has no `freeing_mark` op, so its marks die without a record —
/// only inotify groups get `IN_IGNORED`.
#[test]
fn a_fanotify_inode_mark_dies_without_an_ignored_record() {
    let g = InotifyData::new_fanotify(0);
    let f = mk(0x7004);
    assert_eq!(apply_mark(&g, MarkScope::Inode, inode_key(&f), f.fsid(), FAN_MODIFY, true, false, 0), 0);

    fire_delete_self(&f);

    assert_eq!(wds(&g), Vec::<i32>::new());
    assert_eq!(masks(&g), Vec::<u32>::new(), "no IN_IGNORED for a fanotify group");
}

/// `IN_ONESHOT` retiring a mark after its first event is Linux
/// (`inotify_handle_inode_event`: `if (flags & FSNOTIFY_MARK_FLAG_IN_ONESHOT)
/// fsnotify_destroy_mark`), so the follow-up `inotify_rm_watch` EINVAL is
/// CORRECT, not a lost watch. Pinned so the next reader does not "fix" it.
#[test]
fn oneshot_retires_the_watch_so_a_later_rm_watch_is_correctly_einval() {
    let g = InotifyData::new(0);
    let f = mk(0x7005);
    let wd = add_or_update_watch(&g, inode_key(&f), f.fsid(), FAN_MODIFY | IN_ONESHOT, false, None).unwrap();

    crate::inotify::fire_modify(&f);

    assert_eq!(masks(&g), alloc::vec![FAN_MODIFY, IN_IGNORED]);
    assert_eq!(remove_watch(&g, wd), Err(syscall::errno::Errno::Einval));
}

/// `inotify_merge`/`event_compare`: an identical tail absorbs the new record.
#[test]
fn an_identical_consecutive_event_is_folded_into_the_tail() {
    let g = InotifyData::new(0);
    g.enqueue_event(ev(1, FAN_MODIFY, 0, b""));
    g.enqueue_event(ev(1, FAN_MODIFY, 0, b""));
    assert_eq!(masks(&g).len(), 1);
    assert!(merges_into_tail(&ev(1, FAN_MODIFY, 0, b""), &ev(1, FAN_MODIFY, 0, b"")));
}

/// Only the TAIL is compared (Linux looks at `list->prev` alone), so an
/// interleaved different event breaks the run.
#[test]
fn only_the_tail_absorbs_so_an_interleaved_event_breaks_the_run() {
    let g = InotifyData::new(0);
    g.enqueue_event(ev(1, FAN_MODIFY, 0, b""));
    g.enqueue_event(ev(1, FAN_DELETE_SELF, 0, b""));
    g.enqueue_event(ev(1, FAN_MODIFY, 0, b""));
    assert_eq!(masks(&g), alloc::vec![FAN_MODIFY, FAN_DELETE_SELF, FAN_MODIFY]);
}

/// A different wd or a different name is a different record.
#[test]
fn a_different_wd_or_name_never_merges() {
    assert!(!merges_into_tail(&ev(1, FAN_MODIFY, 0, b""), &ev(2, FAN_MODIFY, 0, b"")));
    assert!(!merges_into_tail(&ev(1, FAN_MODIFY, 0, b"a"), &ev(1, FAN_MODIFY, 0, b"b")));
    assert!(!merges_into_tail(&ev(1, FAN_MODIFY, 0, b""), &ev(1, FAN_MODIFY, 0, b"a")));
}

/// `event_compare` does NOT look at `sync_cookie`, so two moves agreeing on
/// mask/wd/name collapse even with distinct cookies. Mirrors Linux exactly.
#[test]
fn the_rename_cookie_is_not_part_of_the_comparison() {
    assert!(merges_into_tail(&ev(1, FAN_MODIFY, 7, b"x"), &ev(1, FAN_MODIFY, 9, b"x")));
}

/// `if (old->mask & FS_IN_IGNORED) return false` — a watch's death record is
/// the last word on that wd and absorbs nothing.
#[test]
fn an_ignored_tail_absorbs_nothing() {
    assert!(!merges_into_tail(&ev(1, IN_IGNORED, 0, b""), &ev(1, IN_IGNORED, 0, b"")));
    let g = InotifyData::new(0);
    g.enqueue_event(ev(1, IN_IGNORED, 0, b""));
    g.enqueue_event(ev(1, IN_IGNORED, 0, b""));
    assert_eq!(masks(&g).len(), 2);
}
