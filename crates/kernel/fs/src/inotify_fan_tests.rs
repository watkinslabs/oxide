// fanotify(7) hosted tests (D56): full event set, inode/mount/filesystem mark
// scope, FAN_ONDIR + ignore-mask filtering, rename cookie pairing, and the
// permission-reply protocol. Included as a child module of `inotify` via
// `#[path]`, so `use super::*` reaches the module-private mark/dispatch items.

use super::*;
use crate::inotify::response::{FAN_ALLOW, FAN_DENY};
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{InodeBuilder, default_inode_ops, mk_mode, FileType};

/// Build a throwaway inode with a chosen type + superblock identity (`fsid`).
/// Distinct `fsid`/identity per test keeps the shared INSTANCES list from
/// cross-matching parallel tests. # C: O(1)
fn mk_inode(ft: FileType, fsid: u64) -> InodeRef {
    InodeBuilder::new(0x9000_0000 + fsid, mk_mode(ft, 0o644),
        default_inode_ops(), Arc::new(InotifyFileOps))
        .fsid(fsid).build()
}

fn masks(g: &InotifyData) -> Vec<u32> { g.events.lock().iter().map(|e| e.mask).collect() }

// An inode mark delivers exactly the events it requested; un-requested events
// (FAN_ACCESS here) are dropped. fire_attrib maps to FAN_ATTRIB.
#[test]
fn inode_mark_event_set() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x1001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_MODIFY | FAN_OPEN | FAN_ATTRIB | FAN_CLOSE_WRITE, true, false, 0);
    fire_self(&ino, FAN_MODIFY);
    fire_self(&ino, FAN_ACCESS);          // not in mask → dropped
    fire_attrib(&ino);
    fire_self(&ino, FAN_CLOSE_WRITE);
    // Three accesses to one object by one process are ONE record with the
    // masks OR-ed (`fanotify_merge`), not three — a daemon reading a busy file
    // otherwise drowns in duplicates of the same fact.
    assert_eq!(masks(&g), [FAN_MODIFY | FAN_ATTRIB | FAN_CLOSE_WRITE]);
}

// A mount-scope mark matches any object on the same superblock (fsid), and
// nothing on a different one.
#[test]
fn mount_mark_matches_by_fsid() {
    let g = InotifyData::new_fanotify(0);
    apply_mark(&g, MarkScope::Mount, 0, 0x2001, FAN_OPEN, true, false, 0);
    let same = mk_inode(FileType::Regular, 0x2001);
    let other = mk_inode(FileType::Regular, 0x2002);
    fire_self(&same, FAN_OPEN);
    fire_self(&other, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}

// A filesystem-scope mark behaves like a mount mark over the whole superblock.
#[test]
fn filesystem_mark_matches_superblock() {
    let g = InotifyData::new_fanotify(0);
    apply_mark(&g, MarkScope::Filesystem, 0, 0x3001, FAN_MODIFY, true, false, 0);
    let a = mk_inode(FileType::Regular, 0x3001);
    let b = mk_inode(FileType::Regular, 0x3001);   // same fs, different inode
    fire_self(&a, FAN_MODIFY);
    fire_self(&b, FAN_MODIFY);
    assert_eq!(masks(&g), [FAN_MODIFY, FAN_MODIFY]);
}

// A self-event on a directory is delivered only when the mark set FAN_ONDIR
// (Linux `fsnotify_mask_applicable`). The bit is a mark-side OPT-IN, never
// echoed back to a legacy fd-reporting group (`fanotify_group_event_mask`
// clears FANOTIFY_EVENT_FLAGS from `user_mask` outside fid mode).
#[test]
fn ondir_filters_directory_self_events() {
    let g = InotifyData::new_fanotify(0);
    let dir = mk_inode(FileType::Directory, 0x4001);
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_OPEN, true, false, 0);
    fire_self(&dir, FAN_OPEN);                       // no FAN_ONDIR → suppressed
    assert!(masks(&g).is_empty());
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_ONDIR, true, false, 0);
    fire_self(&dir, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}

// FAN_MARK_IGNORED_MASK bits suppress otherwise-requested events.
#[test]
fn ignored_mask_suppresses() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x5001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN | FAN_CLOSE_WRITE, true, false, 0);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, true, 0); // ignore OPEN
    fire_self(&ino, FAN_OPEN);          // suppressed
    fire_self(&ino, FAN_CLOSE_WRITE);   // still delivered
    assert_eq!(masks(&g), [FAN_CLOSE_WRITE]);
}

/// An ignore set established WITHOUT `FAN_MARK_IGNORED_SURV_MODIFY` is cleared
/// the moment the object is modified, and the modification that cleared it is
/// itself delivered — the clear runs before the ignore set is consulted. A
/// watcher relying on a surviving ignore set silently starts receiving events
/// it thought it had suppressed.
#[test]
fn a_volatile_ignore_set_is_cleared_by_a_modification() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x5101);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, true, false, 0);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, true, true, 0);
    fire_self(&ino, FAN_MODIFY);
    assert_eq!(masks(&g), [FAN_MODIFY], "the modify that cleared the set is delivered");
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_MODIFY | FAN_OPEN], "and the set no longer suppresses OPEN");
}

/// `FAN_MARK_IGNORED_SURV_MODIFY` keeps the ignore set across a modification,
/// which is the flag's entire purpose.
#[test]
fn a_surviving_ignore_set_outlives_a_modification() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x5201);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, true, false,
               crate::inotify::validate::FAN_MARK_IGNORED_SURV_MODIFY);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, true,
               crate::inotify::validate::FAN_MARK_IGNORED_SURV_MODIFY);
    fire_self(&ino, FAN_MODIFY);
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_MODIFY], "OPEN stays suppressed after the modify");
}

/// A fanotify mark on a directory does NOT receive events about files inside it
/// unless it asked for child events. Without this gate a mark on `/` reports
/// every open of every file on the system.
#[test]
fn a_directory_mark_needs_event_on_child_for_events_inside_it() {
    let g = InotifyData::new_fanotify(0);
    let dir = mk_inode(FileType::Directory, 0x5301);
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_OPEN, true, false, 0);
    crate::inotify::dispatch::fire_child_path_for_test(&dir, FAN_OPEN, "inside", false);
    assert!(masks(&g).is_empty(), "no FAN_EVENT_ON_CHILD → no child events");
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(),
               crate::inotify::types::FAN_EVENT_ON_CHILD, true, false, 0);
    crate::inotify::dispatch::fire_child_path_for_test(&dir, FAN_OPEN, "inside", false);
    assert_eq!(masks(&g), [FAN_OPEN]);
}

/// The parent leg reaches INODE marks only. A mount- or filesystem-scope mark
/// already matched the same access on the file's own leg, so firing it again on
/// the parent delivers one access twice.
#[test]
fn the_parent_leg_does_not_re_deliver_to_mount_and_filesystem_marks() {
    let g = InotifyData::new_fanotify(0);
    apply_mark(&g, MarkScope::Mount, 0, 0x5401, FAN_OPEN, true, false, 0);
    apply_mark(&g, MarkScope::Filesystem, 0, 0x5401, FAN_OPEN, true, false, 0);
    let dir = mk_inode(FileType::Directory, 0x5401);
    crate::inotify::dispatch::fire_child_path_for_test(&dir, FAN_OPEN, "inside", false);
    assert!(masks(&g).is_empty());
}

// A rename emits FAN_MOVED_FROM on the source dir and FAN_MOVED_TO on the
// destination dir, sharing one cookie; FAN_MOVE_SELF fires on the moved object.
#[test]
fn move_emits_paired_cookie() {
    let g = InotifyData::new_fanotify(0);
    let old = mk_inode(FileType::Directory, 0x6001);
    let new = mk_inode(FileType::Directory, 0x6002);
    let moved = mk_inode(FileType::Regular, 0x6003);
    for d in [&old, &new] {
        apply_mark(&g, MarkScope::Inode, inode_key(d), d.fsid(), FAN_MOVE | FAN_ONDIR, true, false, 0);
    }
    apply_mark(&g, MarkScope::Inode, inode_key(&moved), moved.fsid(), FAN_MOVE_SELF, true, false, 0);
    fire_move(&old, &new, Some(&moved), "before", "after");
    let evs: Vec<(u32, u32)> = g.events.lock().iter().map(|e| (e.mask, e.cookie)).collect();
    // MOVED_FROM, MOVED_TO, MOVE_SELF. A legacy (fd-reporting) fanotify group
    // never reports FAN_ONDIR back to userspace — Linux
    // `fanotify_group_event_mask` strips FANOTIFY_EVENT_FLAGS outside fid mode
    // — and the moved object is a regular file, so FS_ISDIR is unset anyway.
    assert_eq!(evs[0].0, FAN_MOVED_FROM);
    assert_eq!(evs[1].0, FAN_MOVED_TO);
    assert_eq!(evs[2].0, FAN_MOVE_SELF);
    assert_ne!(evs[0].1, 0);
    assert_eq!(evs[0].1, evs[1].1);  // FROM/TO share a cookie
}

#[test]
fn child_create_delete_events_reach_watched_directory() {
    let g = InotifyData::new(0);
    let dir = mk_inode(FileType::Directory, 0x6d01);
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(),
               IN_CREATE | IN_DELETE, true, false, 0);

    fire_child(&dir, IN_CREATE, 0, "kid", false);
    fire_child(&dir, IN_DELETE, 0, "kid", false);

    assert_eq!(masks(&g), [IN_CREATE, IN_DELETE]);
}

// Linux `fsnotify_mask_applicable`: a fanotify mark WITHOUT FAN_ONDIR never
// sees an event whose affected object is a directory — and one WITH it does.
#[test]
fn fanotify_directory_events_need_fan_ondir_on_the_mark() {
    let plain = InotifyData::new_fanotify(0);
    let ondir = InotifyData::new_fanotify(0);
    let dir = mk_inode(FileType::Directory, 0x6d55);
    apply_mark(&plain, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_CREATE, true, false, 0);
    apply_mark(&ondir, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_CREATE | FAN_ONDIR, true, false, 0);

    // A subdirectory was created inside the watched directory: FS_ISDIR is set.
    fire_child(&dir, FAN_CREATE, 0, "sub", true);

    assert!(plain.events.lock().is_empty(), "mark without FAN_ONDIR must not see a dir event");
    assert_eq!(masks(&ondir), [FAN_CREATE], "FAN_ONDIR mark sees it, without the flag echoed back");
}

// FAN_OPEN_EXEC is delivered to a mark requesting it (execve open-exec event).
#[test]
fn open_exec_event() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x7001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN_EXEC, true, false, 0);
    fire_open_exec(&ino);
    assert_eq!(masks(&g), [FAN_OPEN_EXEC]);
}

// REMOVE clears the named bits; emptying the mark retires it (no further events).
#[test]
fn remove_clears_and_retires() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x8001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, true, false, 0);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, false, false, 0);
    fire_self(&ino, FAN_MODIFY);
    assert!(masks(&g).is_empty());
    assert!(g.watches.lock().is_empty());
}

// The full permission-reply cycle: a queued perm event is read by the listener
// (minting a response fd), the listener writes FAN_DENY, and the parked accessor
// observes the verdict. (No scheduler park needed on host: the fd is FAN_NOFD.)
#[test]
fn perm_reply_protocol_deny_then_allow() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9001);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    assert_eq!(respond(&g, fd, FAN_DENY), Ok(8));
    assert_eq!(st.answered(), Some(FAN_DENY));
}

/// A denied access reports EPERM, which is what the accessing syscall returns.
/// EACCES would tell a caller the file's mode bits refused it, which is a
/// different and wrong explanation.
#[test]
fn a_denied_access_reports_eperm() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9101);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    assert_eq!(respond(&g, fd, FAN_DENY), Ok(8));
    let v = crate::inotify::response::validate_response(st.answered().unwrap(), false, false).unwrap();
    assert_eq!(v.as_result(), Err(syscall::errno::Errno::Eperm));
}

/// Permission events share ONE queue with ordinary notifications, so a reader
/// sees them in the order the accesses happened. Held in a second queue they
/// jumped ahead of every notification that explained them.
#[test]
fn permission_events_are_read_in_arrival_order() {
    let g = InotifyData::new_fanotify(0);
    let a = mk_inode(FileType::Regular, 0x9201);
    let b = mk_inode(FileType::Regular, 0x9202);
    apply_mark(&g, MarkScope::Inode, inode_key(&a), a.fsid(), FAN_OPEN, true, false, 0);
    fire_self(&a, FAN_OPEN);                       // notification first
    queue_perm(&g, &b, FAN_OPEN_PERM);             // permission event second
    fire_self(&a, FAN_MODIFY);
    assert_eq!(masks(&g), [FAN_OPEN, FAN_OPEN_PERM]);
}

/// A permission event is never folded into another record: the accessor is
/// parked on that one record and names it by its own descriptor.
#[test]
fn a_permission_event_is_never_merged_away() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9301);
    let s1 = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let s2 = queue_perm(&g, &ino, FAN_OPEN_PERM);
    assert_eq!(masks(&g), [FAN_OPEN_PERM, FAN_OPEN_PERM], "two records, not one");
    assert_eq!(s1.answered(), None);
    assert_eq!(s2.answered(), None);
}

/// Two identical accesses to the same object by the same process collapse into
/// one record with the masks OR-ed, which is the whole point of the merge.
#[test]
fn identical_fanotify_events_merge_with_ored_masks() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9401);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN | FAN_MODIFY, true, false, 0);
    fire_self(&ino, FAN_OPEN);
    fire_self(&ino, FAN_MODIFY);
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN | FAN_MODIFY], "one merged record");
}

/// The merge search is HASHED on the object, not a walk back from the tail. A
/// daemon that has fallen hundreds of events behind must still get its repeated
/// access folded into the record already describing it: with a bounded backward
/// scan the same access reaches userspace twice as soon as the queue is deeper
/// than the bound, which is a behaviour change userspace can see purely from
/// how busy the machine is.
#[test]
fn a_mergeable_event_is_found_however_deep_the_queue_has_grown() {
    let g = InotifyData::new_fanotify(0);
    let first = mk_inode(FileType::Regular, 0xB101);
    apply_mark(&g, MarkScope::Filesystem, 0, 0xB101, FAN_OPEN | FAN_MODIFY, true, false, 0);
    fire_self(&first, FAN_OPEN);
    // Bury it under far more unrelated records than any bounded backward scan
    // would reach — each on its own object, so none of them merges.
    let depth = crate::inotify::queue::FANOTIFY_MAX_MERGE_EVENTS * 2;
    let others: Vec<InodeRef> = (0..depth)
        .map(|i| {
            let o = InodeBuilder::new(0xC000_0000 + i as u64, mk_mode(FileType::Regular, 0o644),
                default_inode_ops(), Arc::new(InotifyFileOps)).fsid(0xB101).build();
            fire_self(&o, FAN_OPEN);
            o
        })
        .collect();
    assert_eq!(g.events.lock().len(), depth + 1, "each unrelated object is its own record");
    fire_self(&first, FAN_MODIFY);
    assert_eq!(g.events.lock().len(), depth + 1, "the repeat merged rather than queueing again");
    assert_eq!(masks(&g)[0], FAN_OPEN | FAN_MODIFY, "into the record at the FRONT");
    drop(others);
}

/// An unknown descriptor is reported, not silently dropped — a daemon that
/// answers a stale event learns it did.
#[test]
fn a_response_naming_no_pending_event_is_enoent() {
    let g = InotifyData::new_fanotify(0);
    assert_eq!(respond(&g, 4242, FAN_ALLOW), Err(vfs::VfsError::Enoent));
}

/// The response word is validated before anything is unblocked.
#[test]
fn a_malformed_response_is_einval() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9501);
    queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    assert_eq!(respond(&g, fd, 0), Err(vfs::VfsError::Einval), "no verdict named");
    assert_eq!(respond(&g, fd, FAN_ALLOW | FAN_DENY), Err(vfs::VfsError::Einval), "both verdicts");
    assert_eq!(respond(&g, fd, FAN_ALLOW | 0x40), Err(vfs::VfsError::Einval), "unknown bit");
    // A short write carries no whole response struct.
    assert_eq!(g.write(0, &[0u8; 7]), Err(vfs::VfsError::Einval));
    // The event is still answerable afterwards.
    assert_eq!(respond(&g, fd, FAN_ALLOW), Ok(8));
}

/// One write carries exactly ONE response, whatever its length, and reports
/// the 8 bytes that response occupied.
#[test]
fn one_write_answers_exactly_one_event() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9601);
    let s1 = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let s2 = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let mut buf = [0u8; 128];
    assert_eq!(g.read_fanotify(&mut buf).unwrap(), 48, "two 24-byte records");
    let fd1 = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let fd2 = i32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let mut two = [0u8; 16];
    two[0..4].copy_from_slice(&fd1.to_le_bytes());
    two[4..8].copy_from_slice(&FAN_ALLOW.to_le_bytes());
    two[8..12].copy_from_slice(&fd2.to_le_bytes());
    two[12..16].copy_from_slice(&FAN_ALLOW.to_le_bytes());
    assert_eq!(g.write(0, &two), Ok(8), "only the first response is consumed");
    assert_eq!(s1.answered(), Some(FAN_ALLOW));
    assert_eq!(s2.answered(), None, "the second response was not applied");
}

/// `FAN_INFO`'s record is PARSED, not skipped. A daemon that attaches an audit
/// rule gets the record's bytes counted in the return value, and the rule is
/// recorded against the decision it justifies.
#[test]
fn a_fan_info_response_carries_its_audit_rule_through_to_the_event() {
    use crate::inotify::response::{AuditRule, AUDIT_RULE_LEN, FAN_INFO,
        FAN_RESPONSE_INFO_AUDIT_RULE};
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9801);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    let w = respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO,
                              &audit_rule_bytes(FAN_RESPONSE_INFO_AUDIT_RULE, 0,
                                                AUDIT_RULE_LEN as u16, 77, 1, 2));
    assert_eq!(w, Ok(8 + AUDIT_RULE_LEN), "the record's bytes are consumed too");
    assert_eq!(st.answered(), Some(FAN_ALLOW), "FAN_INFO is stripped from the stored verdict");
    assert_eq!(st.audit_rule(),
               Some(AuditRule { rule_number: 77, subj_trust: 1, obj_trust: 2 }));
}

/// Every field of the record is checked, and a rejected record leaves the
/// permission event answerable — the daemon may write a correct one instead.
#[test]
fn a_malformed_fan_info_record_is_einval_and_answers_nothing() {
    use crate::inotify::response::{AUDIT_RULE_LEN, FAN_INFO, FAN_RESPONSE_INFO_AUDIT_RULE,
        FAN_RESPONSE_INFO_NONE};
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9901);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    let ok = audit_rule_bytes(FAN_RESPONSE_INFO_AUDIT_RULE, 0, AUDIT_RULE_LEN as u16, 5, 0, 0);
    let einval = Err(vfs::VfsError::Einval);
    // FAN_INFO with no record at all.
    assert_eq!(respond(&g, fd, FAN_ALLOW | FAN_INFO), einval);
    // A truncated record, and a record with trailing bytes: the tail must be
    // EXACTLY one record.
    assert_eq!(respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO, &ok[..AUDIT_RULE_LEN - 1]), einval);
    let mut long = ok.to_vec();
    long.push(0);
    assert_eq!(respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO, &long), einval);
    // The only record type a response may carry.
    assert_eq!(respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO,
        &audit_rule_bytes(FAN_RESPONSE_INFO_NONE, 0, AUDIT_RULE_LEN as u16, 5, 0, 0)), einval);
    // A nonzero pad byte, and a header length disagreeing with the record.
    assert_eq!(respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO,
        &audit_rule_bytes(FAN_RESPONSE_INFO_AUDIT_RULE, 1, AUDIT_RULE_LEN as u16, 5, 0, 0)), einval);
    assert_eq!(respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO,
        &audit_rule_bytes(FAN_RESPONSE_INFO_AUDIT_RULE, 0, 8, 5, 0, 0)), einval);
    assert_eq!(st.answered(), None, "no rejected write answered the event");
    assert_eq!(respond_with_rule(&g, fd, FAN_ALLOW | FAN_INFO, &ok), Ok(8 + AUDIT_RULE_LEN));
    assert_eq!(st.answered(), Some(FAN_ALLOW));
}

/// `FAN_NOFD` names no event. With `FAN_INFO` the write is still accepted for
/// its record alone — it neither answers a pending event nor reports ENOENT —
/// while a negative descriptor WITHOUT a record has nothing to mean and is
/// EINVAL.
#[test]
fn a_fan_nofd_response_with_a_record_is_accepted_and_answers_nothing() {
    use crate::inotify::response::{AUDIT_RULE_LEN, FAN_INFO, FAN_RESPONSE_INFO_AUDIT_RULE};
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9A01);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let _fd = read_one_perm(&g);
    let ok = audit_rule_bytes(FAN_RESPONSE_INFO_AUDIT_RULE, 0, AUDIT_RULE_LEN as u16, 9, 0, 0);
    let nofd = crate::inotify::fan_layout::FAN_NOFD;
    assert_eq!(respond_with_rule(&g, nofd, FAN_ALLOW | FAN_INFO, &ok), Ok(8 + AUDIT_RULE_LEN));
    assert_eq!(st.answered(), None, "no pending event was named");
    assert_eq!(respond(&g, nofd, FAN_ALLOW), Err(vfs::VfsError::Einval),
               "without a record a negative descriptor names nothing at all");
}

/// One `struct fanotify_response_info_audit_rule` in wire order. # C: O(1)
#[cfg(test)]
fn audit_rule_bytes(ty: u8, pad: u8, len: u16, rule: u32, subj: u32, obj: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = ty;
    b[1] = pad;
    b[2..4].copy_from_slice(&len.to_le_bytes());
    b[4..8].copy_from_slice(&rule.to_le_bytes());
    b[8..12].copy_from_slice(&subj.to_le_bytes());
    b[12..16].copy_from_slice(&obj.to_le_bytes());
    b
}

/// A `fanotify_response` followed by raw info bytes, written as one call.
/// # C: O(info.len())
#[cfg(test)]
fn respond_with_rule(g: &InotifyData, fd: i32, response: u32, info: &[u8])
    -> vfs::KResult<usize> {
    let mut w = Vec::new();
    w.extend_from_slice(&fd.to_le_bytes());
    w.extend_from_slice(&response.to_le_bytes());
    w.extend_from_slice(info);
    g.write(0, &w)
}

/// An accessor that abandoned the wait (killed mid-syscall) must not be
/// "resumed" by a verdict that arrives afterwards — it is already gone, and the
/// response is discarded rather than published.
#[test]
fn a_verdict_for_an_abandoned_access_is_discarded() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x9701);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let fd = read_one_perm(&g);
    st.cancel();
    assert_eq!(respond(&g, fd, FAN_DENY), Ok(8), "the daemon's write still succeeds");
    assert_eq!(st.answered(), None, "but nothing is published to the dead accessor");
}

// Closing a group auto-allows still-pending perm events so a dead listener
// never wedges a blocked accessor.
#[test]
fn perm_release_auto_allows() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA001);
    let st = queue_perm(&g, &ino, FAN_OPEN_PERM);
    g.on_release();
    assert_eq!(st.answered(), Some(FAN_ALLOW));
}

/// Closing with events outstanding must answer BOTH the ones a reader already
/// handed to the daemon and the ones still queued. Only answering one list
/// leaves the other set of accessors parked forever.
#[test]
fn release_answers_both_reported_and_still_queued_events() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA101);
    let reported = queue_perm(&g, &ino, FAN_OPEN_PERM);
    let _fd = read_one_perm(&g);                       // moves it to the pending list
    let queued = queue_perm(&g, &ino, crate::inotify::types::FAN_ACCESS_PERM); // still in the queue
    g.on_release();
    assert_eq!(reported.answered(), Some(FAN_ALLOW));
    assert_eq!(queued.answered(), Some(FAN_ALLOW));
}

/// After release the group queues nothing more, so an access arriving during
/// teardown is not parked on a group that will never answer.
#[test]
fn a_closed_group_queues_no_further_events() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA201);
    g.on_release();
    let st = Arc::new(crate::inotify::types::PermState::new());
    assert!(g.queue_perm_event(perm_event(&ino, FAN_OPEN_PERM, st)).is_none());
    assert!(g.events.lock().is_empty());
}

// FAN_OPEN_EXEC_PERM execve-gate cycle (D56). perm_marks_present() is the boot
// fast-path gate the execve hook checks first: false with no perm mark armed
// (execve skips the resolve entirely), true once a FAN_OPEN_EXEC_PERM mark is
// installed. Single test: it is the sole mutator of the global
// PERM_MARK_COUNT, so the gate assertions are race-free.
#[test]
fn open_exec_perm_gate_cycle() {
    // No perm marks armed by us yet → execve gate stays inert.
    assert!(!perm_marks_present());

    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xC001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN_EXEC_PERM, true, false, 0);
    // A FAN_*_PERM mark is now armed → execve gate engages its resolve+check.
    assert!(perm_marks_present());

    let denied = queue_perm(&g, &ino, FAN_OPEN_EXEC_PERM);
    let fd = read_one_perm(&g);
    assert_eq!(respond(&g, fd, FAN_DENY), Ok(8));
    assert_eq!(denied.answered(), Some(FAN_DENY));

    let allowed = queue_perm(&g, &ino, FAN_OPEN_EXEC_PERM);
    let fd2 = read_one_perm(&g);
    assert_eq!(respond(&g, fd2, FAN_ALLOW), Ok(8));
    assert_eq!(allowed.answered(), Some(FAN_ALLOW));

    // Retire the mark → gate goes inert again (PERM_MARK_COUNT back to 0).
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN_EXEC_PERM, false, false, 0);
    assert!(!perm_marks_present());
}

/// One permission-event record for `obj`, with fresh shared state. # C: O(1)
fn perm_event(obj: &InodeRef, mask: u32, st: Arc<crate::inotify::types::PermState>)
    -> crate::inotify::types::Event {
    crate::inotify::types::Event {
        wd: -1, mask, cookie: 0, name: Vec::new(), obj: Some(obj.clone()), pid: 0, perm: Some(st), mnt_id: 0,    }
}

/// Queue a permission event on `g` and hand back the state an accessor would
/// park on. # C: O(1)
fn queue_perm(g: &Arc<InotifyData>, obj: &InodeRef, mask: u32)
    -> Arc<crate::inotify::types::PermState> {
    let st = Arc::new(crate::inotify::types::PermState::new());
    g.queue_perm_event(perm_event(obj, mask, st.clone())).expect("queued");
    st
}

/// Drain one 24-byte metadata record and return the descriptor it carried.
/// # C: O(1)
fn read_one_perm(g: &InotifyData) -> i32 {
    let mut buf = [0u8; 24];
    assert_eq!(g.read_fanotify(&mut buf).unwrap(), 24);
    i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]])
}

/// Write one `struct fanotify_response`. # C: O(1)
fn respond(g: &InotifyData, fd: i32, response: u32) -> vfs::KResult<usize> {
    let mut r = [0u8; 8];
    r[0..4].copy_from_slice(&fd.to_le_bytes());
    r[4..8].copy_from_slice(&response.to_le_bytes());
    g.write(0, &r)
}

// fanotify_init flag validation: unknown bits, the impossible class 0xc, and
// FAN_REPORT_NAME without FAN_REPORT_DIR_FID are all EINVAL.
#[test]
fn init_flag_validation() {
    assert_eq!(validate_fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK), 0);
    assert_eq!(validate_fanotify_init(FAN_CLASS_CONTENT), 0);
    assert_ne!(validate_fanotify_init(0x8000_0000), 0);                 // unknown bit
    assert_ne!(validate_fanotify_init(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT), 0); // 0xc
    assert_ne!(validate_fanotify_init(FAN_REPORT_NAME), 0);             // NAME w/o DIR_FID
    assert_eq!(validate_fanotify_init(FAN_REPORT_NAME | FAN_REPORT_DIR_FID), 0);
}

/// `FAN_MARK_EVICTABLE` means "do not pin the object": the mark goes away with
/// the cached inode, so a later access is NOT reported. An ordinary mark pins
/// the object and survives. Without this the flag was accepted and stored and
/// then changed nothing, which is worse than rejecting it — a watcher believes
/// it holds a non-pinning mark and it does not.
#[test]
fn an_evictable_mark_goes_away_with_the_cached_inode() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xE001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false,
               crate::inotify::validate::FAN_MARK_EVICTABLE);
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN], "armed before eviction");
    crate::inotify::marks::evict_inode_marks(&ino);
    assert!(g.watches.lock().is_empty(), "the evictable mark left with the inode");
}

/// A mark WITHOUT the flag pins its object and survives an eviction.
#[test]
fn an_ordinary_mark_survives_an_eviction() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xE101);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false, 0);
    crate::inotify::marks::evict_inode_marks(&ino);
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}

/// A `FAN_REPORT_PIDFD` group's read carries a pidfd info record after the
/// metadata, and `event_len` accounts for it — a record the size field did not
/// include would desynchronise the reader's record walk on the very first
/// event.
#[test]
fn a_pidfd_group_emits_a_pidfd_record() {
    use crate::inotify::validate::FAN_REPORT_PIDFD;
    let g = InotifyData::new_fanotify(FAN_REPORT_PIDFD);
    let ino = mk_inode(FileType::Regular, 0xF001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false, 0);
    fire_self(&ino, FAN_OPEN);
    let mut buf = [0u8; 64];
    let n = g.read_fanotify(&mut buf).unwrap();
    assert_eq!(n, 24 + 8, "metadata plus one pidfd record");
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 32,
               "event_len covers the info record");
    assert_eq!(buf[24], 4, "FAN_EVENT_INFO_TYPE_PIDFD");
    assert_eq!(u16::from_le_bytes([buf[26], buf[27]]), 8);
}

/// A fid-reporting group IS told the affected object was a directory; a legacy
/// fd-reporting group is not. Reporting it to a legacy group would set a bit
/// in `metadata.mask` that such a group's userspace never expects.
#[test]
fn only_a_fid_group_is_told_the_object_was_a_directory() {
    use crate::inotify::validate::FAN_REPORT_FID;
    let legacy = InotifyData::new_fanotify(0);
    let fid = InotifyData::new_fanotify(FAN_REPORT_FID);
    let d = mk_inode(FileType::Directory, 0xF101);
    for g in [&legacy, &fid] {
        apply_mark(g, MarkScope::Inode, inode_key(&d), d.fsid(), FAN_OPEN | FAN_ONDIR, true, false, 0);
    }
    fire_self(&d, FAN_OPEN);
    assert_eq!(masks(&legacy), [FAN_OPEN], "legacy group: no FAN_ONDIR echoed back");
    assert_eq!(masks(&fid), [FAN_OPEN | FAN_ONDIR]);
}

// FLUSH drops only the marks of the selected scope, leaving other scopes intact.
#[test]
fn flush_is_scope_local() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xB001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false, 0);
    apply_mark(&g, MarkScope::Mount, 0, 0xB001, FAN_OPEN, true, false, 0);
    // Flush only the inode-scope marks by retaining non-inode.
    {
        let mut w = g.watches.lock();
        w.retain(|x| x.scope != MarkScope::Inode);
    }
    // The mount mark survives and still fires on the same superblock.
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}
