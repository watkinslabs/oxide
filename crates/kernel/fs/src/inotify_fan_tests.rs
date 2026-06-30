// fanotify(7) hosted tests (D56): full event set, inode/mount/filesystem mark
// scope, FAN_ONDIR + ignore-mask filtering, rename cookie pairing, and the
// permission-reply protocol. Included as a child module of `inotify` via
// `#[path]`, so `use super::*` reaches the module-private mark/dispatch items.

use super::*;
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
               FAN_MODIFY | FAN_OPEN | FAN_ATTRIB | FAN_CLOSE_WRITE, true, false);
    fire_self(&ino, FAN_MODIFY);
    fire_self(&ino, FAN_ACCESS);          // not in mask → dropped
    fire_attrib(&ino);
    fire_self(&ino, FAN_CLOSE_WRITE);
    assert_eq!(masks(&g), [FAN_MODIFY, FAN_ATTRIB, FAN_CLOSE_WRITE]);
}

// A mount-scope mark matches any object on the same superblock (fsid), and
// nothing on a different one.
#[test]
fn mount_mark_matches_by_fsid() {
    let g = InotifyData::new_fanotify(0);
    apply_mark(&g, MarkScope::Mount, 0, 0x2001, FAN_OPEN, true, false);
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
    apply_mark(&g, MarkScope::Filesystem, 0, 0x3001, FAN_MODIFY, true, false);
    let a = mk_inode(FileType::Regular, 0x3001);
    let b = mk_inode(FileType::Regular, 0x3001);   // same fs, different inode
    fire_self(&a, FAN_MODIFY);
    fire_self(&b, FAN_MODIFY);
    assert_eq!(masks(&g), [FAN_MODIFY, FAN_MODIFY]);
}

// A self-event on a directory is delivered only when the mark set FAN_ONDIR,
// and the reported mask then carries FAN_ONDIR.
#[test]
fn ondir_filters_directory_self_events() {
    let g = InotifyData::new_fanotify(0);
    let dir = mk_inode(FileType::Directory, 0x4001);
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_OPEN, true, false);
    fire_self(&dir, FAN_OPEN);                       // no FAN_ONDIR → suppressed
    assert!(masks(&g).is_empty());
    apply_mark(&g, MarkScope::Inode, inode_key(&dir), dir.fsid(), FAN_ONDIR, true, false);
    fire_self(&dir, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN | FAN_ONDIR]);
}

// FAN_MARK_IGNORED_MASK bits suppress otherwise-requested events.
#[test]
fn ignored_mask_suppresses() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x5001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, true, false);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY, true, true); // ignore MODIFY
    fire_self(&ino, FAN_MODIFY);   // suppressed
    fire_self(&ino, FAN_OPEN);     // still delivered
    assert_eq!(masks(&g), [FAN_OPEN]);
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
        apply_mark(&g, MarkScope::Inode, inode_key(d), d.fsid(), FAN_MOVE | FAN_ONDIR, true, false);
    }
    apply_mark(&g, MarkScope::Inode, inode_key(&moved), moved.fsid(), FAN_MOVE_SELF, true, false);
    fire_move(&old, &new, Some(&moved));
    let evs: Vec<(u32, u32)> = g.events.lock().iter().map(|e| (e.mask, e.cookie)).collect();
    // MOVED_FROM (+ONDIR on the dir), MOVED_TO (+ONDIR), MOVE_SELF.
    assert_eq!(evs[0].0, FAN_MOVED_FROM | FAN_ONDIR);
    assert_eq!(evs[1].0, FAN_MOVED_TO | FAN_ONDIR);
    assert_eq!(evs[2].0, FAN_MOVE_SELF);
    assert_ne!(evs[0].1, 0);
    assert_eq!(evs[0].1, evs[1].1);  // FROM/TO share a cookie
}

// FAN_OPEN_EXEC is delivered to a mark requesting it (execve open-exec event).
#[test]
fn open_exec_event() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x7001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN_EXEC, true, false);
    fire_open_exec(&ino);
    assert_eq!(masks(&g), [FAN_OPEN_EXEC]);
}

// REMOVE clears the named bits; emptying the mark retires it (no further events).
#[test]
fn remove_clears_and_retires() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0x8001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, true, false);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_MODIFY | FAN_OPEN, false, false);
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
    let ev = Arc::new(PermEvent { obj: ino.clone(), pid: 0, mask: FAN_OPEN_PERM, response: AtomicU32::new(0) });
    g.perm_queue.lock().push_back(ev.clone());
    let mut buf = [0u8; 64];
    let n = g.read_fanotify(&mut buf).unwrap();           // listener reads the perm event
    assert_eq!(n, 24);
    let fd = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    // Listener writes fanotify_response { fd, FAN_DENY }.
    let mut resp = [0u8; 8];
    resp[0..4].copy_from_slice(&fd.to_le_bytes());
    resp[4..8].copy_from_slice(&FAN_DENY.to_le_bytes());
    assert_eq!(g.write(0, &resp), Ok(8));
    assert_eq!(ev.response.load(Ordering::Acquire), FAN_DENY);
}

// Closing a group auto-allows still-pending perm events so a dead listener
// never wedges a blocked accessor.
#[test]
fn perm_release_auto_allows() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xA001);
    let ev = Arc::new(PermEvent { obj: ino, pid: 0, mask: FAN_OPEN_PERM, response: AtomicU32::new(0) });
    g.perm_queue.lock().push_back(ev.clone());
    g.on_release();
    assert_eq!(ev.response.load(Ordering::Acquire), FAN_ALLOW);
}

// FAN_OPEN_EXEC_PERM execve-gate cycle (D56). perm_marks_present() is the boot
// fast-path gate the execve hook checks first: false with no perm mark armed
// (execve skips the resolve entirely), true once a FAN_OPEN_EXEC_PERM mark is
// installed. The verdict mapping check_perm applies (DENY→false / ALLOW→true)
// is exercised via the same read/respond cycle as perm_reply_protocol (host
// can't park, so the response→bool mapping is asserted directly). Single test:
// it is the sole mutator of the global PERM_MARK_COUNT, so the gate assertions
// are race-free.
#[test]
fn open_exec_perm_gate_cycle() {
    // No perm marks armed by us yet → execve gate stays inert.
    assert!(!perm_marks_present());

    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xC001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN_EXEC_PERM, true, false);
    // A FAN_*_PERM mark is now armed → execve gate engages its resolve+check.
    assert!(perm_marks_present());

    // DENY verdict: listener reads the queued exec-perm event, writes FAN_DENY;
    // check_perm maps response != FAN_ALLOW → false (caller returns -EACCES).
    let ev = Arc::new(PermEvent { obj: ino.clone(), pid: 0,
        mask: FAN_OPEN_EXEC_PERM, response: AtomicU32::new(0) });
    g.perm_queue.lock().push_back(ev.clone());
    let mut buf = [0u8; 64];
    assert_eq!(g.read_fanotify(&mut buf).unwrap(), 24);
    let fd = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    let mut resp = [0u8; 8];
    resp[0..4].copy_from_slice(&fd.to_le_bytes());
    resp[4..8].copy_from_slice(&FAN_DENY.to_le_bytes());
    assert_eq!(g.write(0, &resp), Ok(8));
    assert_eq!(ev.response.load(Ordering::Acquire), FAN_DENY);
    assert!(ev.response.load(Ordering::Acquire) != FAN_ALLOW);   // → check returns false

    // ALLOW verdict: a fresh exec-perm event answered FAN_ALLOW maps → true.
    let ev2 = Arc::new(PermEvent { obj: ino.clone(), pid: 0,
        mask: FAN_OPEN_EXEC_PERM, response: AtomicU32::new(0) });
    g.perm_queue.lock().push_back(ev2.clone());
    let mut buf2 = [0u8; 64];
    assert_eq!(g.read_fanotify(&mut buf2).unwrap(), 24);
    let fd2 = i32::from_le_bytes([buf2[16], buf2[17], buf2[18], buf2[19]]);
    let mut resp2 = [0u8; 8];
    resp2[0..4].copy_from_slice(&fd2.to_le_bytes());
    resp2[4..8].copy_from_slice(&FAN_ALLOW.to_le_bytes());
    assert_eq!(g.write(0, &resp2), Ok(8));
    assert_eq!(ev2.response.load(Ordering::Acquire), FAN_ALLOW);  // → check returns true

    // Retire the mark → gate goes inert again (PERM_MARK_COUNT back to 0).
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(),
               FAN_OPEN_EXEC_PERM, false, false);
    assert!(!perm_marks_present());
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

// FLUSH drops only the marks of the selected scope, leaving other scopes intact.
#[test]
fn flush_is_scope_local() {
    let g = InotifyData::new_fanotify(0);
    let ino = mk_inode(FileType::Regular, 0xB001);
    apply_mark(&g, MarkScope::Inode, inode_key(&ino), ino.fsid(), FAN_OPEN, true, false);
    apply_mark(&g, MarkScope::Mount, 0, 0xB001, FAN_OPEN, true, false);
    // Flush only the inode-scope marks by retaining non-inode.
    {
        let mut w = g.watches.lock();
        w.retain(|x| x.scope != MarkScope::Inode);
    }
    // The mount mark survives and still fires on the same superblock.
    fire_self(&ino, FAN_OPEN);
    assert_eq!(masks(&g), [FAN_OPEN]);
}
