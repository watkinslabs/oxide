// `fsnotify_change` hosted tests: the ATTR_* -> event-mask table and proof that
// the VFS setattr choke point actually drives it.
//
// Before this, IN_ATTRIB was fired from the chmod(2)/chown(2)/lchown(2) syscall
// slots only. aarch64 has none of those three slots, and glibc routes chmod()
// through fchmodat and chown() through fchownat on x86_64 too, so fchmod,
// fchown, fchmodat, fchownat, truncate, ftruncate and utimensat produced NO
// event at all. The fix is to fire once, from the single VFS setattr choke
// point every attribute change funnels through, which is where the hook now
// lives.
//
// Included as a child module of `inotify` via `#[path]`, so `use super::*`
// reaches the module-private dispatch items.

use super::*;
use alloc::vec::Vec;
use vfs::{ATTR_ATIME, ATTR_CTIME, ATTR_GID, ATTR_MODE, ATTR_MTIME, ATTR_SIZE, ATTR_UID};
use vfs::{Cred, FileType, Iattr, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

use crate::inotify::dispatch::{setattr_event_mask, vfs_setattr_notify};
use crate::inotify::syscalls::add_or_update_watch;
use crate::inotify::types::{inode_key, FAN_ATTRIB, IN_ACCESS, IN_ATTRIB, IN_MODIFY};

/// Distinct `fsid` per test keeps the shared INSTANCES list from cross-matching
/// tests running in parallel. # C: O(1)
fn mk_file(fsid: u64) -> InodeRef {
    InodeBuilder::new(0x5A00_0000 + fsid, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops())
        .fsid(fsid).owner(0, 0).build()
}

fn masks(g: &InotifyData) -> Vec<u32> { g.events.lock().iter().map(|e| e.mask).collect() }

fn root_cred() -> Cred {
    Cred {
        uid: 0, gid: 0, cap_dac_override: true, cap_dac_read_search: true,
        cap_fowner: true, cap_chown: true, cap_fsetid: true,
        groups: vfs::GroupList::empty(),
    }
}

// ---- the ATTR_* -> inotify event-mask table --------------------------------

#[test]
fn owner_and_mode_changes_are_attrib() {
    let _notify = crate::inotify::test_claim::claim_notify();
    assert_eq!(setattr_event_mask(ATTR_UID), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_GID), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_MODE), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_UID | ATTR_GID | ATTR_MODE), FAN_ATTRIB);
}

/// A size change is FS_MODIFY, NOT FS_ATTRIB — truncate reports as a content
/// change. The old per-syscall wiring had no size case at all.
#[test]
fn a_size_change_is_modify_not_attrib() {
    let _notify = crate::inotify::test_claim::claim_notify();
    assert_eq!(setattr_event_mask(ATTR_SIZE), IN_MODIFY);
    assert_eq!(setattr_event_mask(ATTR_SIZE) & FAN_ATTRIB, 0);
}

/// The three-way timestamp split: both together is a `utimes()` call (ATTRIB);
/// atime alone is ACCESS; mtime alone is MODIFY. Collapsing these to ATTRIB
/// would pass a naive "an event fired" test, so each arm is pinned.
#[test]
fn the_timestamp_split_matches_linux() {
    let _notify = crate::inotify::test_claim::claim_notify();
    assert_eq!(setattr_event_mask(ATTR_ATIME | ATTR_MTIME), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_ATIME), IN_ACCESS);
    assert_eq!(setattr_event_mask(ATTR_MTIME), IN_MODIFY);
    // ...and neither lone arm is ATTRIB.
    assert_eq!(setattr_event_mask(ATTR_ATIME) & FAN_ATTRIB, 0);
    assert_eq!(setattr_event_mask(ATTR_MTIME) & FAN_ATTRIB, 0);
}

/// `ATTR_CTIME` alone carries no event — Linux's map has no ctime arm, so a
/// setattr that only stamps ctime is silent.
#[test]
fn a_ctime_only_change_is_silent() {
    let _notify = crate::inotify::test_claim::claim_notify();
    assert_eq!(setattr_event_mask(ATTR_CTIME), 0);
    assert_eq!(setattr_event_mask(0), 0);
}

/// chown + truncate in one `notify_change` reports BOTH bits.
#[test]
fn a_combined_change_reports_every_applicable_bit() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let m = setattr_event_mask(ATTR_UID | ATTR_SIZE);
    assert_eq!(m & FAN_ATTRIB, FAN_ATTRIB);
    assert_eq!(m & IN_MODIFY, IN_MODIFY);
}

// ---- the wiring ------------------------------------------------------------

/// The subscriber queues one event per set bit, and a watch that asked for only
/// one of them receives only that one.
#[test]
fn the_subscriber_queues_one_event_per_bit() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let f = mk_file(0x5A01);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB | IN_MODIFY, false, None).unwrap();

    vfs_setattr_notify(&f, ATTR_UID | ATTR_SIZE);
    let m = masks(&g);
    assert!(m.contains(&IN_ATTRIB), "chown leg reported, got {m:?}");
    assert!(m.contains(&IN_MODIFY), "truncate leg reported, got {m:?}");
    assert_eq!(m.len(), 2, "exactly two events, got {m:?}");
}

#[test]
fn an_unrequested_bit_is_dropped() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let f = mk_file(0x5A02);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB, false, None).unwrap();

    vfs_setattr_notify(&f, ATTR_SIZE);           // MODIFY only — not watched
    assert_eq!(masks(&g), Vec::<u32>::new(), "a watch for ATTRIB gets no MODIFY");
    vfs_setattr_notify(&f, ATTR_MODE);
    assert_eq!(masks(&g), alloc::vec![IN_ATTRIB]);
}

/// THE regression guard: a real `notify_change` must reach the hook. This is
/// what was missing — the mapping could be perfect and still never run, which
/// is exactly how fchmod/fchownat/truncate ended up silent.
#[test]
fn notify_change_drives_the_hook() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let f = mk_file(0x5A03);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB, false, None).unwrap();
    vfs::set_setattr_hook(vfs_setattr_notify);

    let mut ia = Iattr { valid: ATTR_MODE, mode: 0o600, ..Default::default() };
    vfs::notify_change(&vfs::IDENTITY, &f, &mut ia, &root_cred()).expect("chmod applies");
    assert_eq!(masks(&g), alloc::vec![IN_ATTRIB],
        "notify_change fired fsnotify_change — this is the wiring that did not exist");
}

/// And a FAILED setattr fires nothing: Linux only calls `fsnotify_change` when
/// `i_op->setattr` returned 0.
#[test]
fn a_rejected_setattr_fires_nothing() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let f = mk_file(0x5A04);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB, false, None).unwrap();
    vfs::set_setattr_hook(vfs_setattr_notify);

    // Unprivileged, non-owner chmod of a root-owned file → EPERM in
    // `setattr_prepare`, so `i_op->setattr` never runs.
    let nobody = Cred {
        uid: 1000, gid: 1000, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    };
    let mut ia = Iattr { valid: ATTR_MODE, mode: 0o777, ..Default::default() };
    assert!(vfs::notify_change(&vfs::IDENTITY, &f, &mut ia, &nobody).is_err());
    assert_eq!(masks(&g), Vec::<u32>::new(), "a rejected setattr is silent");
}

// --- inotify_read shape ------------------------------------------------------
// `read` and `read_nonblock` are ONE Linux function differing only by the
// O_NONBLOCK arm, so every drain/short-buffer rule must hold identically on
// both. `read_nonblock` used to delegate to the blocking read, which is only
// safe while that read cannot sleep.

use crate::inotify::syscalls::add_or_update_watch as add_watch;
use crate::inotify::types::{Event as InEvent, IN_CREATE as IN_CREATE_BIT};

fn queue(g: &InotifyData, name: &[u8]) {
    g.enqueue_event(InEvent { wd: 1, mask: IN_CREATE_BIT, name: name.to_vec(),
        ..Default::default() });
}

/// `get_one_event` returns EINVAL only when the FIRST event cannot fit; the
/// tail rule (`if (start != buf) ret = buf - start`) means a later misfit
/// reports the bytes already copied. Both entry points, same answers.
#[test]
fn the_short_buffer_rule_is_identical_on_both_entry_points() {
    let _notify = crate::inotify::test_claim::claim_notify();
    for nonblock in [false, true] {
        let g = InotifyData::new(0);
        queue(&g, b"aaaa");   // 16 hdr + 16 padded name = 32
        let mut tiny = [0u8; 16];
        let r = if nonblock { g.read_nonblock(0, &mut tiny) } else { g.read(0, &mut tiny) };
        assert_eq!(r, Err(vfs::VfsError::Einval), "nothing copied yet -> EINVAL (nonblock={nonblock})");

        let g2 = InotifyData::new(0);
        queue(&g2, b"aaaa");
        queue(&g2, b"bbbbbbbbbbbbbbbbbbbb"); // needs 16 + 32 = 48
        let mut room = [0u8; 40];            // fits the first only
        let r2 = if nonblock { g2.read_nonblock(0, &mut room) } else { g2.read(0, &mut room) };
        assert_eq!(r2, Ok(32), "second event misfits AFTER a copy -> byte count, not EINVAL");
    }
}

/// An empty queue is EAGAIN on the O_NONBLOCK path. (Under hosted there is no
/// scheduler, so the blocking path cannot be exercised here — the boot is its
/// gate; see the `wait_for_event` comment.)
#[test]
fn an_empty_queue_is_eagain_on_the_nonblocking_path() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    assert_eq!(g.read_nonblock(0, &mut [0u8; 64]), Err(vfs::VfsError::Eagain));
}

/// One call drains every event that fits, as Linux's `continue` loop does.
#[test]
fn one_read_drains_every_event_that_fits() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    for n in [&b"one"[..], b"two", b"three"] { queue(&g, n); }
    let mut buf = [0u8; 256];
    let n = g.read_nonblock(0, &mut buf).expect("drains");
    assert_eq!(n, 32 * 3, "three 32-byte records in a single call");
    assert_eq!(g.read_nonblock(0, &mut buf), Err(vfs::VfsError::Eagain), "queue emptied");
}

/// A watch's events reach the reader through the same path (guards the
/// dispatch->queue->read chain, not just direct enqueues).
#[test]
fn a_watched_event_is_readable() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let f = mk_file(0x5A09);
    let wd = add_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB, false, None).unwrap();
    vfs_setattr_notify(&f, ATTR_MODE);
    let mut buf = [0u8; 64];
    let n = g.read_nonblock(0, &mut buf).expect("event readable");
    assert_eq!(n, 16, "nameless event = bare header");
    assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), wd);
}
