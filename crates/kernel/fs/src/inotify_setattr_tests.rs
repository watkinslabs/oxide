// `fsnotify_change` hosted tests: the ATTR_* -> event-mask table and proof that
// the VFS setattr choke point actually drives it.
//
// Before this, IN_ATTRIB was fired from the chmod(2)/chown(2)/lchown(2) syscall
// slots only. aarch64 has none of those three slots, and glibc routes chmod()
// through fchmodat and chown() through fchownat on x86_64 too, so fchmod,
// fchown, fchmodat, fchownat, truncate, ftruncate and utimensat produced NO
// event at all. Linux fires once, from `notify_change` (`fs/attr.c`), which is
// where the hook now lives.
//
// Included as a child module of `inotify` via `#[path]`, so `use super::*`
// reaches the module-private dispatch items.

use super::*;
use alloc::sync::Arc;
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

// ---- the Linux table (include/linux/fsnotify.h `fsnotify_change`) ----------

#[test]
fn owner_and_mode_changes_are_attrib() {
    assert_eq!(setattr_event_mask(ATTR_UID), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_GID), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_MODE), FAN_ATTRIB);
    assert_eq!(setattr_event_mask(ATTR_UID | ATTR_GID | ATTR_MODE), FAN_ATTRIB);
}

/// A size change is FS_MODIFY, NOT FS_ATTRIB — truncate reports as a content
/// change. The old per-syscall wiring had no size case at all.
#[test]
fn a_size_change_is_modify_not_attrib() {
    assert_eq!(setattr_event_mask(ATTR_SIZE), IN_MODIFY);
    assert_eq!(setattr_event_mask(ATTR_SIZE) & FAN_ATTRIB, 0);
}

/// The three-way timestamp split: both together is a `utimes()` call (ATTRIB);
/// atime alone is ACCESS; mtime alone is MODIFY. Collapsing these to ATTRIB
/// would pass a naive "an event fired" test, so each arm is pinned.
#[test]
fn the_timestamp_split_matches_linux() {
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
    assert_eq!(setattr_event_mask(ATTR_CTIME), 0);
    assert_eq!(setattr_event_mask(0), 0);
}

/// chown + truncate in one `notify_change` reports BOTH bits.
#[test]
fn a_combined_change_reports_every_applicable_bit() {
    let m = setattr_event_mask(ATTR_UID | ATTR_SIZE);
    assert_eq!(m & FAN_ATTRIB, FAN_ATTRIB);
    assert_eq!(m & IN_MODIFY, IN_MODIFY);
}

// ---- the wiring ------------------------------------------------------------

/// The subscriber queues one event per set bit, and a watch that asked for only
/// one of them receives only that one.
#[test]
fn the_subscriber_queues_one_event_per_bit() {
    let g = InotifyData::new(0);
    let f = mk_file(0x5A01);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB | IN_MODIFY).unwrap();

    vfs_setattr_notify(&f, ATTR_UID | ATTR_SIZE);
    let m = masks(&g);
    assert!(m.contains(&IN_ATTRIB), "chown leg reported, got {m:?}");
    assert!(m.contains(&IN_MODIFY), "truncate leg reported, got {m:?}");
    assert_eq!(m.len(), 2, "exactly two events, got {m:?}");
}

#[test]
fn an_unrequested_bit_is_dropped() {
    let g = InotifyData::new(0);
    let f = mk_file(0x5A02);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB).unwrap();

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
    let g = InotifyData::new(0);
    let f = mk_file(0x5A03);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB).unwrap();
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
    let g = InotifyData::new(0);
    let f = mk_file(0x5A04);
    add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_ATTRIB).unwrap();
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
