// Resource accounting, `IN_EXCL_UNLINK`, unmount teardown, and the fanotify
// FID-mode read record. Every uid used here is unique to its test: the ucount
// table is process-global and the hosted harness runs tests concurrently.

use super::*;
use alloc::vec::Vec;
use crate::inotify::marks::unmount_fs_marks;
use crate::inotify::fan_layout;
use vfs::fsnotify::{inc_ucount, max_queued_events, set_max_queued_events,
    set_max_user_watches, ucount, Ucount, INOTIFY_MIN_MAX_USER_WATCHES};
use vfs::{FileType, InodeBuilder, InodeRef, default_file_ops, mk_mode};

fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), default_file_ops())
        .build()
}

fn ev(wd: i32, mask: u32) -> Event {
    Event { wd, mask, cookie: 0, name: Vec::new(), obj: None, pid: 0, perm: None, mnt_id: 0 }
}

fn read_pair(g: &InotifyData) -> (i32, u32) {
    let mut buf = [0u8; 16];
    assert_eq!(g.read(0, &mut buf), Ok(16));
    (i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
     u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]))
}

#[test]
fn a_new_watch_past_the_per_user_ceiling_is_enospc() {
    let uid = 91_001;
    let g = InotifyData::new_owned(0, false, uid, 0);
    set_max_user_watches(2);
    assert!(add_or_update_watch(&g, 1, 0x10, IN_MODIFY, false).is_ok());
    assert!(add_or_update_watch(&g, 2, 0x10, IN_MODIFY, false).is_ok());
    assert_eq!(add_or_update_watch(&g, 3, 0x10, IN_MODIFY, false),
               Err(syscall::errno::Errno::Enospc), "over the ceiling is ENOSPC, not EINVAL/ENOMEM");
    assert_eq!(g.watches.lock().len(), 2, "the refused watch was not installed");
    // An UPDATE of an existing watch takes no new charge, so it still succeeds
    // while the user sits at their ceiling.
    assert!(add_or_update_watch(&g, 1, 0x10, IN_OPEN, false).is_ok());
    // Removing one frees exactly one slot.
    let wd = g.watches.lock()[0].wd;
    assert_eq!(remove_watch(&g, wd), Ok(()));
    assert!(add_or_update_watch(&g, 3, 0x10, IN_MODIFY, false).is_ok());
    drop(g);
    assert_eq!(ucount(uid, Ucount::InotifyWatches), 0, "the group's charges died with it");
    set_max_user_watches(INOTIFY_MIN_MAX_USER_WATCHES as i64);
}

#[test]
fn closing_a_group_returns_its_instance_and_watch_charges() {
    let uid = 91_002;
    assert!(inc_ucount(uid, Ucount::InotifyInstances), "stand in for the syscall's charge");
    let g = InotifyData::new_owned(0, false, uid, 0);
    add_or_update_watch(&g, 1, 0x10, IN_MODIFY, false).unwrap();
    add_or_update_watch(&g, 2, 0x10, IN_MODIFY, false).unwrap();
    assert_eq!(ucount(uid, Ucount::InotifyInstances), 1);
    assert_eq!(ucount(uid, Ucount::InotifyWatches), 2);
    drop(g);
    assert_eq!(ucount(uid, Ucount::InotifyInstances), 0);
    assert_eq!(ucount(uid, Ucount::InotifyWatches), 0);
}

#[test]
fn a_fanotify_group_charges_marks_not_watches() {
    let uid = 91_003;
    let g = InotifyData::new_owned(0, true, uid, 0);
    assert_eq!(apply_mark(&g, MarkScope::Inode, 7, 0x10, FAN_OPEN, true, false, 0), 0);
    assert_eq!(ucount(uid, Ucount::FanotifyMarks), 1);
    assert_eq!(ucount(uid, Ucount::InotifyWatches), 0, "fanotify marks use their own ceiling");
    // Removing the last bit retires the mark and releases the charge.
    assert_eq!(apply_mark(&g, MarkScope::Inode, 7, 0x10, FAN_OPEN, false, false, 0), 0);
    assert_eq!(ucount(uid, Ucount::FanotifyMarks), 0);
    drop(g);
}

#[test]
fn fan_unlimited_marks_exempts_a_group_from_the_mark_account() {
    let uid = 91_004;
    // FAN_UNLIMITED_MARKS.
    let g = InotifyData::new_owned(0x0000_0020, true, uid, 0);
    assert_eq!(apply_mark(&g, MarkScope::Inode, 7, 0x10, FAN_OPEN, true, false, 0), 0);
    assert_eq!(ucount(uid, Ucount::FanotifyMarks), 0, "an unlimited group contributes nothing");
    drop(g);
}

#[test]
fn the_queue_depth_is_snapshot_at_group_creation() {
    let saved = max_queued_events();
    set_max_queued_events(2);
    let g = InotifyData::new_owned(0, false, 91_005, 0);
    // A later sysctl write must not resize a live group's queue.
    set_max_queued_events(4096);
    for i in 0..2 { g.enqueue_event(ev(i as i32 + 1, IN_OPEN)); }
    g.enqueue_event(ev(9, IN_MODIFY));
    let q = g.events.lock();
    assert_eq!(q.len(), 3, "two events plus the overflow marker");
    assert_eq!(q.back().map(|e| (e.wd, e.mask)), Some((-1, IN_Q_OVERFLOW)),
               "the overflow record is wd = -1");
    drop(q);
    drop(g);
    set_max_queued_events(saved);
}

#[test]
fn excl_unlink_suppresses_path_events_on_an_unlinked_file_only() {
    let g = InotifyData::new_owned(0, false, 91_006, 0);
    let f = file(600_001);
    let wd = add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_MODIFY | IN_EXCL_UNLINK, false).unwrap();
    // Still linked: delivered.
    fire_self_path(&f, IN_MODIFY, false);
    assert_eq!(read_pair(&g), (wd, IN_MODIFY));
    // Unlinked while still open: dropped.
    fire_self_path(&f, IN_MODIFY, true);
    assert_eq!(g.read(0, &mut [0u8; 16]), Err(vfs::VfsError::Eagain));
    // An event with NO path reaches the mark even after the unlink — Linux's
    // guard short-circuits on a NULL path.
    fire_self(&f, IN_MODIFY);
    assert_eq!(read_pair(&g), (wd, IN_MODIFY));
    drop(g);
}

#[test]
fn without_excl_unlink_an_unlinked_files_events_still_arrive() {
    let g = InotifyData::new_owned(0, false, 91_007, 0);
    let f = file(600_002);
    let wd = add_or_update_watch(&g, inode_key(&f), f.fsid(), IN_MODIFY, false).unwrap();
    fire_self_path(&f, IN_MODIFY, true);
    assert_eq!(read_pair(&g), (wd, IN_MODIFY));
    drop(g);
}

#[test]
fn unmount_reports_in_unmount_then_in_ignored_and_frees_the_wd() {
    let g = InotifyData::new_owned(0, false, 91_008, 0);
    // Only IN_MODIFY was requested; IN_UNMOUNT arrives regardless.
    let wd = add_or_update_watch(&g, 600_003, 0xCC, IN_MODIFY, false).unwrap();
    unmount_fs_marks(0xCC);
    assert_eq!(read_pair(&g), (wd, IN_UNMOUNT), "the unmount notice comes first");
    assert_eq!(read_pair(&g), (wd, IN_IGNORED), "then the watch's death record");
    assert!(g.watches.lock().is_empty());
    assert_eq!(remove_watch(&g, wd), Err(syscall::errno::Errno::Einval),
               "the wd is gone, exactly as after an explicit remove");
    drop(g);
}

#[test]
fn unmount_leaves_marks_on_other_filesystems_alone() {
    let g = InotifyData::new_owned(0, false, 91_009, 0);
    let a = file(600_004);
    add_or_update_watch(&g, 4_001, 0xAA, IN_MODIFY, false).unwrap();
    let keep = add_or_update_watch(&g, 4_002, 0xBB, IN_MODIFY, false).unwrap();
    let _ = a;
    unmount_fs_marks(0xAA);
    let live: Vec<i32> = g.watches.lock().iter().map(|w| w.wd).collect();
    assert_eq!(live, alloc::vec![keep]);
    drop(g);
}

#[test]
fn a_fid_mode_group_reports_a_file_handle_and_no_descriptor() {
    // FAN_REPORT_FID.
    let g = InotifyData::new_owned(0x0000_0200, true, 91_010, 0);
    let f = file(0x4242);
    g.enqueue_event(Event { wd: 1, mask: FAN_OPEN, cookie: 0, name: Vec::new(),
                            obj: Some(f.clone()), pid: 77, perm: None, mnt_id: 0 });
    let mut buf = [0u8; 128];
    let n = g.read_fanotify(&mut buf).unwrap();
    let want = fan_layout::FAN_EVENT_METADATA_LEN + fan_layout::fid_info_len(fan_layout::FANOTIFY_FID_LEN, 0);
    assert_eq!(n, want, "metadata plus one FID info record");
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), want as u32,
               "event_len covers the info record");
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), FAN_OPEN as u64);
    assert_eq!(i32::from_le_bytes(buf[16..20].try_into().unwrap()), fan_layout::FAN_NOFD,
               "a fid-mode group reports no fd");
    assert_eq!(i32::from_le_bytes(buf[20..24].try_into().unwrap()), 77);
    let info = &buf[24..want];
    assert_eq!(info[0], fan_layout::FAN_EVENT_INFO_TYPE_FID);
    assert_eq!(u16::from_le_bytes([info[2], info[3]]), fan_layout::fid_info_len(fan_layout::FANOTIFY_FID_LEN, 0) as u16);
    assert_eq!(u32::from_le_bytes(info[12..16].try_into().unwrap()),
               fan_layout::FANOTIFY_FID_LEN as u32, "handle_bytes");
    assert_eq!(i32::from_le_bytes(info[16..20].try_into().unwrap()), fan_layout::FANOTIFY_FID_TYPE);
    // The handle is the one `open_by_handle_at` decodes, not a private
    // fanotify encoding — a reported fid a watcher cannot open is useless.
    let fid = vfs::export::fid::decode_fid(&info[20..20 + fan_layout::FANOTIFY_FID_LEN],
                                           fan_layout::FANOTIFY_FID_TYPE).expect("decodes");
    assert_eq!(fid.ino, 0x4242, "handle carries the ino");
    assert_eq!(fid.parent, None);
    drop(g);
}

#[test]
fn a_dir_fid_name_group_reports_the_entry_name() {
    // FAN_REPORT_DIR_FID | FAN_REPORT_NAME.
    let g = InotifyData::new_owned(0x0000_0400 | 0x0000_0800, true, 91_011, 0);
    let d = file(0x99);
    g.enqueue_event(Event { wd: 1, mask: FAN_CREATE, cookie: 0, name: b"kid".to_vec(),
                            obj: Some(d.clone()), pid: 5, perm: None, mnt_id: 0 });
    let mut buf = [0u8; 128];
    let n = g.read_fanotify(&mut buf).unwrap();
    let want = fan_layout::FAN_EVENT_METADATA_LEN + fan_layout::fid_info_len(fan_layout::FANOTIFY_FID_LEN, 3);
    assert_eq!(n, want);
    let info = &buf[24..want];
    assert_eq!(info[0], fan_layout::FAN_EVENT_INFO_TYPE_DFID_NAME);
    let nm = 20 + fan_layout::FANOTIFY_FID_LEN;
    assert_eq!(&info[nm..nm + 3], b"kid");
    assert_eq!(info[nm + 3], 0, "the name is NUL-terminated");
    drop(g);
}

#[test]
fn a_fanotify_buffer_too_small_for_the_first_event_is_einval() {
    let g = InotifyData::new_owned(0x0000_0200, true, 91_012, 0);
    g.enqueue_event(Event { wd: 1, mask: FAN_OPEN, cookie: 0, name: Vec::new(),
                            obj: Some(file(3)), pid: 0, perm: None, mnt_id: 0 });
    // Room for the metadata but not the info record that follows it.
    let mut small = [0u8; fan_layout::FAN_EVENT_METADATA_LEN];
    assert_eq!(g.read_fanotify(&mut small), Err(vfs::VfsError::Einval));
    // The event was not consumed.
    let mut big = [0u8; 128];
    assert!(g.read_fanotify(&mut big).is_ok());
    drop(g);
}

#[test]
fn a_legacy_fanotify_group_still_emits_bare_metadata() {
    let g = InotifyData::new_owned(0, true, 91_013, 0);
    g.enqueue_event(Event { wd: 1, mask: FAN_OPEN, cookie: 0, name: Vec::new(), obj: None, pid: 3, perm: None, mnt_id: 0 });
    let mut buf = [0u8; 128];
    assert_eq!(g.read_fanotify(&mut buf), Ok(fan_layout::FAN_EVENT_METADATA_LEN));
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()),
               fan_layout::FAN_EVENT_METADATA_LEN as u32);
    assert_eq!(buf[4], fan_layout::FANOTIFY_METADATA_VERSION);
    drop(g);
}
