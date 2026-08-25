use super::*;

#[test]
fn empty_inotify_is_eagain_and_not_pollable() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let ino = InotifyData::new(0);
    let mut buf = [0u8; 64];
    assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
    assert_eq!(ino.poll(), 0);
}

// With an event queued, poll() is readable and read() drains a
// 16-byte inotify_event; a second read returns to EAGAIN.
#[test]
fn queued_event_is_readable_then_drains_to_eagain() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let ino = InotifyData::new(0);
    let before = ino.poll_subs.generation();
    ino.enqueue_event(Event { wd: 1, mask: IN_MODIFY, cookie: 0, name: alloc::vec::Vec::new(), obj: None, pid: 0, ..Default::default() });
    assert!(ino.poll_subs.generation() > before, "queued inotify event wakes epoll subscribers");
    assert_eq!(ino.poll(), vfs::POLL_IN);
    let mut buf = [0u8; 64];
    assert_eq!(ino.read(0, &mut buf), Ok(16));
    assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);
    assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), IN_MODIFY);
    assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
    assert_eq!(ino.poll(), 0);
}

// ---------------------------------------------------------------------------
// `struct inotify_event` name tail (Linux `copy_event_to_user`).
// ---------------------------------------------------------------------------

/// Split one drained buffer into `(wd, mask, cookie, name)` records, walking
/// the VARIABLE-length layout the same way a real reader must.

fn directory_watch_reports_which_entry_changed() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let (d, wd) = watched_dir(&g, 0x7101, IN_CREATE | IN_DELETE);
    fire_child(&d, IN_CREATE, 0, "hello.txt", false);
    fire_child(&d, IN_DELETE, 0, "hello.txt", false);

    let mut buf = [0u8; 256];
    let n = g.read(0, &mut buf).unwrap();
    let evs = parse_events(&buf, n);
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0], (wd, IN_CREATE, 0, b"hello.txt".to_vec()));
    assert_eq!(evs[1], (wd, IN_DELETE, 0, b"hello.txt".to_vec()));
    // 9-byte name + NUL rounds to one 16-byte header ⇒ 32 bytes per record.
    assert_eq!(n, 64, "two 32-byte records");
}

#[test]
fn a_directory_entry_sets_in_isdir_but_a_file_entry_does_not() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let (d, _) = watched_dir(&g, 0x7102, IN_CREATE);
    fire_child(&d, IN_CREATE, 0, "file", false);
    fire_child(&d, IN_CREATE, 0, "subdir", true);

    let mut buf = [0u8; 256];
    let n = g.read(0, &mut buf).unwrap();
    let evs = parse_events(&buf, n);
    assert_eq!(evs[0].1, IN_CREATE, "regular entry: no IN_ISDIR");
    assert_eq!(evs[1].1, IN_CREATE | IN_ISDIR, "directory entry: IN_ISDIR set");
}

#[test]
fn delete_self_and_move_self_never_carry_in_isdir() {
    let _notify = crate::inotify::test_claim::claim_notify();
    // Linux `inotify_handle_inode_event` masks IN_ISDIR out of exactly these
    // two, deliberately, to avoid breaking existing inotify programs.
    let g = InotifyData::new(0);
    let d = dir(0x7103, 0o755, 0, &[]);
    add_or_update_watch(&g, inode_key(&d), d.fsid(), IN_ATTRIB | FAN_DELETE_SELF | FAN_MOVE_SELF, true, None).unwrap();
    fire_self(&d, FAN_ATTRIB);
    fire_self(&d, FAN_DELETE_SELF);
    fire_self(&d, FAN_MOVE_SELF);

    let mut buf = [0u8; 256];
    let n = g.read(0, &mut buf).unwrap();
    let evs = parse_events(&buf, n);
    assert_eq!(evs[0].1, IN_ATTRIB | IN_ISDIR, "a dir's own attrib event does carry IN_ISDIR");
    assert_eq!(evs[1].1, FAN_DELETE_SELF);
    assert_eq!(evs[2].1, FAN_MOVE_SELF);
    for e in &evs { assert!(e.3.is_empty(), "self events carry no name"); }
}

#[test]
fn rename_names_both_halves_under_one_cookie() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let (from, from_wd) = watched_dir(&g, 0x7104, IN_MOVED_FROM);
    let (to, to_wd) = watched_dir(&g, 0x7105, IN_MOVED_TO);
    let moved = reg(0x7106, 0o644, 0);
    fire_move(&from, &to, Some(&moved), "old-name", "new-name");

    let mut buf = [0u8; 256];
    let n = g.read(0, &mut buf).unwrap();
    let evs = parse_events(&buf, n);
    assert_eq!(evs.len(), 2);
    assert_eq!((evs[0].0, evs[0].1, &evs[0].3[..]), (from_wd, IN_MOVED_FROM, &b"old-name"[..]));
    assert_eq!((evs[1].0, evs[1].1, &evs[1].3[..]), (to_wd, IN_MOVED_TO, &b"new-name"[..]));
    assert_ne!(evs[0].2, 0);
    assert_eq!(evs[0].2, evs[1].2, "one cookie pairs the halves");
}

#[test]
fn a_buffer_too_small_for_the_next_whole_event_is_einval_not_a_partial_event() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let (d, _) = watched_dir(&g, 0x7107, IN_CREATE);
    fire_child(&d, IN_CREATE, 0, "abcd", false);   // needs 16 + 16 = 32 bytes

    let mut small = [0xAAu8; 31];
    assert_eq!(g.read(0, &mut small), Err(vfs::VfsError::Einval),
               "Linux get_one_event returns ERR_PTR(-EINVAL) when the event cannot fit");
    assert_eq!(small, [0xAAu8; 31], "no partial event was written");

    // The event is still queued and comes out whole in an adequate buffer.
    let mut ok = [0u8; 32];
    assert_eq!(g.read(0, &mut ok), Ok(32));
    assert_eq!(parse_events(&ok, 32)[0].3, b"abcd".to_vec());
}

#[test]
fn a_short_buffer_after_a_successful_copy_returns_the_bytes_copied() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let (d, _) = watched_dir(&g, 0x7108, IN_CREATE);
    fire_child(&d, IN_CREATE, 0, "one", false);
    fire_child(&d, IN_CREATE, 0, "two", false);

    // Room for exactly one 32-byte record: the first is copied, the second
    // stays queued (Linux `inotify_read`: `if (start != buf) ret = buf - start`).
    let mut buf = [0u8; 40];
    assert_eq!(g.read(0, &mut buf), Ok(32));
    assert_eq!(parse_events(&buf, 32)[0].3, b"one".to_vec());
    let mut rest = [0u8; 64];
    let n = g.read(0, &mut rest).unwrap();
    assert_eq!(parse_events(&rest, n)[0].3, b"two".to_vec());
}

