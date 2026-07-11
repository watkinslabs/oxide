use super::*;

#[test]
fn inotify_init_flags_match_linux() {
    assert_eq!(validate_inotify_init_flags(0), Ok(()));
    assert_eq!(validate_inotify_init_flags(0o0_004_000), Ok(()));
    assert_eq!(validate_inotify_init_flags(0o2_000_000), Ok(()));
    assert_eq!(validate_inotify_init_flags(0o2_004_000), Ok(()));
    assert_eq!(validate_inotify_init_flags(1), Err(syscall::errno::Errno::Einval));
    assert_eq!(validate_inotify_init_flags(0x8000_0000), Err(syscall::errno::Errno::Einval));
}

#[test]
fn legacy_inotify_init_ignores_a0() {
    let args = syscall::SyscallArgs { a0: 1, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
    assert_eq!(sys_inotify_init(&args), -(syscall::errno::Errno::Ebadf.as_i32() as i64));
    assert_eq!(sys_inotify_init1(&args), -(syscall::errno::Errno::Einval.as_i32() as i64));
}

#[test]
fn inotify_add_watch_mask_validation_matches_linux_ordering_units() {
    assert_eq!(validate_inotify_watch_mask_bits(IN_MODIFY), Ok(()));
    assert_eq!(validate_inotify_watch_mask_bits(0), Err(syscall::errno::Errno::Einval));
    assert_eq!(validate_inotify_watch_mask_bits(0x0080_0000), Err(syscall::errno::Errno::Einval));
    assert_eq!(validate_inotify_watch_mask_bits(0x0100_0000), Ok(()));

    assert_eq!(validate_inotify_watch_mask_after_fd(IN_MODIFY), Ok(()));
    assert_eq!(
        validate_inotify_watch_mask_after_fd(0x1000_0000 | 0x2000_0000),
        Err(syscall::errno::Errno::Einval),
    );
}

#[test]
fn inotify_add_watch_create_replace_and_add_semantics() {
    let g = InotifyData::new(0);
    let key = 0xabcdusize;
    let wd = add_or_update_watch(&g, key, 0x44, IN_MODIFY).unwrap();
    assert_eq!(wd, 1);
    assert_eq!(g.watches.lock()[0].mask, IN_MODIFY);

    let same = add_or_update_watch(&g, key, 0x44, IN_OPEN).unwrap();
    assert_eq!(same, wd);
    assert_eq!(g.watches.lock()[0].mask, IN_OPEN);

    let same = add_or_update_watch(&g, key, 0x44, IN_MODIFY | 0x2000_0000).unwrap();
    assert_eq!(same, wd);
    assert_eq!(g.watches.lock()[0].mask, IN_OPEN | IN_MODIFY);

    assert_eq!(
        add_or_update_watch(&g, key, 0x44, IN_ATTRIB | 0x1000_0000),
        Err(syscall::errno::Errno::Eexist),
    );
    assert_eq!(g.watches.lock()[0].mask, IN_OPEN | IN_MODIFY);

    let flags_only = add_or_update_watch(&g, 0xbeefusize, 0x44, 0x0100_0000).unwrap();
    assert_eq!(flags_only, 2);
    assert_eq!(g.watches.lock()[1].mask, 0);
}

// An empty inotify fd is EAGAIN (would-block), never EOF(0), and
// poll() reports not-readable — else an epoll-driven reader spins.
#[test]
fn empty_inotify_is_eagain_and_not_pollable() {
    let ino = InotifyData::new(0);
    let mut buf = [0u8; 64];
    assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
    assert_eq!(ino.poll(), 0);
}

// With an event queued, poll() is readable and read() drains a
// 16-byte inotify_event; a second read returns to EAGAIN.
#[test]
fn queued_event_is_readable_then_drains_to_eagain() {
    let ino = InotifyData::new(0);
    ino.events.lock().push_back(Event { wd: 1, mask: IN_MODIFY, cookie: 0, len: 0, obj: None, pid: 0 });
    assert_eq!(ino.poll(), vfs::POLL_IN);
    let mut buf = [0u8; 64];
    assert_eq!(ino.read(0, &mut buf), Ok(16));
    assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);
    assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), IN_MODIFY);
    assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
    assert_eq!(ino.poll(), 0);
}
