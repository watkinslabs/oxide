use super::*;

#[test]
fn inotify_watch_path_resolution_matches_linux_permission_shape() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let public = reg(3, 0o644, 0);
    let private = reg(4, 0o600, 0);
    let subdir = dir(5, 0o755, 0, &[]);
    let root_inode = dir(1, 0o755, 0, &[
        ("public", public.clone()),
        ("private", private),
        ("subdir", subdir),
    ]);
    let root = Dentry::new_root(root_inode);
    let user = cred(1000);

    assert!(Arc::ptr_eq(
        &resolve_watch_path_at(root.clone(), 0, root.clone(), 0, "/public", false, false, user.clone()).unwrap(),
        &public,
    ));
    assert_eq!(path_err(resolve_watch_path_at(root.clone(), 0, root.clone(), 0, "/private", false, false, user.clone())), errno(syscall::errno::Errno::Eacces));
    assert_eq!(path_err(resolve_watch_path_at(root.clone(), 0, root.clone(), 0, "/missing", false, false, user.clone())), errno(syscall::errno::Errno::Enoent));
    assert_eq!(path_err(resolve_watch_path_at(root.clone(), 0, root, 0, "/public", false, true, user.clone())), errno(syscall::errno::Errno::Enotdir));
}

#[test]
fn inotify_init_flags_match_linux() {
    let _notify = crate::inotify::test_claim::claim_notify();
    assert_eq!(validate_inotify_init_flags(0), Ok(()));
    assert_eq!(validate_inotify_init_flags(0o0_004_000), Ok(()));
    assert_eq!(validate_inotify_init_flags(0o2_000_000), Ok(()));
    assert_eq!(validate_inotify_init_flags(0o2_004_000), Ok(()));
    assert_eq!(validate_inotify_init_flags(1), Err(syscall::errno::Errno::Einval));
    assert_eq!(validate_inotify_init_flags(0x8000_0000), Err(syscall::errno::Errno::Einval));
}

#[test]
fn legacy_inotify_init_ignores_a0() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let args = syscall::SyscallArgs { a0: 1, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 };
    assert_eq!(sys_inotify_init(&args), -(syscall::errno::Errno::Ebadf.as_i32() as i64));
    assert_eq!(sys_inotify_init1(&args), -(syscall::errno::Errno::Einval.as_i32() as i64));
}

#[test]
fn inotify_add_watch_mask_validation_matches_linux_ordering_units() {
    let _notify = crate::inotify::test_claim::claim_notify();
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
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let key = 0xabcdusize;
    let wd = add_or_update_watch(&g, key, 0x44, IN_MODIFY, false, None).unwrap();
    assert_eq!(wd, 1);
    assert_eq!(g.watches.lock()[0].mask, IN_MODIFY);

    let same = add_or_update_watch(&g, key, 0x44, IN_OPEN, false, None).unwrap();
    assert_eq!(same, wd);
    assert_eq!(g.watches.lock()[0].mask, IN_OPEN);

    let same = add_or_update_watch(&g, key, 0x44, IN_MODIFY | 0x2000_0000, false, None).unwrap();
    assert_eq!(same, wd);
    assert_eq!(g.watches.lock()[0].mask, IN_OPEN | IN_MODIFY);

    assert_eq!(
        add_or_update_watch(&g, key, 0x44, IN_ATTRIB | 0x1000_0000, false, None),
        Err(syscall::errno::Errno::Eexist),
    );
    assert_eq!(g.watches.lock()[0].mask, IN_OPEN | IN_MODIFY);

    let flags_only = add_or_update_watch(&g, 0xbeefusize, 0x44, 0x0100_0000, false, None).unwrap();
    assert_eq!(flags_only, 2);
    assert_eq!(g.watches.lock()[1].mask, 0);
}

#[test]
fn inotify_oneshot_removes_watch_and_queues_ignored() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let ino = InotifyData::new(0);
    let file = reg(6, 0o644, 0);
    let wd = add_or_update_watch(&ino, inode_key(&file), file.fsid(), IN_MODIFY | IN_ONESHOT, false, None).unwrap();
    fire_self(&file, IN_MODIFY);
    assert_eq!(ino.watches.lock().len(), 0);
    assert_eq!(read_event_pair(&ino), (wd, IN_MODIFY));
    assert_eq!(read_event_pair(&ino), (wd, IN_IGNORED));
    fire_self(&file, IN_MODIFY);
    assert_eq!(ino.read(0, &mut [0u8; 16]), Err(vfs::VfsError::Eagain));
}

#[test]
fn inotify_remove_watch_queues_ignored_and_rejects_missing_wd() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let ino = InotifyData::new(0);
    let wd = add_or_update_watch(&ino, 0xcafeusize, 0x44, IN_OPEN, false, None).unwrap();
    assert_eq!(remove_watch(&ino, wd), Ok(()));
    assert_eq!(read_event_pair(&ino), (wd, IN_IGNORED));
    assert_eq!(remove_watch(&ino, wd), Err(syscall::errno::Errno::Einval));
}

#[test]
fn file_event_admission_uses_attached_inode_and_parent_marks() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let g = InotifyData::new(0);
    let parent_inode = dir(0x6200, 0o755, 0, &[]);
    let watched = reg(0x6201, 0o644, 0);
    let unrelated = reg(0x6202, 0o644, 0);
    let root = Dentry::new_root(parent_inode.clone());
    let watched_dentry = Dentry::new_child(&root, "watched", Some(watched.clone()));
    let unrelated_dentry = Dentry::new_child(&root, "unrelated", Some(unrelated.clone()));

    let direct_wd = add_or_update_watch(&g, inode_key(&watched), watched.fsid(),
                                        IN_ACCESS, false, Some(&watched)).unwrap();
    assert!(watched.fsnotify_has_mask(IN_ACCESS));
    assert!(!unrelated.fsnotify_has_mask(IN_ACCESS));
    crate::inotify::dispatch::fire_with_parent_for_test(&unrelated, IN_ACCESS, &unrelated_dentry);
    assert_eq!(g.read(0, &mut [0u8; 64]), Err(vfs::VfsError::Eagain));
    crate::inotify::dispatch::fire_with_parent_for_test(&watched, IN_ACCESS, &watched_dentry);
    assert_eq!(read_event_pair(&g), (direct_wd, IN_ACCESS));

    let parent_wd = add_or_update_watch(&g, inode_key(&parent_inode), parent_inode.fsid(),
                                        IN_MODIFY, true, Some(&parent_inode)).unwrap();
    crate::inotify::dispatch::fire_with_parent_for_test(&unrelated, IN_MODIFY, &unrelated_dentry);
    let mut buf = [0u8; 64];
    let n = g.read(0, &mut buf).unwrap();
    let events = parse_events(&buf, n);
    assert_eq!(events, alloc::vec![(parent_wd, IN_MODIFY, 0, b"unrelated".to_vec())]);

    add_or_update_watch(&g, inode_key(&watched), watched.fsid(),
                        IN_OPEN, false, Some(&watched)).unwrap();
    assert!(!watched.fsnotify_has_mask(IN_ACCESS));
    assert!(watched.fsnotify_has_mask(IN_OPEN));
    remove_watch(&g, direct_wd).unwrap();
    assert!(!watched.fsnotify_has_mask(IN_OPEN));
    remove_watch(&g, parent_wd).unwrap();
    assert!(!parent_inode.fsnotify_has_mask(IN_MODIFY | FAN_EVENT_ON_CHILD));
}

#[test]
fn inotify_queue_overflow_reports_single_overflow_event() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let ino = InotifyData::new(0);
    // Distinct wds: identical consecutive records are MERGED into the tail
    // (Linux `inotify_merge`), so a run of clones would never fill the queue.
    for i in 0..INOTIFY_DEFAULT_MAX_QUEUED_EVENTS {
        ino.enqueue_event(Event { wd: i as i32, mask: IN_OPEN, cookie: 0, name: alloc::vec::Vec::new(), obj: None, pid: 0, ..Default::default() });
    }
    ino.enqueue_event(Event { wd: 1, mask: IN_MODIFY, cookie: 0, name: alloc::vec::Vec::new(), obj: None, pid: 0, ..Default::default() });
    ino.enqueue_event(Event { wd: 1, mask: IN_ATTRIB, cookie: 0, name: alloc::vec::Vec::new(), obj: None, pid: 0, ..Default::default() });
    let q = ino.events.lock();
    assert_eq!(q.len(), INOTIFY_DEFAULT_MAX_QUEUED_EVENTS + 1);
    assert_eq!(q.back().map(|e| (e.wd, e.mask)), Some((-1, IN_Q_OVERFLOW)));
    assert_eq!(q.iter().filter(|e| (e.mask & IN_Q_OVERFLOW) != 0).count(), 1);
}


