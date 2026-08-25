use super::*;

fn fanotify_init_validation_matches_linux_ordering_units() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let einval = syscall::errno::Errno::Einval.as_i32();
    let eperm = syscall::errno::Errno::Eperm.as_i32();

    assert_eq!(init_args(0, 0, false, false), eperm);
    assert_eq!(validate_fanotify_init(FAN_REPORT_DIR_FID), 0);
    assert_eq!(init_args(FAN_REPORT_DIR_FID, 0, false, false), 0);
    assert_eq!(init_args(FAN_CLASS_CONTENT, 0, false, false), eperm);

    assert_eq!(init_args(0x8000_0000, 0, true, true), einval);
    assert_eq!(init_args(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT, 0, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_NAME, 0, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_DIR_FID | FAN_REPORT_NAME, 0, true, true), 0);
    assert_eq!(
        init_args(FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID, 0, true, true),
        einval,
    );
    assert_eq!(
        init_args(
            FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID,
            0,
            true,
            true,
        ),
        0,
    );

    assert_eq!(init_args(FAN_REPORT_MNT | FAN_CLASS_CONTENT, 0, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_MNT | FAN_REPORT_FID, 0, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_MNT | FAN_REPORT_FD_ERROR, 0, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_MNT, 0, false, false), 0);
    assert_eq!(init_args(FAN_REPORT_DIR_FID | FAN_ENABLE_AUDIT, 0, true, false), eperm);
    assert_eq!(init_args(FAN_REPORT_DIR_FID | FAN_ENABLE_AUDIT, 0, true, true), 0);

    assert_eq!(init_args(FAN_REPORT_DIR_FID, 0o3, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_DIR_FID, 0x8000_0000, true, true), einval);
    assert_eq!(init_args(FAN_REPORT_DIR_FID, 0o4000 | 0o2, true, true), 0);
}

#[test]
fn fanotify_mark_prefd_validation_matches_linux_units() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let einval = syscall::errno::Errno::Einval;

    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_ADD, FAN_OPEN as u64), Ok(()));
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_FS_ERROR as u64), Ok(()));
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_ADD, 1u64 << 32), Err(einval));
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_ADD | FAN_MARK_REMOVE, FAN_OPEN as u64), Err(einval));
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_ADD, 0), Err(einval));
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_FLUSH | FAN_MARK_ONLYDIR, 0), Err(einval));
    assert_eq!(
        validate_fanotify_mark_prefd(FAN_MARK_ADD | FAN_MARK_MNTNS, FAN_OPEN as u64),
        Ok(()),
    );
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_MOUNT | 0x0000_0200, FAN_OPEN as u64), Err(einval));
    assert_eq!(validate_fanotify_mark_prefd(FAN_MARK_ADD, 0x0000_4000), Err(einval));
    assert_eq!(
        validate_fanotify_mark_prefd(FAN_MARK_ADD | FAN_MARK_IGNORE | FAN_MARK_IGNORED_MASK, FAN_OPEN as u64),
        Err(einval),
    );
}

#[test]
fn fanotify_mark_group_validation_matches_linux_units() {
    let _notify = crate::inotify::test_claim::claim_notify();
    let einval = syscall::errno::Errno::Einval;
    let ino = InotifyData::new(0);
    assert_eq!(
        validate_fanotify_mark_group(&ino, MarkScope::Inode, FAN_OPEN, FAN_MARK_ADD, true),
        Err(einval),
    );

    let notif = InotifyData::new_fanotify(0);
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_OPEN_PERM, FAN_MARK_ADD, true),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_FS_ERROR, FAN_MARK_ADD, true),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Mount, FAN_OPEN, FAN_MARK_ADD | FAN_MARK_EVICTABLE, true),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_RENAME, FAN_MARK_ADD, true),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_MNT_ATTACH, FAN_MARK_ADD, true),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::MountNamespace, FAN_MNT_ATTACH, FAN_MARK_ADD, true),
        Err(einval),
    );

    let content = InotifyData::new_fanotify(FAN_CLASS_CONTENT);
    assert_eq!(validate_fanotify_mark_group(&content, MarkScope::Inode, FAN_OPEN_PERM, FAN_MARK_ADD, true), Ok(()));
    assert_eq!(
        validate_fanotify_mark_group(&content, MarkScope::Inode, FAN_PRE_ACCESS, FAN_MARK_ADD, true),
        Err(einval),
    );

    let fid = InotifyData::new_fanotify(FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_FID);
    assert_eq!(validate_fanotify_mark_group(&fid, MarkScope::Inode, FAN_RENAME, FAN_MARK_ADD, true), Ok(()));

    let mnt = InotifyData::new_fanotify(FAN_REPORT_MNT);
    assert_eq!(
        validate_fanotify_mark_group(&mnt, MarkScope::MountNamespace, FAN_MNT_ATTACH, FAN_MARK_ADD, true),
        Ok(()),
    );
    assert_eq!(
        validate_fanotify_mark_group(&mnt, MarkScope::Inode, FAN_OPEN, FAN_MARK_ADD, true),
        Err(einval),
    );
}

// An empty inotify fd is EAGAIN (would-block), never EOF(0), and
// poll() reports not-readable — else an epoll-driven reader spins.

