use super::*;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use crate::inotify::path::resolve_watch_path_at;
use vfs::{CreateCtx, Cred, Dentry, FileType, Inode, InodeBuilder, InodeOps,
    InodeRef, KResult, VfsError, default_file_ops, mk_mode};

struct DirData { kids: BTreeMap<&'static str, InodeRef> }
struct DirOps;

impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<DirData>().ok_or(VfsError::Enotdir)?
            .kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
    fn create(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn mkdir(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Eio)
    }
    fn symlink(&self, _inode: &Inode, _name: &str, _target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Eio)
    }
}

fn cred(uid: u32) -> Cred {
    Cred {
        uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

fn reg(ino: u64, mode: u16, uid: u32) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, mode), vfs::default_inode_ops(), default_file_ops())
        .owner(uid, uid).build()
}

fn dir(ino: u64, mode: u16, uid: u32, kids: &[(&'static str, InodeRef)]) -> InodeRef {
    let mut map = BTreeMap::new();
    for (name, inode) in kids { map.insert(*name, inode.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, mode), Arc::new(DirOps), default_file_ops())
        .owner(uid, uid).private(Arc::new(DirData { kids: map })).build()
}

fn errno(e: syscall::errno::Errno) -> i64 { -(e.as_i32() as i64) }

fn path_err(r: Result<InodeRef, i64>) -> i64 {
    match r {
        Ok(_) => 0,
        Err(e) => e,
    }
}

fn read_event_pair(ino: &InotifyData) -> (i32, u32) {
    let mut buf = [0u8; 16];
    assert_eq!(ino.read(0, &mut buf), Ok(16));
    (
        i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
    )
}

#[test]
fn inotify_watch_path_resolution_matches_linux_permission_shape() {
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

#[test]
fn inotify_oneshot_removes_watch_and_queues_ignored() {
    let ino = InotifyData::new(0);
    let file = reg(6, 0o644, 0);
    let wd = add_or_update_watch(&ino, inode_key(&file), file.fsid(), IN_MODIFY | IN_ONESHOT).unwrap();
    fire_self(&file, IN_MODIFY);
    assert_eq!(ino.watches.lock().len(), 0);
    assert_eq!(read_event_pair(&ino), (wd, IN_MODIFY));
    assert_eq!(read_event_pair(&ino), (wd, IN_IGNORED));
    fire_self(&file, IN_MODIFY);
    assert_eq!(ino.read(0, &mut [0u8; 16]), Err(vfs::VfsError::Eagain));
}

#[test]
fn inotify_remove_watch_queues_ignored_and_rejects_missing_wd() {
    let ino = InotifyData::new(0);
    let wd = add_or_update_watch(&ino, 0xcafeusize, 0x44, IN_OPEN).unwrap();
    assert_eq!(remove_watch(&ino, wd), Ok(()));
    assert_eq!(read_event_pair(&ino), (wd, IN_IGNORED));
    assert_eq!(remove_watch(&ino, wd), Err(syscall::errno::Errno::Einval));
}

#[test]
fn inotify_queue_overflow_reports_single_overflow_event() {
    let ino = InotifyData::new(0);
    for _ in 0..INOTIFY_DEFAULT_MAX_QUEUED_EVENTS {
        ino.enqueue_event(Event { wd: 1, mask: IN_OPEN, cookie: 0, len: 0, obj: None, pid: 0 });
    }
    ino.enqueue_event(Event { wd: 1, mask: IN_MODIFY, cookie: 0, len: 0, obj: None, pid: 0 });
    ino.enqueue_event(Event { wd: 1, mask: IN_ATTRIB, cookie: 0, len: 0, obj: None, pid: 0 });
    let q = ino.events.lock();
    assert_eq!(q.len(), INOTIFY_DEFAULT_MAX_QUEUED_EVENTS + 1);
    assert_eq!(q.back().map(|e| (e.wd, e.mask)), Some((-1, IN_Q_OVERFLOW)));
    assert_eq!(q.iter().filter(|e| (e.mask & IN_Q_OVERFLOW) != 0).count(), 1);
}

#[test]
fn fanotify_init_validation_matches_linux_ordering_units() {
    let einval = syscall::errno::Errno::Einval.as_i32();
    let eperm = syscall::errno::Errno::Eperm.as_i32();

    assert_eq!(validate_fanotify_init_args(0, 0, false, false), eperm);
    assert_eq!(validate_fanotify_init(FAN_REPORT_DIR_FID), 0);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID, 0, false, false), 0);
    assert_eq!(validate_fanotify_init_args(FAN_CLASS_CONTENT, 0, false, false), eperm);

    assert_eq!(validate_fanotify_init_args(0x8000_0000, 0, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT, 0, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_NAME, 0, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID | FAN_REPORT_NAME, 0, true, true), 0);
    assert_eq!(
        validate_fanotify_init_args(FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_TARGET_FID, 0, true, true),
        einval,
    );
    assert_eq!(
        validate_fanotify_init_args(
            FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_FID | FAN_REPORT_TARGET_FID,
            0,
            true,
            true,
        ),
        0,
    );

    assert_eq!(validate_fanotify_init_args(FAN_REPORT_MNT | FAN_CLASS_CONTENT, 0, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_MNT | FAN_REPORT_FID, 0, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_MNT | FAN_REPORT_FD_ERROR, 0, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_MNT, 0, false, false), 0);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID | FAN_ENABLE_AUDIT, 0, true, false), eperm);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID | FAN_ENABLE_AUDIT, 0, true, true), 0);

    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID, 0o3, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID, 0x8000_0000, true, true), einval);
    assert_eq!(validate_fanotify_init_args(FAN_REPORT_DIR_FID, 0o4000 | 0o2, true, true), 0);
}

#[test]
fn fanotify_mark_prefd_validation_matches_linux_units() {
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
    let einval = syscall::errno::Errno::Einval;
    let ino = InotifyData::new(0);
    assert_eq!(
        validate_fanotify_mark_group(&ino, MarkScope::Inode, FAN_OPEN, FAN_MARK_ADD),
        Err(einval),
    );

    let notif = InotifyData::new_fanotify(0);
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_OPEN_PERM, FAN_MARK_ADD),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_FS_ERROR, FAN_MARK_ADD),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Mount, FAN_OPEN, FAN_MARK_ADD | FAN_MARK_EVICTABLE),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_RENAME, FAN_MARK_ADD),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::Inode, FAN_MNT_ATTACH, FAN_MARK_ADD),
        Err(einval),
    );
    assert_eq!(
        validate_fanotify_mark_group(&notif, MarkScope::MountNamespace, FAN_MNT_ATTACH, FAN_MARK_ADD),
        Err(einval),
    );

    let content = InotifyData::new_fanotify(FAN_CLASS_CONTENT);
    assert_eq!(validate_fanotify_mark_group(&content, MarkScope::Inode, FAN_OPEN_PERM, FAN_MARK_ADD), Ok(()));
    assert_eq!(
        validate_fanotify_mark_group(&content, MarkScope::Inode, FAN_PRE_ACCESS, FAN_MARK_ADD),
        Err(einval),
    );

    let fid = InotifyData::new_fanotify(FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_REPORT_FID);
    assert_eq!(validate_fanotify_mark_group(&fid, MarkScope::Inode, FAN_RENAME, FAN_MARK_ADD), Ok(()));

    let mnt = InotifyData::new_fanotify(FAN_REPORT_MNT);
    assert_eq!(
        validate_fanotify_mark_group(&mnt, MarkScope::MountNamespace, FAN_MNT_ATTACH, FAN_MARK_ADD),
        Ok(()),
    );
    assert_eq!(
        validate_fanotify_mark_group(&mnt, MarkScope::Inode, FAN_OPEN, FAN_MARK_ADD),
        Err(einval),
    );
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
    let before = ino.poll_subs.generation();
    ino.enqueue_event(Event { wd: 1, mask: IN_MODIFY, cookie: 0, len: 0, obj: None, pid: 0 });
    assert!(ino.poll_subs.generation() > before, "queued inotify event wakes epoll subscribers");
    assert_eq!(ino.poll(), vfs::POLL_IN);
    let mut buf = [0u8; 64];
    assert_eq!(ino.read(0, &mut buf), Ok(16));
    assert_eq!(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);
    assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), IN_MODIFY);
    assert_eq!(ino.read(0, &mut buf), Err(vfs::VfsError::Eagain));
    assert_eq!(ino.poll(), 0);
}
