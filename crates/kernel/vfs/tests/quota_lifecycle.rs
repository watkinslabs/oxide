use std::sync::Arc;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    Dquot, DquotOperations, FileType, InodeBuilder, Kqid, KResult, QuotaType, VfsError,
    default_file_ops, default_inode_ops, dquot_charge_usage, dquot_initialize, dquot_release_usage,
    inode_dquot, mk_mode, quota_getinfo, quota_getquota, quota_off, quota_on, quota_setinfo,
    quota_setquota, IIF_BGRACE, IIF_IGRACE, MemDqblk, MemDqinfo,
};

static SERIAL: Mutex<()> = Mutex::new(());
static WAIT: (Mutex<WaitState>, Condvar) = (Mutex::new(WaitState { parked: false, wake: false }), Condvar::new());

struct WaitState { parked: bool, wake: bool }

fn guard() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn install_wait_hooks() {
    let (m, _) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    st.parked = false;
    st.wake = false;
    drop(st);
    vfs::set_quota_wait_hooks(park_hook, schedule_hook, wake_hook);
}

fn park_hook(_key: usize) {
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    st.parked = true;
    cv.notify_all();
}

fn schedule_hook() {
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    while !st.wake {
        st = cv.wait(st).unwrap_or_else(|e| e.into_inner());
    }
}

fn wake_hook(_key: usize) {
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    st.wake = true;
    cv.notify_all();
}

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "quotafs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

#[derive(Default)]
struct QOps {
    writes:     AtomicUsize,
    write_fail: AtomicUsize,
    info_writes: AtomicUsize,
    info_fail:   AtomicUsize,
    releases:   AtomicUsize,
    release_fail: AtomicUsize,
}

impl DquotOperations for QOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn write_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.write_fail.load(Ordering::SeqCst) != 0 {
            self.write_fail.fetch_sub(1, Ordering::SeqCst);
            return Err(VfsError::Eio);
        }
        Ok(())
    }
    fn release_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        if self.release_fail.load(Ordering::SeqCst) != 0 {
            self.release_fail.fetch_sub(1, Ordering::SeqCst);
            return Err(VfsError::Eio);
        }
        Ok(())
    }
    fn write_info(&self, _kind: QuotaType, _info: MemDqinfo) -> KResult<()> {
        self.info_writes.fetch_add(1, Ordering::SeqCst);
        if self.info_fail.load(Ordering::SeqCst) != 0 {
            self.info_fail.fetch_sub(1, Ordering::SeqCst);
            return Err(VfsError::Eio);
        }
        Ok(())
    }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5155, 0x1234, 4096, "quotafs".into(), Arc::new(()))
}

fn inode(sb: &Arc<SuperBlock>, uid: u32, gid: u32, projid: u32) -> vfs::InodeRef {
    sb.iget(0x55, || {
        InodeBuilder::new(0x55, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
            .sb(Arc::downgrade(sb))
            .owner(uid, gid)
            .projid(projid)
            .build()
    })
}

#[test]
fn quota_off_blocks_new_operations_even_when_writeback_fails() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, Kqid::user(1000), MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    dquot_initialize(&ino).unwrap();
    ops.write_fail.store(1, Ordering::SeqCst);

    assert_eq!(quota_off(&sb, QuotaType::User), Err(VfsError::Eio));

    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(inode_dquot(&ino, QuotaType::User).is_none());
    assert_eq!(quota_getquota(&sb, Kqid::user(1000)), Err(VfsError::Esrch));
    dquot_charge_usage(&sb, 1000, 1, 1, vfs::DquotUsage::inode(4096, 0)).unwrap();
    dquot_release_usage(&sb, 1000, 1, 1, vfs::DquotUsage::inode(4096, 0)).unwrap();
    assert_eq!(ops.writes.load(Ordering::SeqCst), 2);
    assert_eq!(ops.releases.load(Ordering::SeqCst), 1);
}

#[test]
fn quota_off_reports_dirty_inode_dquot_writeback_failure() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, Kqid::user(1000), MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    dquot_initialize(&ino).unwrap();
    ops.write_fail.store(1, Ordering::SeqCst);

    assert_eq!(quota_off(&sb, QuotaType::User), Err(VfsError::Eio));

    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(inode_dquot(&ino, QuotaType::User).is_none());
    assert_eq!(ops.writes.load(Ordering::SeqCst), 2);
    assert_eq!(ops.releases.load(Ordering::SeqCst), 1);
}

#[test]
fn quota_off_retains_dirty_dquot_when_final_drop_writeback_fails() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    let qid = Kqid::user(1000);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    dquot_initialize(&ino).unwrap();
    ops.write_fail.store(3, Ordering::SeqCst);

    assert_eq!(quota_off(&sb, QuotaType::User), Err(VfsError::Eio));

    let dq = sb.s_dquot.dquots().lookup(qid).unwrap();
    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(dq.is_dirty());
    assert_eq!(ops.writes.load(Ordering::SeqCst), 3);
    assert_eq!(ops.releases.load(Ordering::SeqCst), 0);

    assert_eq!(quota_off(&sb, QuotaType::User), Ok(()));
    assert!(sb.s_dquot.dquots().lookup(qid).is_none());
    assert_eq!(ops.releases.load(Ordering::SeqCst), 1);
}

#[test]
fn quota_off_retains_dquot_when_final_release_fails() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    let qid = Kqid::user(1000);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    dquot_initialize(&ino).unwrap();
    ops.release_fail.store(2, Ordering::SeqCst);

    assert_eq!(quota_off(&sb, QuotaType::User), Err(VfsError::Eio));

    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(sb.s_dquot.dquots().lookup(qid).is_some());
    assert_eq!(ops.releases.load(Ordering::SeqCst), 2);

    assert_eq!(quota_off(&sb, QuotaType::User), Ok(()));
    assert!(sb.s_dquot.dquots().lookup(qid).is_none());
    assert_eq!(ops.releases.load(Ordering::SeqCst), 3);
}

#[test]
fn quota_setinfo_writeback_failure_restores_old_info() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setinfo(&sb, QuotaType::User, MemDqinfo {
        dqi_bgrace: 60,
        dqi_igrace: 30,
        dqi_valid: IIF_BGRACE | IIF_IGRACE,
        ..MemDqinfo::default()
    }).unwrap();
    ops.info_fail.store(1, Ordering::SeqCst);

    assert_eq!(quota_setinfo(&sb, QuotaType::User, MemDqinfo {
        dqi_bgrace: 600,
        dqi_igrace: 300,
        dqi_valid: IIF_BGRACE | IIF_IGRACE,
        ..MemDqinfo::default()
    }), Err(VfsError::Eio));

    let info = quota_getinfo(&sb, QuotaType::User).unwrap();
    assert_eq!(info.dqi_bgrace, 60);
    assert_eq!(info.dqi_igrace, 30);
    assert_eq!(ops.info_writes.load(Ordering::SeqCst), 2);
}

#[test]
fn quota_off_waits_for_external_dquot_refs() {
    let _serial = guard();
    install_wait_hooks();
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, Kqid::user(1000), MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    dquot_initialize(&ino).unwrap();
    let held = sb.s_dquot.dqget(Kqid::user(1000)).unwrap();
    let off_sb = sb.clone();
    let t = thread::spawn(move || quota_off(&off_sb, QuotaType::User));

    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    while !st.parked {
        let (next, timeout) = cv.wait_timeout(st, Duration::from_secs(1)).unwrap_or_else(|e| e.into_inner());
        st = next;
        assert!(!timeout.timed_out(), "quota_off did not park on held dquot");
    }
    assert_eq!(ops.releases.load(Ordering::SeqCst), 0);
    drop(st);

    vfs::dqput(held);
    assert_eq!(t.join().unwrap(), Ok(()));

    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(sb.s_dquot.dquots().lookup(Kqid::user(1000)).is_none());
    assert_eq!(ops.releases.load(Ordering::SeqCst), 1);
    vfs::clear_quota_wait_hooks();
}
