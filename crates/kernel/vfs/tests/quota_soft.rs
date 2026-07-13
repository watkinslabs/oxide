use std::sync::{Arc, Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, Ordering};

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    Dquot, DquotOperations, DquotUsage, Kqid, KResult, MemDqblk, MemDqinfo, QuotaType, VfsError,
    dquot_charge_usage, dquot_release_usage, quota_getquota, quota_on, quota_setinfo, quota_setquota,
};

static SERIAL: Mutex<()> = Mutex::new(());
static TEST_NOW_NS: AtomicU64 = AtomicU64::new(0);

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "quotafs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

struct QOps;
impl DquotOperations for QOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn mark_dirty(&self, _dq: &Dquot) -> KResult<()> { Ok(()) }
}

fn guard() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn test_now_ns() -> u64 { TEST_NOW_NS.load(Ordering::SeqCst) }

fn set_quota_time_sec(sec: u64) {
    vfs::inode_times::set_realtime_provider(test_now_ns);
    TEST_NOW_NS.store(sec.saturating_mul(vfs::superblock::NSEC_PER_SEC), Ordering::SeqCst);
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5155, 0x1234, 4096, "quotafs".into(), Arc::new(()))
}

#[test]
fn block_soft_limit_sets_deadline_and_denies_after_grace() {
    let _g = guard();
    set_quota_time_sec(100);
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    quota_setinfo(&sb, QuotaType::User, MemDqinfo { dqi_bgrace: 10, dqi_valid: 1, ..MemDqinfo::default() }).unwrap();
    quota_setquota(&sb, Kqid::user(10), MemDqblk { dqb_bsoftlimit: 1000, ..MemDqblk::new() }).unwrap();

    dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 900, reserved_space: 0, inodes: 0 }).unwrap();
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_btime, 0);
    dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 200, reserved_space: 0, inodes: 0 }).unwrap();
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_btime, 110);

    set_quota_time_sec(109);
    dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 1, reserved_space: 0, inodes: 0 }).unwrap();
    set_quota_time_sec(110);
    assert_eq!(dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 1, reserved_space: 0, inodes: 0 }), Err(VfsError::Edquot));
}

#[test]
fn release_under_block_soft_limit_clears_deadline() {
    let _g = guard();
    set_quota_time_sec(200);
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    quota_setinfo(&sb, QuotaType::User, MemDqinfo { dqi_bgrace: 30, dqi_valid: 1, ..MemDqinfo::default() }).unwrap();
    quota_setquota(&sb, Kqid::user(10), MemDqblk { dqb_bsoftlimit: 1000, ..MemDqblk::new() }).unwrap();
    dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 1200, reserved_space: 0, inodes: 0 }).unwrap();
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_btime, 230);

    dquot_release_usage(&sb, 10, 20, 30, DquotUsage { space: 201, reserved_space: 0, inodes: 0 }).unwrap();

    let dq = quota_getquota(&sb, Kqid::user(10)).unwrap();
    assert_eq!(dq.dqb_curspace, 999);
    assert_eq!(dq.dqb_btime, 0);
}

#[test]
fn inode_soft_limit_sets_deadline_and_denies_after_grace() {
    let _g = guard();
    set_quota_time_sec(300);
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    quota_setinfo(&sb, QuotaType::User, MemDqinfo { dqi_igrace: 5, dqi_valid: 2, ..MemDqinfo::default() }).unwrap();
    quota_setquota(&sb, Kqid::user(10), MemDqblk { dqb_isoftlimit: 1, ..MemDqblk::new() }).unwrap();
    dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 0, reserved_space: 0, inodes: 1 }).unwrap();
    dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 0, reserved_space: 0, inodes: 1 }).unwrap();
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_itime, 305);

    set_quota_time_sec(305);
    assert_eq!(dquot_charge_usage(&sb, 10, 20, 30, DquotUsage { space: 0, reserved_space: 0, inodes: 1 }), Err(VfsError::Edquot));
}
