use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::errno::Errno;

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(_addr: u64) -> Result<String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        Err(vfs::VfsError::Enoent)
    }
}

#[path = "../src/179_quotactl/abi.rs"]
mod abi;
#[path = "../src/179_quotactl/cmd.rs"]
mod cmd;
#[path = "../src/179_quotactl/dispatch.rs"]
mod dispatch;
#[path = "../src/179_quotactl_xfs.rs"]
mod xfs;

struct ClassicType;
impl vfs::FileSystemType for ClassicType {
    fn name(&self) -> &str { "quota-classic-order-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct ClassicOps;
impl vfs::SuperOps for ClassicOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

struct QOps {
    acquires: AtomicU32,
    next_hits: AtomicU32,
    next_id: AtomicU32,
}

impl QOps {
    fn new() -> Self {
        Self { acquires: AtomicU32::new(0), next_hits: AtomicU32::new(0), next_id: AtomicU32::new(0) }
    }
    fn reset(&self) {
        self.acquires.store(0, Ordering::SeqCst);
        self.next_hits.store(0, Ordering::SeqCst);
    }
}

impl vfs::DquotOperations for QOps {
    fn as_any(&self) -> &dyn Any { self }
    fn acquire_dquot(&self, _dq: &vfs::Dquot) -> vfs::KResult<()> {
        self.acquires.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn get_next_id(&self, qid: vfs::Kqid) -> vfs::KResult<Option<vfs::Kqid>> {
        self.next_hits.fetch_add(1, Ordering::SeqCst);
        let id = self.next_id.load(Ordering::SeqCst);
        if id == 0 { Ok(None) } else { Ok(Some(vfs::Kqid { kind: qid.kind, id })) }
    }
}

fn sb(id: &str) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(ClassicType), Arc::new(ClassicOps), 0x5155_17C0, 0x17C, 4096, id.into(), Arc::new(()))
}

fn active_sb(id: &str, ops: Arc<QOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb(id);
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, ops).expect("quota_on");
    sb
}

fn seed_quota(sb: &vfs::SuperBlock, id: u32) {
    vfs::quota_setquota(sb, vfs::Kqid::user(id), vfs::MemDqblk {
        dqb_curspace: 4096,
        dqb_curinodes: 1,
        ..vfs::MemDqblk::new()
    }).expect("seed quota record");
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests leak Task pointers for the process lifetime and serialize current-task replacement.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_root() {
    let task = Box::leak(Box::new(sched::Task::new(0x17C0, "quotactl-classic-order-hosted", sched::SchedClass::Normal { weight: 1024 })));
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

#[test]
fn targeted_classic_getfmt_active_quota_checked_before_null_copyout_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QOps::new());
    let sb = active_sb("classic-order-getfmt", ops);

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETFMT, cmd::USRQUOTA), 0, 0), eno(Errno::Efault));
}

#[test]
fn targeted_classic_getinfo_active_info_checked_before_null_copyout_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QOps::new());
    let sb = active_sb("classic-order-getinfo", ops);
    vfs::quota_setinfo(&sb, vfs::QuotaType::User, vfs::MemDqinfo {
        dqi_bgrace: 11,
        dqi_valid:  vfs::IIF_BGRACE,
        ..vfs::MemDqinfo::default()
    }).expect("seed quota info");

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA), 0, 0), eno(Errno::Efault));
}

#[test]
fn targeted_classic_getquota_loads_dquot_before_null_copyout_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QOps::new());
    let sb = active_sb("classic-order-getquota", ops.clone());
    seed_quota(&sb, 77);
    ops.reset();

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA), 77, 0), eno(Errno::Efault));
    assert_eq!(ops.acquires.load(Ordering::SeqCst), 1);
}

#[test]
fn targeted_classic_getnextquota_iterates_and_loads_dquot_before_null_copyout_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QOps::new());
    ops.next_id.store(81, Ordering::SeqCst);
    let sb = active_sb("classic-order-getnextquota", ops.clone());
    seed_quota(&sb, 81);
    ops.reset();

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA), 50, 0), eno(Errno::Efault));
    assert_eq!(ops.next_hits.load(Ordering::SeqCst), 1);
    assert_eq!(ops.acquires.load(Ordering::SeqCst), 1);
}
