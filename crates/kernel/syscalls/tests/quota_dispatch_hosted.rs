use std::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use syscall::errno::Errno;

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static CURRENT_TEST_LOCK: Mutex<()> = Mutex::new(());

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

struct QuotaOrderType;
impl vfs::FileSystemType for QuotaOrderType {
    fn name(&self) -> &str { "quota-dispatch-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct NoQuotaOps;
impl vfs::SuperOps for NoQuotaOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
}

struct UserQuotaOps;
impl vfs::SuperOps for UserQuotaOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, kind: vfs::QuotaType) -> bool { kind == vfs::QuotaType::User }
}

struct StateOps;
impl vfs::SuperOps for StateOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, kind: vfs::QuotaType) -> bool { kind == vfs::QuotaType::User }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
        Ok(vfs::QuotaState { types: core::array::from_fn(|idx| {
            let mut ty = vfs::QuotaTypeState::default();
            if idx == vfs::QuotaType::User.slot() { ty.accounting = false; }
            ty
        }) })
    }
}

#[repr(C)]
struct TestIfDqinfo {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags:  u32,
    dqi_valid:  u32,
}

fn sb_with_ops(ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(QuotaOrderType), ops, 0x5155_1790, 0x179, 4096, "quota-dispatch-hosted".into(), Arc::new(()))
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_current_test() -> MutexGuard<'static, ()> {
    let guard = CURRENT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current(euid: u32, cap_sys_admin: bool) -> &'static sched::Task {
    let task = Box::leak(Box::new(sched::Task::new(0x179, "quotactl-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
    task
}

#[test]
fn targeted_dispatch_checks_quota_ops_before_type_hosted() {
    // Takes CURRENT_TEST_LOCK and zeroes CURRENT_TASK_PTR. Tests that assert
    // the NO-current-task answer (ESRCH) need it just as much as the ones
    // that install a task — a sibling's install_current is what breaks them.
    let _serial = begin_current_test();
    let sb = sb_with_ops(Arc::new(NoQuotaOps));

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETFMT, cmd::USRQUOTA), 0, 0), eno(Errno::Enosys));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETFMT, cmd::MAXQUOTAS), 0, 0), eno(Errno::Enosys));
}

#[test]
fn targeted_dispatch_rejects_type_before_current_task_hosted() {
    // Takes CURRENT_TEST_LOCK and zeroes CURRENT_TASK_PTR. Tests that assert
    // the NO-current-task answer (ESRCH) need it just as much as the ones
    // that install a task — a sibling's install_current is what breaks them.
    let _serial = begin_current_test();
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SYNC, cmd::MAXQUOTAS), 0, 0), eno(Errno::Einval));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SYNC, cmd::GRPQUOTA), 0, 0), eno(Errno::Einval));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETFMT, cmd::GRPQUOTA), 0, 0), eno(Errno::Einval));
}

#[test]
fn targeted_dispatch_supported_type_current_task_order_hosted() {
    // Takes CURRENT_TEST_LOCK and zeroes CURRENT_TASK_PTR. Tests that assert
    // the NO-current-task answer (ESRCH) need it just as much as the ones
    // that install a task — a sibling's install_current is what breaks them.
    let _serial = begin_current_test();
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA), 0, 0), eno(Errno::Enosys));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA), 0, 0), eno(Errno::Esrch));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_QUOTAOFF, cmd::USRQUOTA), 0, 0), eno(Errno::Esrch));
    assert_eq!(
        dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA), vfs::QFMT_VFS_V1 as u64, 0),
        eno(Errno::Esrch),
    );
}

#[test]
fn targeted_dispatch_getinfo_checks_get_state_support_before_state_hosted() {
    let _guard = begin_current_test();
    install_current(0, true);
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(
        dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA), 0, 0),
        eno(Errno::Enosys),
    );
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}

#[test]
fn targeted_dispatch_getinfo_get_state_inactive_returns_esrch_before_copyout_hosted() {
    let _guard = begin_current_test();
    install_current(0, true);
    let sb = sb_with_ops(Arc::new(StateOps));

    assert_eq!(
        dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA), 0, 0),
        eno(Errno::Esrch),
    );
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}

#[test]
fn targeted_dispatch_usercopy_after_current_task_hosted() {
    // Takes CURRENT_TEST_LOCK and zeroes CURRENT_TASK_PTR. Tests that assert
    // the NO-current-task answer (ESRCH) need it just as much as the ones
    // that install a task — a sibling's install_current is what breaks them.
    let _serial = begin_current_test();
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA), 0, 0), eno(Errno::Esrch));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA), 0, 0), eno(Errno::Esrch));
    assert_eq!(dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA), 0, 0), eno(Errno::Esrch));
}

#[test]
fn targeted_dispatch_setquota_permission_denied_before_usercopy_hosted() {
    let _guard = begin_current_test();
    install_current(1000, false);
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(
        dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA), 1000, 0),
        eno(Errno::Eperm),
    );
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}

#[test]
fn targeted_dispatch_setinfo_support_checked_before_valid_mask_hosted() {
    let _guard = begin_current_test();
    install_current(0, true);
    let sb = sb_with_ops(Arc::new(UserQuotaOps));
    let info = TestIfDqinfo {
        dqi_bgrace: 0,
        dqi_igrace: 0,
        dqi_flags:  0,
        dqi_valid:  vfs::IIF_RT_BGRACE,
    };

    assert_eq!(
        dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA), 0, &info as *const _ as u64),
        eno(Errno::Enosys),
    );
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}

#[test]
fn targeted_dispatch_setquota_root_reaches_usercopy_hosted() {
    let _guard = begin_current_test();
    install_current(0, true);
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(
        dispatch::quotactl_dispatch_sb(&sb, cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA), 1000, 0),
        eno(Errno::Efault),
    );
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}
