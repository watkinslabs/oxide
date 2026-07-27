use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
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
#[path = "../src/179_quotactl/sys.rs"]
mod sys;
#[path = "../src/179_quotactl_xfs.rs"]
mod xfs;

struct QsyncType;
impl vfs::FileSystemType for QsyncType {
    fn name(&self) -> &str { "quota-block-qsync-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct QsyncOps;
impl vfs::SuperOps for QsyncOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

struct UnsupportedOps;
impl vfs::SuperOps for UnsupportedOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
}

#[derive(Default)]
struct DqOps {
    writes: AtomicU32,
    fail_write_info: AtomicBool,
}
impl vfs::DquotOperations for DqOps {
    fn as_any(&self) -> &dyn Any { self }
    fn write_info(&self, _kind: vfs::QuotaType, _info: vfs::MemDqinfo) -> vfs::KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.fail_write_info.load(Ordering::SeqCst) { return Err(vfs::VfsError::Eio); }
        Ok(())
    }
}

fn sb(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(QsyncType), Arc::new(QsyncOps), 0x5155_17D0, s_dev, 4096, id.into(), Arc::new(()))
}

fn unsupported_sb(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(QsyncType), Arc::new(UnsupportedOps), 0x5155_17D0, s_dev, 4096, id.into(), Arc::new(()))
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    sched::set_current_hook(|| None);
    guard
}

fn qsync_args(qtype: u64) -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SYNC, qtype),
        a1: 0,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

fn high_cmd_qsync_args(qtype: u64) -> SyscallArgs {
    let mut args = qsync_args(qtype);
    args.a0 |= 1u64 << 32;
    args
}

fn null_special_args(subcmd: u64) -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(subcmd, cmd::USRQUOTA),
        a1: 0,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

#[test]
fn sys_quotactl_truncates_cmd_to_u32_before_decode_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&high_cmd_qsync_args(cmd::USRQUOTA)), 0);
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}

#[test]
fn sys_quotactl_null_special_qsync_user_syncs_only_user_quota_globally_hosted() {
    let _guard = begin_test();
    let user_a = Arc::new(DqOps::default());
    let group_a = Arc::new(DqOps::default());
    let user_b = Arc::new(DqOps::default());
    let project_b = Arc::new(DqOps::default());
    let sb_a = sb("qsync-user-a", 0x5155_17D1);
    let sb_b = sb("qsync-user-b", 0x5155_17D2);
    vfs::quota_on(&sb_a, vfs::QuotaType::User, vfs::QFMT_VFS_V1, user_a.clone()).expect("user quota a");
    vfs::quota_on(&sb_a, vfs::QuotaType::Group, vfs::QFMT_VFS_V1, group_a.clone()).expect("group quota a");
    vfs::quota_on(&sb_b, vfs::QuotaType::User, vfs::QFMT_VFS_V1, user_b.clone()).expect("user quota b");
    vfs::quota_on(&sb_b, vfs::QuotaType::Project, vfs::QFMT_VFS_V1, project_b.clone()).expect("project quota b");
    vfs::superblock::register_super(&sb_a);
    vfs::superblock::register_super(&sb_b);

    assert_eq!(sys::sys_quotactl(&qsync_args(cmd::USRQUOTA)), 0);
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
    assert_eq!(user_a.writes.load(Ordering::SeqCst), 1);
    assert_eq!(user_b.writes.load(Ordering::SeqCst), 1);
    assert_eq!(group_a.writes.load(Ordering::SeqCst), 0);
    assert_eq!(project_b.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_null_special_qsync_skips_unsupported_superblocks_hosted() {
    let _guard = begin_test();
    let user = Arc::new(DqOps::default());
    let group = Arc::new(DqOps::default());
    let supported = sb("qsync-mixed-supported", 0x5155_17D4);
    let unsupported = unsupported_sb("qsync-mixed-unsupported", 0x5155_17D5);
    vfs::quota_on(&supported, vfs::QuotaType::User, vfs::QFMT_VFS_V1, user.clone()).expect("user quota");
    vfs::quota_on(&supported, vfs::QuotaType::Group, vfs::QFMT_VFS_V1, group.clone()).expect("group quota");
    vfs::superblock::register_super(&unsupported);
    vfs::superblock::register_super(&supported);

    assert_eq!(sys::sys_quotactl(&qsync_args(cmd::GRPQUOTA)), 0);
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
    assert_eq!(user.writes.load(Ordering::SeqCst), 0);
    assert_eq!(group.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn sys_quotactl_null_special_qsync_propagates_global_writeback_error_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(DqOps::default());
    ops.fail_write_info.store(true, Ordering::SeqCst);
    let target = sb("qsync-error-target", 0x5155_17D3);
    vfs::quota_on(&target, vfs::QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).expect("user quota");
    vfs::superblock::register_super(&target);

    assert_eq!(sys::sys_quotactl(&qsync_args(cmd::USRQUOTA)), eno(Errno::Eio));
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
    assert_eq!(ops.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn sys_quotactl_null_special_qsync_rejects_invalid_type_before_path_lookup_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&qsync_args(cmd::MAXQUOTAS)), eno(Errno::Einval));
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}

#[test]
fn sys_quotactl_null_special_rejects_classic_non_qsync_before_path_lookup_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&null_special_args(cmd::Q_GETFMT)), eno(Errno::Enodev));
    assert_eq!(sys::sys_quotactl(&null_special_args(cmd::Q_SETINFO)), eno(Errno::Enodev));
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}

#[test]
fn sys_quotactl_null_special_rejects_xfs_non_qsync_before_path_lookup_hosted() {
    let _guard = begin_test();

    assert_eq!(sys::sys_quotactl(&null_special_args(cmd::Q_XGETQSTAT)), eno(Errno::Enodev));
    assert_eq!(sys::sys_quotactl(&null_special_args(cmd::Q_XSETQLIM)), eno(Errno::Enodev));
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}
