use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_2790;
const BAD_QUOTAON_ADDR: u64 = 0x5155_2791;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        match addr {
            crate::BAD_QUOTAON_ADDR => Err(-(syscall::errno::Errno::Efault.as_i32() as i64)),
            _ => Ok("/dev/quota-block-quotaon-hosted".into()),
        }
    }
}

mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        crate::SPECIAL_PATH.lock().unwrap().clone().ok_or(vfs::VfsError::Enoent)
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

struct BlockType;
impl vfs::FileSystemType for BlockType {
    fn name(&self) -> &str { "quota-block-quotaon-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct QuotaOnOps {
    system_file: bool,
    enables: AtomicU32,
    disables: AtomicU32,
    quota_ons: AtomicU32,
}
impl QuotaOnOps {
    fn new(system_file: bool) -> Self {
        Self { system_file, enables: AtomicU32::new(0), disables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) }
    }
}
impl vfs::SuperOps for QuotaOnOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, kind: vfs::QuotaType) -> bool { kind == vfs::QuotaType::User }
    fn quota_enable_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { self.system_file }
    fn quota_enable(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> vfs::KResult<()> {
        self.enables.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn quota_disable_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { self.system_file }
    fn quota_disable(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> vfs::KResult<()> {
        self.disables.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn quota_on_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { !self.system_file }
    fn quota_on(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType, _format_id: u32, _path: Option<&vfs::VfsPath>) -> vfs::KResult<()> {
        self.quota_ons.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct NoopDqOps;
impl vfs::DquotOperations for NoopDqOps {
    fn as_any(&self) -> &dyn Any { self }
}

fn sb_with_ops(id: &str, s_dev: u64, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), ops, 0x5155_2790, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_block_path(inode_sb: &Arc<vfs::SuperBlock>, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x279, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-quotaon-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn clear_paths() {
    *SPECIAL_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    CURRENT_TASK_PTR.store(0, Ordering::Release);
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_paths();
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_root() {
    let task = Box::leak(Box::new(sched::Task::new(0x2790, "quotactl-block-quotaon-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(0, Ordering::Release);
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn quotaon_args() -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: BAD_QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    }
}

#[test]
fn block_quotaon_system_file_ignores_deferred_bad_quota_path_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QuotaOnOps::new(true));
    let target_sb = sb_with_ops("quotaon-system-target-sb", 0x5155_2792, ops.clone());
    let special_sb = sb_with_ops("quotaon-system-special-sb", 0x5155_2793, Arc::new(QuotaOnOps::new(true)));
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));
    vfs::quota_on(&target_sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(NoopDqOps)).expect("seed accounting");

    assert_eq!(sys::sys_quotactl(&quotaon_args()), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.enables.load(Ordering::SeqCst), 1);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn block_quotaon_visible_file_returns_deferred_bad_quota_path_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QuotaOnOps::new(false));
    let target_sb = sb_with_ops("quotaon-visible-target-sb", 0x5155_2794, ops.clone());
    let special_sb = sb_with_ops("quotaon-visible-special-sb", 0x5155_2795, Arc::new(QuotaOnOps::new(true)));
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));

    assert_eq!(sys::sys_quotactl(&quotaon_args()), eno(Errno::Efault));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn block_quotaon_system_file_readonly_returns_erofs_before_enable_hook_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QuotaOnOps::new(true));
    let target_sb = sb_with_ops("quotaon-system-readonly-target-sb", 0x5155_2796, ops.clone());
    let special_sb = sb_with_ops("quotaon-system-readonly-special-sb", 0x5155_2797, Arc::new(QuotaOnOps::new(true)));
    vfs::superblock::register_super(&target_sb);
    target_sb.set_readonly(true);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));

    assert_eq!(sys::sys_quotactl(&quotaon_args()), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn block_quotaon_visible_file_readonly_returns_erofs_before_deferred_path_error_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QuotaOnOps::new(false));
    let target_sb = sb_with_ops("quotaon-visible-readonly-target-sb", 0x5155_2798, ops.clone());
    let special_sb = sb_with_ops("quotaon-visible-readonly-special-sb", 0x5155_2799, Arc::new(QuotaOnOps::new(true)));
    vfs::superblock::register_super(&target_sb);
    target_sb.set_readonly(true);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));

    assert_eq!(sys::sys_quotactl(&quotaon_args()), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn block_quotaoff_system_file_readonly_returns_erofs_before_disable_hook_hosted() {
    let _guard = begin_test();
    install_root();
    let ops = Arc::new(QuotaOnOps::new(true));
    let target_sb = sb_with_ops("quotaoff-system-readonly-target-sb", 0x5155_27A0, ops.clone());
    let special_sb = sb_with_ops("quotaoff-system-readonly-special-sb", 0x5155_27A1, Arc::new(QuotaOnOps::new(true)));
    vfs::superblock::register_super(&target_sb);
    target_sb.set_readonly(true);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAOFF, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.disables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
    clear_paths();
}
