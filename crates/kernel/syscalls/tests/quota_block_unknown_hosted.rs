use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_2B10;
const UNKNOWN_SUBCMD: u64 = 0x8000fe;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-block-unknown-hosted".into())
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

struct UnknownType;
impl vfs::FileSystemType for UnknownType {
    fn name(&self) -> &str { "quota-block-unknown-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct UnknownOps;
impl vfs::SuperOps for UnknownOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

fn sb(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(UnknownType), Arc::new(UnknownOps), 0x5155_2B10, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_block_path(inode_sb: &Arc<vfs::SuperBlock>, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x2b10, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-unknown-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *SPECIAL_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current(euid: u32, cap_sys_admin: bool) {
    let task = Box::leak(Box::new(sched::Task::new(0x2b10, "quotactl-block-unknown-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn args() -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(UNKNOWN_SUBCMD, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

fn install_block_target() -> (Arc<vfs::SuperBlock>, Arc<vfs::SuperBlock>) {
    let target_sb = sb("unknown-target-sb", 0x5155_2B11);
    let special_sb = sb("unknown-special-sb", 0x5155_2B12);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));
    (target_sb, special_sb)
}

fn install_readonly_block_target() -> (Arc<vfs::SuperBlock>, Arc<vfs::SuperBlock>) {
    let (target_sb, special_sb) = install_block_target();
    target_sb.set_readonly(true);
    (target_sb, special_sb)
}

#[test]
fn sys_quotactl_unknown_subcmd_root_returns_einval_after_block_lookup_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let (_target_sb, _special_sb) = install_block_target();

    assert_eq!(sys::sys_quotactl(&args()), eno(Errno::Einval));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}

#[test]
fn sys_quotactl_unknown_subcmd_readonly_target_returns_erofs_before_permission_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let (_target_sb, _special_sb) = install_readonly_block_target();

    assert_eq!(sys::sys_quotactl(&args()), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);

    READ_USER_PATH_CALLS.lock().unwrap().clear();
    install_current(1000, false);
    assert_eq!(sys::sys_quotactl(&args()), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}

#[test]
fn sys_quotactl_unknown_subcmd_nonroot_returns_eperm_after_block_lookup_hosted() {
    let _guard = begin_test();
    install_current(1000, false);
    let (_target_sb, _special_sb) = install_block_target();

    assert_eq!(sys::sys_quotactl(&args()), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}
