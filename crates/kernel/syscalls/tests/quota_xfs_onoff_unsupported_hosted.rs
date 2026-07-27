use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_5E00;
const UNKNOWN_XFS_QUOTA_FLAG: u32 = 1 << 31;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-xfs-onoff-unsupported".into())
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

mod s179_quotactl {
    pub use crate::cmd::*;
    pub use crate::dispatch::quotactl_dispatch_sb_fd;
}

#[path = "../src/443_quotactl_fd/dispatch.rs"]
mod qfd_dispatch;
mod s443_quotactl_fd {
    pub use crate::qfd_dispatch::quotactl_fd_file;
}
#[path = "../src/443_quotactl_fd/sys.rs"]
mod qfd_sys;

struct TestType;
impl vfs::FileSystemType for TestType {
    fn name(&self) -> &str { "quota-xfs-onoff-unsupported-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct PlainOps;
impl vfs::SuperOps for PlainOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
}

fn sb(id: &str, dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(TestType), Arc::new(PlainOps), 0x5155_5E00, dev, 4096, id.into(), Arc::new(()))
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized test cases.
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

fn install_current(fdt: Option<Arc<vfs::FdTable>>) {
    let task = Box::leak(Box::new(sched::Task::new(0x5E00, "quota-xfs-onoff-unsupported", sched::SchedClass::Normal { weight: 1024 })));
    // SAFETY: hosted test owns this leaked task and publishes its fd table before installing the current hook pointer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn mounted_file(mount_sb: Arc<vfs::SuperBlock>, inode_sb: Arc<vfs::SuperBlock>) -> Arc<vfs::File> {
    static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);
    fn cur_ns() -> vfs::mntns::MntNamespaceRef {
        CUR_NS.lock().unwrap().as_ref().expect("current namespace owner").clone()
    }

    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace");
    let ns = namespace.id();
    *CUR_NS.lock().unwrap() = Some(namespace);
    vfs::mount::set_current_ns_provider(cur_ns);
    vfs::mount::attach_sb(None, mount_sb).expect("attach root mount");
    let mnt_id = vfs::mount::root_mount_id(ns).expect("root mount id");
    let ino = vfs::InodeBuilder::new(0x5E01, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&inode_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-xfs-onoff-unsupported-fd".into(), Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDONLY, mnt_id, vfs::FileCred::root())
}

fn install_fd(file: Arc<vfs::File>) -> i32 {
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current(Some(fdt));
    fd
}

fn install_block_target(target_sb: &Arc<vfs::SuperBlock>, special_sb: &Arc<vfs::SuperBlock>) {
    vfs::superblock::register_super(target_sb);
    let ino = vfs::InodeBuilder::new(0x5E02, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(special_sb))
        .rdev(target_sb.s_dev as u32)
        .build();
    let d = vfs::Dentry::new(None, "quota-xfs-onoff-unsupported-block".into(), Arc::clone(&ino));
    *SPECIAL_PATH.lock().unwrap() = Some(vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None });
}

#[test]
fn sys_quotactl_fd_xfs_onoff_unsupported_hooks_win_over_unknown_flags_hosted() {
    let _guard = begin_test();
    let file = mounted_file(sb("fd-xfs-onoff-unsupported-mount-sb", 0x5155_5E01),
        sb("fd-xfs-onoff-unsupported-inode-sb", 0x5155_5E02));
    let fd = install_fd(file);
    let mut flags = UNKNOWN_XFS_QUOTA_FLAG;
    let mut args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
        a2: 0,
        a3: &mut flags as *mut u32 as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Enosys));
    args.a1 = cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::USRQUOTA);
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Enosys));
}

#[test]
fn sys_quotactl_block_xfs_onoff_unsupported_hooks_win_over_unknown_flags_hosted() {
    let _guard = begin_test();
    install_current(None);
    let target_sb = sb("block-xfs-onoff-unsupported-target-sb", 0x5155_5E03);
    let special_sb = sb("block-xfs-onoff-unsupported-special-sb", 0x5155_5E04);
    install_block_target(&target_sb, &special_sb);
    let mut flags = UNKNOWN_XFS_QUOTA_FLAG;
    let mut args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut flags as *mut u32 as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Enosys));
    args.a0 = cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::USRQUOTA);
    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Enosys));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR, SPECIAL_ADDR]);
}
