use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static FREEZE_TARGET: Mutex<Option<Arc<vfs::SuperBlock>>> = Mutex::new(None);
static FREEZE_PARKS: AtomicU32 = AtomicU32::new(0);
static FREEZE_WAKES: AtomicU32 = AtomicU32::new(0);
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

struct FdFreezeType;
impl vfs::FileSystemType for FdFreezeType {
    fn name(&self) -> &str { "quota-fd-freeze-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct FdFreezeOps;
impl vfs::SuperOps for FdFreezeOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

fn sb(id: &str) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdFreezeType), Arc::new(FdFreezeOps), 0x5155_443F, 0x443F, 4096, id.into(), Arc::new(()))
}

fn mounted_file(mount_sb: Arc<vfs::SuperBlock>) -> Arc<vfs::File> {
    static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);
    fn cur_ns() -> vfs::mntns::MntNamespaceRef {
        CUR_NS.lock().unwrap().as_ref().expect("current namespace owner").clone()
    }

    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace");
    let ns = namespace.id();
    *CUR_NS.lock().unwrap() = Some(namespace);
    vfs::mount::set_current_ns_provider(cur_ns);
    vfs::mount::attach_sb(None, mount_sb.clone()).expect("attach root mount");
    let mnt_id = vfs::mount::root_mount_id(ns).expect("root mount id");
    let ino = vfs::InodeBuilder::new(0x443F, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&mount_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-freeze-hosted".into(), Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDONLY, mnt_id, vfs::FileCred::root())
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: hosted test stores a leaked Task pointer and clears it only while serialized.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    *FREEZE_TARGET.lock().unwrap() = None;
    FREEZE_PARKS.store(0, Ordering::SeqCst);
    FREEZE_WAKES.store(0, Ordering::SeqCst);
    vfs::superblock::clear_freeze_wait_hooks();
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_fd(file: Arc<vfs::File>) -> i32 {
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install fd");
    let task = Box::leak(Box::new(sched::Task::new(0x443F, "quotactl-fd-freeze-hosted", sched::SchedClass::Normal { weight: 1024 })));
    // SAFETY: hosted test owns this leaked task and publishes its fd table before installing the current hook pointer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
    fd
}

fn freeze_park_hook(_key: usize) {
    FREEZE_PARKS.fetch_add(1, Ordering::SeqCst);
}

fn freeze_schedule_hook() {
    let target = FREEZE_TARGET.lock().unwrap().clone();
    if let Some(sb) = target {
        sb.thaw_super().expect("hosted thaw from freeze wait hook");
    }
}

fn freeze_wake_hook(_key: usize) {
    FREEZE_WAKES.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn sys_quotactl_fd_write_command_waits_for_frozen_superblock_hosted() {
    let _guard = begin_test();
    let mount_sb = sb("fd-freeze-mount-sb");
    let fd = install_fd(mounted_file(mount_sb.clone()));
    *FREEZE_TARGET.lock().unwrap() = Some(mount_sb.clone());
    vfs::superblock::set_freeze_wait_hooks(freeze_park_hook, freeze_schedule_hook, freeze_wake_hook);
    mount_sb.freeze_super().expect("freeze mount superblock");
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Efault));
    assert!(!mount_sb.is_frozen());
    assert_eq!(mount_sb.sb_writers(), 0);
    assert_eq!(FREEZE_PARKS.load(Ordering::SeqCst), 1);
    assert!(FREEZE_WAKES.load(Ordering::SeqCst) >= 1);
    vfs::superblock::clear_freeze_wait_hooks();
}
