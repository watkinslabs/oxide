use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const UNKNOWN_SUBCMD: u64 = 0x8000fe;

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

struct FdUnknownType;
impl vfs::FileSystemType for FdUnknownType {
    fn name(&self) -> &str { "quota-fd-unknown-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct FdUnknownOps;
impl vfs::SuperOps for FdUnknownOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

fn sb(id: &str) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdUnknownType), Arc::new(FdUnknownOps), 0x5155_4D10, 0x4d10, 4096, id.into(), Arc::new(()))
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
    let ino = vfs::InodeBuilder::new(0x4d10, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&mount_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-unknown-hosted".into(), Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDONLY, mnt_id, vfs::FileCred::root())
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current(fdt: Arc<vfs::FdTable>, euid: u32, cap_sys_admin: bool) {
    let task = Box::leak(Box::new(sched::Task::new(0x4d10, "quotactl-fd-unknown-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    // SAFETY: hosted test owns this leaked task and publishes its fd table before installing the current hook pointer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn install_fd(file: Arc<vfs::File>, euid: u32, cap_sys_admin: bool) -> i32 {
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install fd");
    install_current(fdt, euid, cap_sys_admin);
    fd
}

fn args(fd: i32) -> SyscallArgs {
    SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(UNKNOWN_SUBCMD, cmd::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

fn invalid_qtype_args(fd: i32) -> SyscallArgs {
    SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_SYNC, cmd::MAXQUOTAS),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

fn high_cmd_qsync_args(fd: i32) -> SyscallArgs {
    SyscallArgs {
        a0: fd as u64,
        a1: (1u64 << 32) | cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

fn anon_file(sb: Arc<vfs::SuperBlock>) -> Arc<vfs::File> {
    let ino = vfs::InodeBuilder::new(0x4d11, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-invalid-qtype-hosted".into(), Arc::clone(&ino));
    vfs::File::new(ino, d, vfs::OpenFlags::O_RDONLY)
}

#[test]
fn sys_quotactl_fd_truncates_cmd_to_u32_after_fd_lookup_hosted() {
    let _guard = begin_test();
    let fd = install_fd(mounted_file(sb("fd-high-qsync-sb")), 0, true);

    assert_eq!(qfd_sys::sys_quotactl_fd(&high_cmd_qsync_args(fd)), eno(Errno::Enosys));
}

#[test]
fn sys_quotactl_fd_unknown_subcmd_root_returns_einval_after_fd_lookup_hosted() {
    let _guard = begin_test();
    let fd = install_fd(mounted_file(sb("fd-unknown-root-sb")), 0, true);

    assert_eq!(qfd_sys::sys_quotactl_fd(&args(fd)), eno(Errno::Einval));
}

#[test]
fn sys_quotactl_fd_unknown_subcmd_nonroot_returns_eperm_after_fd_lookup_hosted() {
    let _guard = begin_test();
    let fd = install_fd(mounted_file(sb("fd-unknown-nonroot-sb")), 1000, false);

    assert_eq!(qfd_sys::sys_quotactl_fd(&args(fd)), eno(Errno::Eperm));
}

#[test]
fn sys_quotactl_fd_invalid_qtype_returns_einval_after_fd_lookup_before_mount_hosted() {
    let _guard = begin_test();
    let fd = install_fd(anon_file(sb("fd-invalid-qtype-sb")), 0, true);

    assert_eq!(qfd_sys::sys_quotactl_fd(&invalid_qtype_args(fd)), eno(Errno::Einval));
}
