use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

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

struct FdType;
impl vfs::FileSystemType for FdType {
    fn name(&self) -> &str { "quota-fd-quotaon-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct QuotaOnOps {
    system_file: bool,
    enables: AtomicU32,
    quota_ons: AtomicU32,
}
impl vfs::SuperOps for QuotaOnOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_enable_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { self.system_file }
    fn quota_enable(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> vfs::KResult<()> {
        self.enables.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn quota_on_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { !self.system_file }
    fn quota_on(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType, _format_id: u32, _path: Option<&vfs::VfsPath>) -> vfs::KResult<()> {
        self.quota_ons.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn sb_with_ops(id: &str, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdType), ops, 0x5155_4431, 0x4431, 4096, id.into(), Arc::new(()))
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
    let ino = vfs::InodeBuilder::new(0x4431, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&inode_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-quotaon-hosted".into(), Arc::clone(&ino));
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
    let task = Box::leak(Box::new(sched::Task::new(0x4431, "quotactl-fd-quotaon-hosted", sched::SchedClass::Normal { weight: 1024 })));
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

fn quotaon_args(fd: i32) -> SyscallArgs {
    SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

#[test]
fn quotactl_fd_file_quotaon_mount_readonly_before_hooks_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) });
    let file = mounted_file(sb_with_ops("fd-quotaon-mnt-ro-mount-sb", ops.clone()), sb_with_ops("fd-quotaon-mnt-ro-inode-sb", Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) })));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);

    assert_eq!(qfd_dispatch::quotactl_fd_file(&file, cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA), vfs::QFMT_VFS_V1 as u64, 0), -(vfs::VfsError::Erofs as i64));
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
}

#[test]
fn quotactl_fd_file_quotaon_superblock_readonly_before_hooks_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) });
    let file = mounted_file(sb_with_ops("fd-quotaon-sb-ro-mount-sb", ops.clone()), sb_with_ops("fd-quotaon-sb-ro-inode-sb", Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) })));
    file.vfsmount().expect("file has mount").sb().set_readonly(true);

    assert_eq!(qfd_dispatch::quotactl_fd_file(&file, cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA), vfs::QFMT_VFS_V1 as u64, 0), -(vfs::VfsError::Erofs as i64));
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_quotaon_system_file_uses_enable_hook_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) });
    let file = mounted_file(sb_with_ops("fd-quotaon-system-mount-sb", ops.clone()), sb_with_ops("fd-quotaon-system-inode-sb", Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) })));
    let fd = install_fd(file, 0, true);

    assert_eq!(qfd_sys::sys_quotactl_fd(&quotaon_args(fd)), 0);
    assert_eq!(ops.enables.load(Ordering::SeqCst), 1);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_quotaon_visible_file_invalid_path_before_quota_on_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(QuotaOnOps { system_file: false, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) });
    let file = mounted_file(sb_with_ops("fd-quotaon-visible-mount-sb", ops.clone()), sb_with_ops("fd-quotaon-visible-inode-sb", Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) })));
    let fd = install_fd(file, 0, true);

    assert_eq!(qfd_sys::sys_quotactl_fd(&quotaon_args(fd)), eno(Errno::Einval));
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_quotaon_permission_denied_before_hooks_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) });
    let file = mounted_file(sb_with_ops("fd-quotaon-perm-mount-sb", ops.clone()), sb_with_ops("fd-quotaon-perm-inode-sb", Arc::new(QuotaOnOps { system_file: true, enables: AtomicU32::new(0), quota_ons: AtomicU32::new(0) })));
    let fd = install_fd(file, 1000, false);

    assert_eq!(qfd_sys::sys_quotactl_fd(&quotaon_args(fd)), eno(Errno::Eperm));
    assert_eq!(ops.enables.load(Ordering::SeqCst), 0);
    assert_eq!(ops.quota_ons.load(Ordering::SeqCst), 0);
}
