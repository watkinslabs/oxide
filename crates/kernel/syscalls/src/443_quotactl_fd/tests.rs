use super::*;
use core::any::Any;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::{AtomicU32, Ordering};
use sched::{SchedClass, Task};
use std::boxed::Box;
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const QCMD_SHIFT: u32 = 8;
static CUR_NS: Mutex<Option<vfs::mntns::MntNamespaceRef>> = Mutex::new(None);
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn cur_ns() -> vfs::mntns::MntNamespaceRef {
    CUR_NS.lock().unwrap().as_ref().expect("current namespace owner").clone()
}

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() {
        None
    } else {
        // SAFETY: tests store only leaked Task pointers and clear the hook pointer after each use.
        Some(unsafe { &*p })
    }
}

fn install_current() {
    let task = Box::leak(Box::new(Task::new(0x4430, "quotactl-fd-test", SchedClass::Normal { weight: 1024 })));
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn clear_current() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    guard
}

struct TType;
impl vfs::FileSystemType for TType {
    fn name(&self) -> &str { "quotactl-fd-test" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct DqOps { writes: AtomicU32 }
impl vfs::DquotOperations for DqOps {
    fn as_any(&self) -> &dyn Any { self }
    fn write_info(&self, _kind: vfs::QuotaType, _info: vfs::MemDqinfo) -> vfs::KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct TOps;
impl vfs::SuperOps for TOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

struct CountOps { quota_supported: AtomicU32 }
impl vfs::SuperOps for CountOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool {
        self.quota_supported.fetch_add(1, Ordering::SeqCst);
        true
    }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

struct SysfileEnableOps { calls: AtomicU32, kind: AtomicU32 }
impl vfs::SuperOps for SysfileEnableOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_enable_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { true }
    fn quota_enable(&self, _sb: &vfs::SuperBlock, kind: vfs::QuotaType) -> vfs::KResult<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.kind.store(kind.slot() as u32, Ordering::SeqCst);
        Ok(())
    }
}

struct VisibleOnlyOps { quota_on_calls: AtomicU32 }
impl vfs::SuperOps for VisibleOnlyOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_on_supported(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType) -> bool { true }
    fn quota_on(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType, _format_id: u32, _path: Option<&vfs::VfsPath>) -> vfs::KResult<()> {
        self.quota_on_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn qcmd(subcmd: u64, qtype: u64) -> u64 { (subcmd << QCMD_SHIFT) | qtype }
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn sb(id: &str) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x443, 0x443, 4096, id.into(), Arc::new(()))
}

fn sb_with_ops(id: &str, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(TType), ops, 0x443, 0x443, 4096, id.into(), Arc::new(()))
}

fn active_sync_sb(id: &str, ops: Arc<DqOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb(id);
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, ops).expect("quota_on");
    sb
}

fn active_sync_sb_with_ops(id: &str, dqops: Arc<DqOps>, sops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb_with_ops(id, sops);
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, dqops).expect("quota_on");
    sb
}

fn mounted_file(mount_sb: Arc<vfs::SuperBlock>, inode_sb: Arc<vfs::SuperBlock>) -> Arc<vfs::File> {
    let init = vfs::mntns::initial();
    let namespace = vfs::mntns::allocate(init.owner_user_namespace()).expect("allocate mount namespace");
    let ns = namespace.id();
    *CUR_NS.lock().unwrap() = Some(namespace);
    vfs::mount::set_current_ns_provider(cur_ns);
    vfs::mount::attach_sb(None, mount_sb).expect("attach root mount");
    let mnt_id = vfs::mount::root_mount_id(ns).expect("root mount id");
    let ino = vfs::InodeBuilder::new(0x443, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&inode_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd".into(), Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDONLY, mnt_id, vfs::FileCred::root())
}

fn anon_file() -> Arc<vfs::File> {
    let ino = vfs::InodeBuilder::new(0x444, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build();
    let d = vfs::Dentry::new(None, "anon-quota-fd".into(), Arc::clone(&ino));
    vfs::File::new(ino, d, vfs::OpenFlags::O_RDONLY)
}

#[test]
fn syscall_validates_fd_before_qtype() {
    let _guard = begin_test();
    let args = SyscallArgs { a0: -1i64 as u64, a1: qcmd(crate::s179_quotactl::Q_SYNC, crate::s179_quotactl::MAXQUOTAS),
        a2: 0, a3: 0, a4: 0, a5: 0 };

    assert_eq!(sys_quotactl_fd(&args), err(Errno::Ebadf));
}

#[test]
fn qtype_is_checked_before_mount_lookup() {
    let _guard = begin_test();
    let file = anon_file();

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_SYNC, crate::s179_quotactl::MAXQUOTAS), 0, 0),
        err(Errno::Einval),
    );
    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_SYNC, crate::s179_quotactl::USRQUOTA), 0, 0),
        err(Errno::Enodev),
    );
}

#[test]
fn write_commands_check_mount_writability_before_dispatch() {
    let _guard = begin_test();
    let mount_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("ro-mount", mount_ops.clone()), sb("inode-sb"));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_SETINFO, crate::s179_quotactl::USRQUOTA), 0, 0),
        -(vfs::VfsError::Erofs as i64),
    );
    assert_eq!(mount_ops.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn write_commands_reject_frozen_superblock_without_freeze_wait_hook() {
    let _guard = begin_test();
    let dqops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let sops = Arc::new(CountOps { quota_supported: AtomicU32::new(0) });
    let mount_sb = active_sync_sb_with_ops("frozen-mount", dqops.clone(), sops.clone());
    sops.quota_supported.store(0, Ordering::SeqCst);
    mount_sb.freeze_super().expect("freeze_super");
    let file = mounted_file(mount_sb.clone(), sb("inode-sb"));

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_SETINFO, crate::s179_quotactl::USRQUOTA), 0, 0),
        -(vfs::VfsError::Erofs as i64),
    );
    assert_eq!(sops.quota_supported.load(Ordering::SeqCst), 0);
    assert_eq!(dqops.writes.load(Ordering::SeqCst), 0);
    assert_eq!(mount_sb.sb_writers(), 0);
    mount_sb.thaw_super().expect("thaw_super");
}

#[test]
fn read_commands_dispatch_on_readonly_mount() {
    let _guard = begin_test();
    let mount_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("ro-read", mount_ops.clone()), sb("inode-sb"));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_SYNC, crate::s179_quotactl::USRQUOTA), 0, 0),
        0,
    );
    assert_eq!(mount_ops.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn dispatch_uses_file_vfsmount_superblock_not_inode_superblock() {
    let _guard = begin_test();
    let mount_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let inode_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("mount-sb", mount_ops.clone()), active_sync_sb("inode-sb", inode_ops.clone()));

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_SYNC, crate::s179_quotactl::USRQUOTA), 0, 0),
        0,
    );
    assert_eq!(mount_ops.writes.load(Ordering::SeqCst), 1);
    assert_eq!(inode_ops.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn quotaon_fd_routes_to_sysfile_enable_hook() {
    let _guard = begin_test();
    install_current();
    let ops = Arc::new(SysfileEnableOps { calls: AtomicU32::new(0), kind: AtomicU32::new(u32::MAX) });
    let file = mounted_file(sb_with_ops("quotaon-fd-sysfile", ops.clone()), sb("inode-sb"));

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_QUOTAON, crate::s179_quotactl::USRQUOTA), vfs::QFMT_VFS_V1 as u64, 0),
        0,
    );
    assert_eq!(ops.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    clear_current();
}

#[test]
fn quotaon_fd_visible_quota_file_path_is_invalid() {
    let _guard = begin_test();
    install_current();
    let ops = Arc::new(VisibleOnlyOps { quota_on_calls: AtomicU32::new(0) });
    let file = mounted_file(sb_with_ops("quotaon-fd-visible", ops.clone()), sb("inode-sb"));

    assert_eq!(
        quotactl_fd_file(&file, qcmd(crate::s179_quotactl::Q_QUOTAON, crate::s179_quotactl::GRPQUOTA), vfs::QFMT_VFS_V1 as u64, 0),
        err(Errno::Einval),
    );
    assert_eq!(ops.quota_on_calls.load(Ordering::SeqCst), 0);
    clear_current();
}
