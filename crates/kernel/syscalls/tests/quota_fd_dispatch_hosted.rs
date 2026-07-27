use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::errno::Errno;
use syscall::SyscallArgs;

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static SYS_TEST_LOCK: Mutex<()> = Mutex::new(());

const FS_DQUOT_VERSION: i8 = 1;
const FS_USER_QUOTA: i8 = 1 << 0;
const FS_QUOTA_UDQ_ACCT: u32 = 1 << 0;
const FS_QUOTA_GDQ_ENFD: u32 = 1 << 3;
const FS_QUOTA_PDQ_ACCT: u32 = 1 << 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsDiskQuota {
    d_version: i8,
    d_flags: i8,
    d_fieldmask: u16,
    d_id: u32,
    d_blk_hardlimit: u64,
    d_blk_softlimit: u64,
    d_ino_hardlimit: u64,
    d_ino_softlimit: u64,
    d_bcount: u64,
    d_icount: u64,
    d_itimer: i32,
    d_btimer: i32,
    d_iwarns: u16,
    d_bwarns: u16,
    d_itimer_hi: i8,
    d_btimer_hi: i8,
    d_rtbtimer_hi: i8,
    d_padding2: i8,
    d_rtb_hardlimit: u64,
    d_rtb_softlimit: u64,
    d_rtbcount: u64,
    d_rtbtimer: i32,
    d_rtbwarns: u16,
    d_padding3: i16,
    d_padding4: [u8; 8],
}

const _: [(); 112] = [(); core::mem::size_of::<FsDiskQuota>()];

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
    fn name(&self) -> &str { "quota-fd-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct FdOps;
impl vfs::SuperOps for FdOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

struct XfsFdOps {
    get_calls: AtomicU32,
    on_calls:  AtomicU32,
    off_calls: AtomicU32,
    rm_calls:  AtomicU32,
    qid:       AtomicU32,
    on_flags:  AtomicU32,
    off_flags: AtomicU32,
    rm_flags:  AtomicU32,
}

impl XfsFdOps {
    fn new() -> Self {
        Self {
            get_calls: AtomicU32::new(0), on_calls: AtomicU32::new(0), off_calls: AtomicU32::new(0),
            rm_calls: AtomicU32::new(0), qid: AtomicU32::new(u32::MAX), on_flags: AtomicU32::new(0),
            off_flags: AtomicU32::new(0), rm_flags: AtomicU32::new(0),
        }
    }
}

impl vfs::SuperOps for XfsFdOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<vfs::MemDqblk> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        self.qid.store(qid.id, Ordering::SeqCst);
        Ok(vfs::MemDqblk { dqb_bhardlimit: 4096, dqb_bsoftlimit: 2048, dqb_curspace: 1024, ..vfs::MemDqblk::new() })
    }
    fn quota_enable_xfs(&self, _sb: &vfs::SuperBlock, flags: u32) -> vfs::KResult<()> {
        self.on_calls.fetch_add(1, Ordering::SeqCst);
        self.on_flags.store(flags, Ordering::SeqCst);
        Ok(())
    }
    fn quota_enable_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_disable_xfs(&self, _sb: &vfs::SuperBlock, flags: u32) -> vfs::KResult<()> {
        self.off_calls.fetch_add(1, Ordering::SeqCst);
        self.off_flags.store(flags, Ordering::SeqCst);
        Ok(())
    }
    fn quota_disable_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_remove_xfs(&self, _sb: &vfs::SuperBlock, flags: u32) -> vfs::KResult<()> {
        self.rm_calls.fetch_add(1, Ordering::SeqCst);
        self.rm_flags.store(flags, Ordering::SeqCst);
        Ok(())
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

fn sb(id: &str) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdType), Arc::new(FdOps), 0x5155_4430, 0x443, 4096, id.into(), Arc::new(()))
}

fn sb_ops(id: &str, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdType), ops, 0x5155_4430, 0x443, 4096, id.into(), Arc::new(()))
}

fn active_sync_sb(id: &str, ops: Arc<DqOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb(id);
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, ops).expect("quota_on");
    sb
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
    let ino = vfs::InodeBuilder::new(0x443, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&inode_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-hosted".into(), Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDONLY, mnt_id, vfs::FileCred::root())
}

fn anon_file() -> Arc<vfs::File> {
    let ino = vfs::InodeBuilder::new(0x444, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build();
    let d = vfs::Dentry::new(None, "anon-quota-fd-hosted".into(), Arc::clone(&ino));
    vfs::File::new(ino, d, vfs::OpenFlags::O_RDONLY)
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: wrapper tests store leaked Task pointers and clear only between serialized test cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_sys_test() -> MutexGuard<'static, ()> {
    let guard = SYS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current(fdt: Option<Arc<vfs::FdTable>>) -> &'static sched::Task {
    install_current_with_creds(fdt, 0, true)
}

fn install_current_with_creds(fdt: Option<Arc<vfs::FdTable>>, euid: u32, cap_sys_admin: bool) -> &'static sched::Task {
    let task = Box::leak(Box::new(sched::Task::new(0x443, "quotactl-fd-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    // SAFETY: hosted test owns this leaked task and publishes its fd table before installing the current hook pointer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
    task
}

#[test]
fn fd_dispatch_checks_qtype_before_mount_hosted() {
    let _guard = begin_sys_test();
    let file = anon_file();

    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::MAXQUOTAS), 0, 0),
        eno(Errno::Einval),
    );
    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::USRQUOTA), 0, 0),
        eno(Errno::Enodev),
    );
}

#[test]
fn fd_write_commands_check_mount_readonly_before_dispatch_hosted() {
    let _guard = begin_sys_test();
    let dqops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("fd-ro", dqops.clone()), sb("inode-sb"));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);

    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_SETINFO, s179_quotactl::USRQUOTA), 0, 0),
        -(vfs::VfsError::Erofs as i64),
    );
    assert_eq!(dqops.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn fd_classic_getquota_checks_mount_readonly_before_dispatch_hosted() {
    let _guard = begin_sys_test();
    let file = mounted_file(sb("fd-classic-getquota-ro"), sb("inode-sb"));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);

    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_GETQUOTA, s179_quotactl::USRQUOTA), 0, 0),
        -(vfs::VfsError::Erofs as i64),
    );
    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_GETNEXTQUOTA, s179_quotactl::USRQUOTA), 0, 0),
        -(vfs::VfsError::Erofs as i64),
    );
}

#[test]
fn fd_read_commands_dispatch_on_readonly_mount_hosted() {
    let _guard = begin_sys_test();
    let dqops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("fd-ro-read", dqops.clone()), sb("inode-sb"));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);

    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::USRQUOTA), 0, 0),
        0,
    );
    assert_eq!(dqops.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn fd_dispatch_uses_file_vfsmount_superblock_hosted() {
    let _guard = begin_sys_test();
    let mount_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let inode_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("fd-mount-sb", mount_ops.clone()), active_sync_sb("fd-inode-sb", inode_ops.clone()));

    assert_eq!(
        qfd_dispatch::quotactl_fd_file(&file, s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::USRQUOTA), 0, 0),
        0,
    );
    assert_eq!(mount_ops.writes.load(Ordering::SeqCst), 1);
    assert_eq!(inode_ops.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_no_current_returns_ebadf_before_cmd_validation_hosted() {
    let _guard = begin_sys_test();
    let args = SyscallArgs {
        a0: 7,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::MAXQUOTAS),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Ebadf));
}

#[test]
fn sys_quotactl_fd_missing_fd_returns_ebadf_before_cmd_validation_hosted() {
    let _guard = begin_sys_test();
    install_current(Some(Arc::new(vfs::FdTable::new())));
    let args = SyscallArgs {
        a0: 9,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::MAXQUOTAS),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Ebadf));
}

#[test]
fn sys_quotactl_fd_real_fd_dispatches_through_fd_table_hosted() {
    let _guard = begin_sys_test();
    let dqops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let file = mounted_file(active_sync_sb("fd-wrapper-mount-sb", dqops.clone()), sb("fd-wrapper-inode-sb"));
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current(Some(fdt));
    let args = SyscallArgs {
        a0: fd as u64,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_SYNC, s179_quotactl::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(dqops.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn sys_quotactl_fd_xfs_getquota_success_reaches_mount_superblock_hook_hosted() {
    let _guard = begin_sys_test();
    let mount_ops = Arc::new(XfsFdOps::new());
    let inode_ops = Arc::new(XfsFdOps::new());
    let file = mounted_file(sb_ops("fd-xfs-getquota-mount-sb", mount_ops.clone()), sb_ops("fd-xfs-getquota-inode-sb", inode_ops.clone()));
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current(Some(fdt));
    let mut out = FsDiskQuota::default();
    let args = SyscallArgs {
        a0: fd as u64,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_XGETQUOTA, s179_quotactl::USRQUOTA),
        a2: 1000,
        a3: &mut out as *mut FsDiskQuota as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(mount_ops.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(mount_ops.qid.load(Ordering::SeqCst), 1000);
    assert_eq!(inode_ops.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(out.d_version, FS_DQUOT_VERSION);
    assert_eq!(out.d_flags, FS_USER_QUOTA);
    assert_eq!(out.d_id, 1000);
    assert_eq!((out.d_blk_hardlimit, out.d_blk_softlimit, out.d_bcount), (8, 4, 2));
}

#[test]
fn sys_quotactl_fd_xfs_state_mutators_success_pass_raw_flags_hosted() {
    let _guard = begin_sys_test();
    let ops = Arc::new(XfsFdOps::new());
    let file = mounted_file(sb_ops("fd-xfs-mutators-mount-sb", ops.clone()), sb("fd-xfs-mutators-inode-sb"));
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current(Some(fdt));
    let mut on_flags = FS_QUOTA_UDQ_ACCT | FS_QUOTA_GDQ_ENFD;
    let mut off_flags = FS_QUOTA_PDQ_ACCT;
    let mut rm_flags = FS_QUOTA_UDQ_ACCT | FS_QUOTA_PDQ_ACCT;
    let mut args = SyscallArgs {
        a0: fd as u64,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_XQUOTAON, s179_quotactl::USRQUOTA),
        a2: 0,
        a3: &mut on_flags as *mut u32 as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    args.a1 = s179_quotactl::qcmd(s179_quotactl::Q_XQUOTAOFF, s179_quotactl::USRQUOTA);
    args.a3 = &mut off_flags as *mut u32 as u64;
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    args.a1 = s179_quotactl::qcmd(s179_quotactl::Q_XQUOTARM, s179_quotactl::USRQUOTA);
    args.a3 = &mut rm_flags as *mut u32 as u64;
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);

    assert_eq!(ops.on_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.off_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.rm_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.on_flags.load(Ordering::SeqCst), on_flags);
    assert_eq!(ops.off_flags.load(Ordering::SeqCst), off_flags);
    assert_eq!(ops.rm_flags.load(Ordering::SeqCst), rm_flags);
}

#[test]
fn sys_quotactl_fd_xfs_quotasync_mount_readonly_allowed_super_readonly_errors_hosted() {
    let _guard = begin_sys_test();
    let file = mounted_file(sb_ops("fd-xfs-quotasync-mount-sb", Arc::new(XfsFdOps::new())), sb("fd-xfs-quotasync-inode-sb"));
    let mnt = file.vfsmount().expect("file has mount");
    mnt.flags.store(vfs::mount::MNT_RDONLY, Ordering::Release);
    let sb = mnt.sb().clone();
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current_with_creds(Some(fdt), 2000, false);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_XQUOTASYNC, s179_quotactl::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    sb.set_readonly(true);
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Erofs));
}

#[test]
fn sys_quotactl_fd_setquota_permission_denied_before_usercopy_hosted() {
    let _guard = begin_sys_test();
    let file = mounted_file(sb("fd-setquota-perm-mount-sb"), sb("fd-setquota-perm-inode-sb"));
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current_with_creds(Some(fdt), 1000, false);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_SETQUOTA, s179_quotactl::USRQUOTA),
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
}

#[test]
fn sys_quotactl_fd_setquota_root_reaches_usercopy_hosted() {
    let _guard = begin_sys_test();
    let file = mounted_file(sb("fd-setquota-root-mount-sb"), sb("fd-setquota-root-inode-sb"));
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current_with_creds(Some(fdt), 0, true);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: s179_quotactl::qcmd(s179_quotactl::Q_SETQUOTA, s179_quotactl::USRQUOTA),
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Efault));
}
