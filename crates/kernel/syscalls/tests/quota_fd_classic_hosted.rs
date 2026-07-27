use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const IIF_CLASSIC_ALL: u32 = vfs::IIF_BGRACE | vfs::IIF_IGRACE | vfs::IIF_FLAGS;
const QIF_ALL: u32 = 0x3f;

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IfDqinfo {
    dqi_bgrace: u64,
    dqi_igrace: u64,
    dqi_flags:  u32,
    dqi_valid:  u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IfDqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace:   u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes:  u64,
    dqb_btime:      u64,
    dqb_itime:      u64,
    dqb_valid:      u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IfNextDqblk {
    dqb_bhardlimit: u64,
    dqb_bsoftlimit: u64,
    dqb_curspace:   u64,
    dqb_ihardlimit: u64,
    dqb_isoftlimit: u64,
    dqb_curinodes:  u64,
    dqb_btime:      u64,
    dqb_itime:      u64,
    dqb_valid:      u32,
    dqb_id:         u32,
}

const _: [(); 24] = [(); core::mem::size_of::<IfDqinfo>()];
const _: [(); 72] = [(); core::mem::size_of::<IfDqblk>()];
const _: [(); 72] = [(); core::mem::size_of::<IfNextDqblk>()];

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
    fn name(&self) -> &str { "quota-fd-classic-hosted" }
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

struct InfoOps {
    writes: AtomicU32,
    bgrace: AtomicU64,
    igrace: AtomicU64,
    flags:  AtomicU32,
    valid:  AtomicU32,
    next:   AtomicU32,
    next_hits: AtomicU32,
}

impl InfoOps {
    fn new() -> Self {
        Self {
            writes: AtomicU32::new(0), bgrace: AtomicU64::new(0), igrace: AtomicU64::new(0),
            flags: AtomicU32::new(0), valid: AtomicU32::new(0), next: AtomicU32::new(0),
            next_hits: AtomicU32::new(0),
        }
    }
}

impl vfs::DquotOperations for InfoOps {
    fn as_any(&self) -> &dyn Any { self }
    fn write_info(&self, _kind: vfs::QuotaType, info: vfs::MemDqinfo) -> vfs::KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.bgrace.store(info.dqi_bgrace, Ordering::SeqCst);
        self.igrace.store(info.dqi_igrace, Ordering::SeqCst);
        self.flags.store(info.dqi_flags, Ordering::SeqCst);
        self.valid.store(info.dqi_valid, Ordering::SeqCst);
        Ok(())
    }
    fn get_next_id(&self, qid: vfs::Kqid) -> vfs::KResult<Option<vfs::Kqid>> {
        self.next_hits.fetch_add(1, Ordering::SeqCst);
        let id = self.next.load(Ordering::SeqCst);
        if id == 0 { Ok(None) } else { Ok(Some(vfs::Kqid { kind: qid.kind, id })) }
    }
}

fn sb(id: &str, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdType), ops, 0x5155_17B0, 0x17B, 4096, id.into(), Arc::new(()))
}

fn active_quota_sb(id: &str, ops: Arc<InfoOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb(id, Arc::new(FdOps));
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
    let ino = vfs::InodeBuilder::new(0x17B, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&inode_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-classic-hosted".into(), Arc::clone(&ino));
    vfs::File::new_at(ino, d, vfs::OpenFlags::O_RDONLY, mnt_id, vfs::FileCred::root())
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests leak Task pointers for the process lifetime and serialize current-task replacement.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_current_with_creds(fdt: Arc<vfs::FdTable>, euid: u32, cap_sys_admin: bool) {
    let task = Box::leak(Box::new(sched::Task::new(0x17B0, "quotactl-fd-classic-hosted", sched::SchedClass::Normal { weight: 1024 })));
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
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current_with_creds(fdt, euid, cap_sys_admin);
    fd
}

fn seed_user_quota(sb: &vfs::SuperBlock, id: u32) {
    vfs::quota_setquota(sb, vfs::Kqid::user(id), vfs::MemDqblk {
        dqb_bhardlimit: 4097,
        dqb_bsoftlimit: 2048,
        dqb_curspace:   1536,
        dqb_ihardlimit: 11,
        dqb_isoftlimit: 7,
        dqb_curinodes:  5,
        dqb_btime:      33,
        dqb_itime:      44,
        ..vfs::MemDqblk::new()
    }).expect("seed quota record");
}

fn assert_classic_dqblk(out: &IfDqblk) {
    assert_eq!(out.dqb_bhardlimit, 5);
    assert_eq!(out.dqb_bsoftlimit, 2);
    assert_eq!(out.dqb_curspace, 1536);
    assert_eq!(out.dqb_ihardlimit, 11);
    assert_eq!(out.dqb_isoftlimit, 7);
    assert_eq!(out.dqb_curinodes, 5);
    assert_eq!(out.dqb_btime, 33);
    assert_eq!(out.dqb_itime, 44);
    assert_eq!(out.dqb_valid, QIF_ALL);
}

fn assert_setquota_record(sb: &vfs::SuperBlock, id: u32) {
    let got = vfs::quota_getquota(sb, vfs::Kqid::user(id)).expect("updated quota record");
    assert_eq!(got.dqb_bhardlimit, 7168);
    assert_eq!(got.dqb_bsoftlimit, 5120);
    assert_eq!(got.dqb_curspace, 4096);
    assert_eq!(got.dqb_ihardlimit, 12);
    assert_eq!(got.dqb_isoftlimit, 9);
    assert_eq!(got.dqb_curinodes, 6);
}

#[test]
fn sys_quotactl_fd_getfmt_success_writes_active_format_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-getfmt-mount-sb", ops);
    let inode_sb = sb("fd-classic-getfmt-inode-sb", Arc::new(FdOps));
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 2000, false);
    let mut out = 0u32;
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_GETFMT, cmd::USRQUOTA),
        a2: 0,
        a3: &mut out as *mut u32 as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(out, vfs::QFMT_VFS_V1);
}

#[test]
fn sys_quotactl_fd_getquota_success_encodes_classic_dqblk_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-getquota-mount-sb", ops);
    let inode_sb = sb("fd-classic-getquota-inode-sb", Arc::new(FdOps));
    seed_user_quota(&mount_sb, 77);
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 77, false);
    let mut out = IfDqblk::default();
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA),
        a2: 77,
        a3: &mut out as *mut IfDqblk as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_classic_dqblk(&out);
}

#[test]
fn sys_quotactl_fd_getquota_permission_denied_before_null_copyout_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-getquota-perm-mount-sb", ops);
    let inode_sb = sb("fd-classic-getquota-perm-inode-sb", Arc::new(FdOps));
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 2000, false);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA),
        a2: 77,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
}

#[test]
fn sys_quotactl_fd_getnextquota_success_encodes_next_id_and_dqblk_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    ops.next.store(81, Ordering::SeqCst);
    let mount_sb = active_quota_sb("fd-classic-getnext-mount-sb", ops);
    let inode_sb = sb("fd-classic-getnext-inode-sb", Arc::new(FdOps));
    seed_user_quota(&mount_sb, 81);
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 0, true);
    let mut out = IfNextDqblk::default();
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA),
        a2: 50,
        a3: &mut out as *mut IfNextDqblk as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(out.dqb_id, 81);
    assert_classic_dqblk(&IfDqblk {
        dqb_bhardlimit: out.dqb_bhardlimit,
        dqb_bsoftlimit: out.dqb_bsoftlimit,
        dqb_curspace:   out.dqb_curspace,
        dqb_ihardlimit: out.dqb_ihardlimit,
        dqb_isoftlimit: out.dqb_isoftlimit,
        dqb_curinodes:  out.dqb_curinodes,
        dqb_btime:      out.dqb_btime,
        dqb_itime:      out.dqb_itime,
        dqb_valid:      out.dqb_valid,
    });
}

#[test]
fn sys_quotactl_fd_getnextquota_permission_denied_before_backend_and_null_copyout_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    ops.next.store(81, Ordering::SeqCst);
    let mount_sb = active_quota_sb("fd-classic-getnext-perm-mount-sb", ops.clone());
    let inode_sb = sb("fd-classic-getnext-perm-inode-sb", Arc::new(FdOps));
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 2000, false);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA),
        a2: 77,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
    assert_eq!(ops.next_hits.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_setquota_success_decodes_classic_dqblk_into_vfs_record_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-setquota-mount-sb", ops);
    let inode_sb = sb("fd-classic-setquota-inode-sb", Arc::new(FdOps));
    let fd = install_fd(mounted_file(mount_sb.clone(), inode_sb), 0, true);
    let mut dq = IfDqblk {
        dqb_bhardlimit: 7,
        dqb_bsoftlimit: 5,
        dqb_curspace:   4096,
        dqb_ihardlimit: 12,
        dqb_isoftlimit: 9,
        dqb_curinodes:  6,
        dqb_btime:      99,
        dqb_itime:      111,
        dqb_valid:      QIF_ALL,
    };
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA),
        a2: 90,
        a3: &mut dq as *mut IfDqblk as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_setquota_record(&mount_sb, 90);
}

#[test]
fn sys_quotactl_fd_getinfo_success_encodes_classic_info_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-getinfo-mount-sb", ops.clone());
    let inode_sb = sb("fd-classic-getinfo-inode-sb", Arc::new(FdOps));
    vfs::quota_setinfo(&mount_sb, vfs::QuotaType::User, vfs::MemDqinfo {
        dqi_bgrace: 111,
        dqi_igrace: 222,
        dqi_flags:  0,
        dqi_valid:  IIF_CLASSIC_ALL,
        ..vfs::MemDqinfo::default()
    }).expect("seed quota info");
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 2000, false);
    let mut out = IfDqinfo::default();
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA),
        a2: 0,
        a3: &mut out as *mut IfDqinfo as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(out.dqi_bgrace, 111);
    assert_eq!(out.dqi_igrace, 222);
    assert_eq!(out.dqi_flags, 0);
    assert_eq!(out.dqi_valid, IIF_CLASSIC_ALL);
}

#[test]
fn sys_quotactl_fd_setinfo_success_updates_mount_superblock_info_hosted() {
    let _guard = begin_test();
    let mount_ops = Arc::new(InfoOps::new());
    let inode_ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-setinfo-mount-sb", mount_ops.clone());
    let inode_sb = active_quota_sb("fd-classic-setinfo-inode-sb", inode_ops.clone());
    let fd = install_fd(mounted_file(mount_sb.clone(), inode_sb), 0, true);
    let mut info = IfDqinfo {
        dqi_bgrace: 333,
        dqi_igrace: 444,
        dqi_flags:  0,
        dqi_valid:  IIF_CLASSIC_ALL,
    };
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA),
        a2: 0,
        a3: &mut info as *mut IfDqinfo as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(mount_ops.writes.load(Ordering::SeqCst), 1);
    assert_eq!(inode_ops.writes.load(Ordering::SeqCst), 0);
    assert_eq!(mount_ops.bgrace.load(Ordering::SeqCst), 333);
    assert_eq!(mount_ops.igrace.load(Ordering::SeqCst), 444);
    assert_eq!(mount_ops.valid.load(Ordering::SeqCst), vfs::IIF_ALL);
    let got = vfs::quota_getinfo(&mount_sb, vfs::QuotaType::User).expect("updated quota info");
    assert_eq!(got.dqi_bgrace, 333);
    assert_eq!(got.dqi_igrace, 444);
}

#[test]
fn sys_quotactl_fd_setinfo_permission_denied_before_usercopy_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(InfoOps::new());
    let mount_sb = active_quota_sb("fd-classic-setinfo-perm-mount-sb", ops.clone());
    let inode_sb = sb("fd-classic-setinfo-perm-inode-sb", Arc::new(FdOps));
    let fd = install_fd(mounted_file(mount_sb, inode_sb), 2000, false);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
    assert_eq!(ops.writes.load(Ordering::SeqCst), 0);
}
