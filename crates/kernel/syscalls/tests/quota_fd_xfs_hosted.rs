use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const FS_DQUOT_VERSION: i8 = 1;
const FS_QSTAT_VERSION: i8 = 1;
const FS_QSTATV_VERSION1: i8 = 1;
const FS_DQ_BHARD: u16 = 1 << 3;
const FS_USER_QUOTA: i8 = 1 << 0;
const FS_QUOTA_UDQ_ACCT: u16 = 1 << 0;
const FS_QUOTA_UDQ_ENFD: u16 = 1 << 1;
const FS_QUOTA_PDQ_ACCT: u16 = 1 << 4;
const FS_QUOTA_PDQ_ENFD: u16 = 1 << 5;

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQfilestat { qfs_ino: u64, qfs_nblks: u64, qfs_nextents: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQuotaStat {
    qs_version: i8,
    qs_flags: u16,
    qs_pad: i8,
    qs_uquota: FsQfilestat,
    qs_gquota: FsQfilestat,
    qs_incoredqs: u32,
    qs_btimelimit: i32,
    qs_itimelimit: i32,
    qs_rtbtimelimit: i32,
    qs_bwarnlimit: u16,
    qs_iwarnlimit: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQfilestatv { qfs_ino: u64, qfs_nblks: u64, qfs_nextents: u32, qfs_pad: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQuotaStatv {
    qs_version: i8,
    qs_pad1: u8,
    qs_flags: u16,
    qs_incoredqs: u32,
    qs_uquota: FsQfilestatv,
    qs_gquota: FsQfilestatv,
    qs_pquota: FsQfilestatv,
    qs_btimelimit: i32,
    qs_itimelimit: i32,
    qs_rtbtimelimit: i32,
    qs_bwarnlimit: u16,
    qs_iwarnlimit: u16,
    qs_rtbwarnlimit: u16,
    qs_pad3: u16,
    qs_pad4: u32,
    qs_pad2: [u64; 7],
}

const _: [(); 80] = [(); core::mem::size_of::<FsQuotaStat>()];
const _: [(); 160] = [(); core::mem::size_of::<FsQuotaStatv>()];

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

struct FdXfsType;
impl vfs::FileSystemType for FdXfsType {
    fn name(&self) -> &str { "quota-fd-xfs-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct XfsOps {
    next_calls: AtomicU32,
    set_calls:  AtomicU32,
    state_calls: AtomicU32,
    on_calls:   AtomicU32,
    off_calls:  AtomicU32,
    rm_calls:   AtomicU32,
    kind:       AtomicU32,
    id:         AtomicU32,
    fieldmask:  AtomicU32,
    bhard:      AtomicU64,
}

impl XfsOps {
    fn new() -> Self {
        Self {
            next_calls: AtomicU32::new(0), set_calls: AtomicU32::new(0), state_calls: AtomicU32::new(0),
            on_calls: AtomicU32::new(0), off_calls: AtomicU32::new(0), rm_calls: AtomicU32::new(0),
            kind: AtomicU32::new(u32::MAX), id: AtomicU32::new(u32::MAX),
            fieldmask: AtomicU32::new(0), bhard: AtomicU64::new(0),
        }
    }
}

impl vfs::SuperOps for XfsOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
        self.state_calls.fetch_add(1, Ordering::SeqCst);
        let mut st = vfs::QuotaState::default();
        st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
            accounting: true,
            enforcement: true,
            info: vfs::MemDqinfo {
                dqi_bgrace: 31, dqi_igrace: 37, dqi_rt_bgrace: 41,
                dqi_bwarnlimit: 43, dqi_iwarnlimit: 47, dqi_rtbwarnlimit: 53,
                ..vfs::MemDqinfo::default()
            },
            file: vfs::QuotaFileStat { ino: 101, blocks: 202, nextents: 3 },
            incoredqs: 5,
        };
        st.types[vfs::QuotaType::Project.slot()] = vfs::QuotaTypeState {
            accounting: true,
            enforcement: true,
            file: vfs::QuotaFileStat { ino: 303, blocks: 404, nextents: 6 },
            incoredqs: 7,
            ..vfs::QuotaTypeState::default()
        };
        Ok(st)
    }
    fn quota_get_next_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<(vfs::Kqid, vfs::MemDqblk)> {
        self.next_calls.fetch_add(1, Ordering::SeqCst);
        self.kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
        self.id.store(qid.id, Ordering::SeqCst);
        Ok((vfs::Kqid { kind: qid.kind, id: qid.id + 7 }, vfs::MemDqblk {
            dqb_bhardlimit: 6144,
            dqb_bsoftlimit: 3072,
            dqb_curspace: 1536,
            dqb_ihardlimit: 29,
            dqb_isoftlimit: 23,
            dqb_curinodes: 17,
            ..vfs::MemDqblk::new()
        }))
    }
    fn quota_set_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_set_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid, dqblk: vfs::MemDqblk, fieldmask: u32, _now_sec: u64) -> vfs::KResult<()> {
        self.set_calls.fetch_add(1, Ordering::SeqCst);
        self.kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
        self.id.store(qid.id, Ordering::SeqCst);
        self.fieldmask.store(fieldmask, Ordering::SeqCst);
        self.bhard.store(dqblk.dqb_bhardlimit, Ordering::SeqCst);
        Ok(())
    }
    fn quota_enable_xfs(&self, _sb: &vfs::SuperBlock, _flags: u32) -> vfs::KResult<()> {
        self.on_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn quota_enable_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_disable_xfs(&self, _sb: &vfs::SuperBlock, _flags: u32) -> vfs::KResult<()> {
        self.off_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn quota_disable_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_remove_xfs(&self, _sb: &vfs::SuperBlock, _flags: u32) -> vfs::KResult<()> {
        self.rm_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn sb_with_ops(id: &str, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(FdXfsType), ops, 0x5155_4450, 0x445, 4096, id.into(), Arc::new(()))
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
    let ino = vfs::InodeBuilder::new(0x445, vfs::mk_mode(vfs::FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(&inode_sb))
        .build();
    let d = vfs::Dentry::new(None, "quota-fd-xfs-hosted".into(), Arc::clone(&ino));
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

fn install_current_with_creds(fdt: Arc<vfs::FdTable>, euid: u32, cap_sys_admin: bool) {
    let task = Box::leak(Box::new(sched::Task::new(0x445, "quotactl-fd-xfs-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    // SAFETY: hosted test owns this leaked task and publishes its fd table before installing the current hook pointer.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn install_current(fdt: Arc<vfs::FdTable>) {
    install_current_with_creds(fdt, 0, true);
}

fn install_fd(file: Arc<vfs::File>) -> i32 {
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current(fdt);
    fd
}

fn install_fd_with_creds(file: Arc<vfs::File>, euid: u32, cap_sys_admin: bool) -> i32 {
    let fdt = Arc::new(vfs::FdTable::new());
    let fd = fdt.alloc(file).expect("install hosted fd");
    install_current_with_creds(fdt, euid, cap_sys_admin);
    fd
}

#[test]
fn sys_quotactl_fd_xfs_getnextquota_success_reaches_hook_and_encodes_next_id_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(XfsOps::new());
    let file = mounted_file(sb_with_ops("fd-xfs-getnext-mount-sb", ops.clone()),
        sb_with_ops("fd-xfs-getnext-inode-sb", Arc::new(XfsOps::new())));
    let fd = install_fd(file);
    let mut out = FsDiskQuota::default();
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_XGETNEXTQUOTA, cmd::USRQUOTA),
        a2: 1000,
        a3: &mut out as *mut FsDiskQuota as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 1000);
    assert_eq!(out.d_version, FS_DQUOT_VERSION);
    assert_eq!(out.d_flags, FS_USER_QUOTA);
    assert_eq!(out.d_id, 1007);
    assert_eq!((out.d_blk_hardlimit, out.d_blk_softlimit, out.d_bcount), (12, 6, 3));
    assert_eq!((out.d_ino_hardlimit, out.d_ino_softlimit, out.d_icount), (29, 23, 17));
}

#[test]
fn sys_quotactl_fd_xfs_setqlim_success_reaches_hook_with_decoded_limits_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(XfsOps::new());
    let file = mounted_file(sb_with_ops("fd-xfs-setqlim-mount-sb", ops.clone()),
        sb_with_ops("fd-xfs-setqlim-inode-sb", Arc::new(XfsOps::new())));
    let fd = install_fd(file);
    let mut q = FsDiskQuota { d_fieldmask: FS_DQ_BHARD, d_blk_hardlimit: 10, ..FsDiskQuota::default() };
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_XSETQLIM, cmd::USRQUOTA),
        a2: 2000,
        a3: &mut q as *mut FsDiskQuota as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 2000);
    assert_eq!(ops.fieldmask.load(Ordering::SeqCst), vfs::DQB_SPC_HARD);
    assert_eq!(ops.bhard.load(Ordering::SeqCst), 5120);
}

#[test]
fn sys_quotactl_fd_xfs_setqlim_permission_denied_before_usercopy_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(XfsOps::new());
    let file = mounted_file(sb_with_ops("fd-xfs-setqlim-perm-mount-sb", ops.clone()),
        sb_with_ops("fd-xfs-setqlim-perm-inode-sb", Arc::new(XfsOps::new())));
    let fd = install_fd_with_creds(file, 2000, false);
    let args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_XSETQLIM, cmd::USRQUOTA),
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.fieldmask.load(Ordering::SeqCst), 0);
    assert_eq!(ops.bhard.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_xfs_state_mutators_permission_denied_before_flag_usercopy_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(XfsOps::new());
    let file = mounted_file(sb_with_ops("fd-xfs-mutators-perm-mount-sb", ops.clone()),
        sb_with_ops("fd-xfs-mutators-perm-inode-sb", Arc::new(XfsOps::new())));
    let fd = install_fd_with_creds(file, 2000, false);
    let mut args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
    args.a1 = cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::USRQUOTA);
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));
    args.a1 = cmd::qcmd(cmd::Q_XQUOTARM, cmd::USRQUOTA);
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), eno(Errno::Eperm));

    assert_eq!(ops.on_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.off_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.rm_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_fd_xfs_qstat_success_maps_filesystem_state_hosted() {
    let _guard = begin_test();
    let ops = Arc::new(XfsOps::new());
    let file = mounted_file(sb_with_ops("fd-xfs-qstat-mount-sb", ops.clone()),
        sb_with_ops("fd-xfs-qstat-inode-sb", Arc::new(XfsOps::new())));
    let fd = install_fd(file);
    let mut out = FsQuotaStat::default();
    let mut outv = FsQuotaStatv { qs_version: FS_QSTATV_VERSION1, ..FsQuotaStatv::default() };
    let mut args = SyscallArgs {
        a0: fd as u64,
        a1: cmd::qcmd(cmd::Q_XGETQSTAT, cmd::USRQUOTA),
        a2: 0,
        a3: &mut out as *mut FsQuotaStat as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);
    args.a1 = cmd::qcmd(cmd::Q_XGETQSTATV, cmd::USRQUOTA);
    args.a3 = &mut outv as *mut FsQuotaStatv as u64;
    assert_eq!(qfd_sys::sys_quotactl_fd(&args), 0);

    assert_eq!(ops.state_calls.load(Ordering::SeqCst), 2);
    assert_eq!(out.qs_version, FS_QSTAT_VERSION);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_UDQ_ENFD | FS_QUOTA_PDQ_ACCT | FS_QUOTA_PDQ_ENFD);
    assert_eq!(out.qs_incoredqs, 12);
    assert_eq!((out.qs_uquota.qfs_ino, out.qs_uquota.qfs_nblks, out.qs_uquota.qfs_nextents), (101, 202, 3));
    assert_eq!((out.qs_gquota.qfs_ino, out.qs_gquota.qfs_nblks, out.qs_gquota.qfs_nextents), (303, 404, 6));
    assert_eq!((out.qs_btimelimit, out.qs_itimelimit, out.qs_rtbtimelimit), (31, 37, 41));
    assert_eq!((outv.qs_uquota.qfs_ino, outv.qs_pquota.qfs_ino, outv.qs_incoredqs), (101, 303, 12));
    assert_eq!((outv.qs_bwarnlimit, outv.qs_iwarnlimit, outv.qs_rtbwarnlimit), (43, 47, 53));
}
