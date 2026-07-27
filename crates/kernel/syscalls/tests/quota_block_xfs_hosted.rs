use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_1900;
const FS_DQUOT_VERSION: i8 = 1;
const FS_DQ_BHARD: u16 = 1 << 3;
const FS_USER_QUOTA: i8 = 1 << 0;
const FS_QUOTA_UDQ_ACCT: u32 = 1 << 0;
const FS_QUOTA_UDQ_ENFD: u32 = 1 << 1;
const FS_QUOTA_GDQ_ACCT: u32 = 1 << 2;
const FS_QUOTA_GDQ_ENFD: u32 = 1 << 3;
const FS_QUOTA_PDQ_ACCT: u32 = 1 << 4;
const FS_QUOTA_PDQ_ENFD: u32 = 1 << 5;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
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

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-block-xfs-hosted".into())
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
    fn name(&self) -> &str { "quota-block-xfs-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct XfsGetOps {
    get_calls:  AtomicU32,
    next_calls: AtomicU32,
    set_calls:  AtomicU32,
    on_calls:   AtomicU32,
    off_calls:  AtomicU32,
    rm_calls:   AtomicU32,
    kind:       AtomicU32,
    id:         AtomicU32,
    fieldmask:  AtomicU32,
    bhard:      AtomicU64,
    on_flags:   AtomicU32,
    off_flags:  AtomicU32,
    rm_flags:   AtomicU32,
}

impl XfsGetOps {
    fn new() -> Self {
        Self {
            get_calls: AtomicU32::new(0), next_calls: AtomicU32::new(0), set_calls: AtomicU32::new(0),
            on_calls: AtomicU32::new(0), off_calls: AtomicU32::new(0), rm_calls: AtomicU32::new(0),
            kind: AtomicU32::new(u32::MAX), id: AtomicU32::new(u32::MAX), fieldmask: AtomicU32::new(0),
            bhard: AtomicU64::new(0), on_flags: AtomicU32::new(0), off_flags: AtomicU32::new(0),
            rm_flags: AtomicU32::new(0),
        }
    }
}

impl vfs::SuperOps for XfsGetOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<vfs::MemDqblk> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        self.kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
        self.id.store(qid.id, Ordering::SeqCst);
        Ok(vfs::MemDqblk {
            dqb_bhardlimit: 4096,
            dqb_bsoftlimit: 2048,
            dqb_curspace: 1536,
            dqb_ihardlimit: 11,
            dqb_isoftlimit: 7,
            dqb_curinodes: 5,
            ..vfs::MemDqblk::new()
        })
    }
    fn quota_get_next_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<(vfs::Kqid, vfs::MemDqblk)> {
        self.next_calls.fetch_add(1, Ordering::SeqCst);
        self.kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
        self.id.store(qid.id, Ordering::SeqCst);
        Ok((vfs::Kqid { kind: qid.kind, id: qid.id + 9 }, vfs::MemDqblk {
            dqb_bhardlimit: 8192,
            dqb_bsoftlimit: 4096,
            dqb_curspace: 2048,
            dqb_ihardlimit: 19,
            dqb_isoftlimit: 17,
            dqb_curinodes: 13,
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

fn sb_with_ops(id: &str, s_dev: u64, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), ops, 0x5155_1900, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_inode_path(inode_sb: &Arc<vfs::SuperBlock>, ft: vfs::FileType, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x190, vfs::mk_mode(ft, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-xfs-hosted".into(), Arc::clone(&ino));
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

fn install_current(euid: u32, cap_sys_admin: bool) {
    let task = Box::leak(Box::new(sched::Task::new(0x1900, "quotactl-block-xfs-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn install_block_target(target_sb: &Arc<vfs::SuperBlock>, special_sb: &Arc<vfs::SuperBlock>) {
    vfs::superblock::register_super(target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
}

#[test]
fn sys_quotactl_block_xfs_getquota_success_reaches_hook_and_encodes_output_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-getquota-target-sb", 0x5155_1901, ops.clone());
    let special_sb = sb_with_ops("block-xfs-getquota-special-sb", 0x5155_1902, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let mut out = FsDiskQuota::default();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XGETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: &mut out as *mut FsDiskQuota as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 1000);
    assert_eq!(out.d_version, FS_DQUOT_VERSION);
    assert_eq!(out.d_flags, FS_USER_QUOTA);
    assert_eq!(out.d_id, 1000);
    assert_eq!((out.d_blk_hardlimit, out.d_blk_softlimit, out.d_bcount), (8, 4, 3));
    assert_eq!((out.d_ino_hardlimit, out.d_ino_softlimit, out.d_icount), (11, 7, 5));
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_getnextquota_success_reaches_hook_and_encodes_next_id_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-getnext-target-sb", 0x5155_1905, ops.clone());
    let special_sb = sb_with_ops("block-xfs-getnext-special-sb", 0x5155_1906, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let mut out = FsDiskQuota::default();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XGETNEXTQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: &mut out as *mut FsDiskQuota as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 1000);
    assert_eq!(out.d_version, FS_DQUOT_VERSION);
    assert_eq!(out.d_flags, FS_USER_QUOTA);
    assert_eq!(out.d_id, 1009);
    assert_eq!((out.d_blk_hardlimit, out.d_blk_softlimit, out.d_bcount), (16, 8, 4));
    assert_eq!((out.d_ino_hardlimit, out.d_ino_softlimit, out.d_icount), (19, 17, 13));
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_setqlim_success_reaches_hook_with_decoded_limits_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-setqlim-target-sb", 0x5155_1907, ops.clone());
    let special_sb = sb_with_ops("block-xfs-setqlim-special-sb", 0x5155_1908, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let mut q = FsDiskQuota { d_fieldmask: FS_DQ_BHARD, d_blk_hardlimit: 8, ..FsDiskQuota::default() };
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XSETQLIM, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: &mut q as *mut FsDiskQuota as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 1000);
    assert_eq!(ops.fieldmask.load(Ordering::SeqCst), vfs::DQB_SPC_HARD);
    assert_eq!(ops.bhard.load(Ordering::SeqCst), 4096);
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_state_mutators_success_pass_raw_flags_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-mutators-target-sb", 0x5155_1909, ops.clone());
    let special_sb = sb_with_ops("block-xfs-mutators-special-sb", 0x5155_1910, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let mut on_flags = FS_QUOTA_UDQ_ACCT | FS_QUOTA_GDQ_ENFD;
    let mut off_flags = FS_QUOTA_PDQ_ACCT | FS_QUOTA_PDQ_ENFD;
    let mut rm_flags = FS_QUOTA_UDQ_ENFD | FS_QUOTA_GDQ_ACCT | FS_QUOTA_PDQ_ACCT;
    let mut args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut on_flags as *mut u32 as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    args.a0 = cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::GRPQUOTA);
    args.a3 = &mut off_flags as *mut u32 as u64;
    assert_eq!(sys::sys_quotactl(&args), 0);
    args.a0 = cmd::qcmd(cmd::Q_XQUOTARM, cmd::PRJQUOTA);
    args.a3 = &mut rm_flags as *mut u32 as u64;
    assert_eq!(sys::sys_quotactl(&args), 0);

    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR, SPECIAL_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.on_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.off_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.rm_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.on_flags.load(Ordering::SeqCst), on_flags);
    assert_eq!(ops.off_flags.load(Ordering::SeqCst), off_flags);
    assert_eq!(ops.rm_flags.load(Ordering::SeqCst), rm_flags);
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_quotasync_success_and_readonly_error_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-quotasync-target-sb", 0x5155_1911, ops.clone());
    let special_sb = sb_with_ops("block-xfs-quotasync-special-sb", 0x5155_1912, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XQUOTASYNC, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    target_sb.set_readonly(true);
    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_setqlim_permission_denied_before_usercopy_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-setqlim-perm-target-sb", 0x5155_1913, ops.clone());
    let special_sb = sb_with_ops("block-xfs-setqlim-perm-special-sb", 0x5155_1914, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XSETQLIM, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.fieldmask.load(Ordering::SeqCst), 0);
    assert_eq!(ops.bhard.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_state_mutators_permission_denied_before_flag_usercopy_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-mutators-perm-target-sb", 0x5155_1915, ops.clone());
    let special_sb = sb_with_ops("block-xfs-mutators-perm-special-sb", 0x5155_1916, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let mut args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    args.a0 = cmd::qcmd(cmd::Q_XQUOTAOFF, cmd::USRQUOTA);
    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    args.a0 = cmd::qcmd(cmd::Q_XQUOTARM, cmd::USRQUOTA);
    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));

    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR, SPECIAL_ADDR, SPECIAL_ADDR]);
    assert_eq!(ops.on_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.off_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.rm_calls.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_getquota_permission_denied_before_hook_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(XfsGetOps::new());
    let target_sb = sb_with_ops("block-xfs-getquota-perm-target-sb", 0x5155_1903, ops.clone());
    let special_sb = sb_with_ops("block-xfs-getquota-perm-special-sb", 0x5155_1904, Arc::new(XfsGetOps::new()));
    install_block_target(&target_sb, &special_sb);
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XGETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 0);
    clear_paths();
}
