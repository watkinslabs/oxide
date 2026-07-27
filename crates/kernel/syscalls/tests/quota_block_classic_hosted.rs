use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_17A0;
const IIF_CLASSIC_ALL: u32 = vfs::IIF_BGRACE | vfs::IIF_IGRACE | vfs::IIF_FLAGS;
const QIF_ALL: u32 = 0x3f;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
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
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-block-classic-hosted".into())
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
    fn name(&self) -> &str { "quota-block-classic-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct BlockOps;
impl vfs::SuperOps for BlockOps {
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

fn sb_with_dev(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), Arc::new(BlockOps), 0x5155_17A0, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_inode_path(inode_sb: &Arc<vfs::SuperBlock>, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x17A, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-classic-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests leak Task pointers for the process lifetime and serialize current-task replacement.
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
    let task = Box::leak(Box::new(sched::Task::new(0x17A0, "quotactl-block-classic-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn install_block_target(target_sb: &Arc<vfs::SuperBlock>, special_sb: &Arc<vfs::SuperBlock>) {
    vfs::superblock::register_super(target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(special_sb, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
}

fn active_quota_target(id: &str, s_dev: u64, ops: Arc<InfoOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb_with_dev(id, s_dev);
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, ops).expect("quota_on");
    sb
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
fn sys_quotactl_block_getfmt_success_writes_active_format_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-getfmt-target-sb", 0x5155_17A7, ops);
    let special_sb = sb_with_dev("block-classic-getfmt-special-sb", 0x5155_17A8);
    install_block_target(&target_sb, &special_sb);
    let mut out = 0u32;
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETFMT, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut out as *mut u32 as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(out, vfs::QFMT_VFS_V1);
}

#[test]
fn sys_quotactl_block_getquota_success_encodes_classic_dqblk_hosted() {
    let _guard = begin_test();
    install_current(77, false);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-getquota-target-sb", 0x5155_17A9, ops);
    let special_sb = sb_with_dev("block-classic-getquota-special-sb", 0x5155_17AA);
    seed_user_quota(&target_sb, 77);
    install_block_target(&target_sb, &special_sb);
    let mut out = IfDqblk::default();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 77,
        a3: &mut out as *mut IfDqblk as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_classic_dqblk(&out);
}

#[test]
fn sys_quotactl_block_getquota_permission_denied_after_lookup_before_null_copyout_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-getquota-perm-target-sb", 0x5155_17AD, ops);
    let special_sb = sb_with_dev("block-classic-getquota-perm-special-sb", 0x5155_17AE);
    install_block_target(&target_sb, &special_sb);
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 77,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}

#[test]
fn sys_quotactl_block_getnextquota_success_encodes_next_id_and_dqblk_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(InfoOps::new());
    ops.next.store(81, Ordering::SeqCst);
    let target_sb = active_quota_target("block-classic-getnext-target-sb", 0x5155_17AB, ops);
    let special_sb = sb_with_dev("block-classic-getnext-special-sb", 0x5155_17AC);
    seed_user_quota(&target_sb, 81);
    install_block_target(&target_sb, &special_sb);
    let mut out = IfNextDqblk::default();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 50,
        a3: &mut out as *mut IfNextDqblk as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
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
fn sys_quotactl_block_getnextquota_permission_denied_after_lookup_before_backend_and_null_copyout_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(InfoOps::new());
    ops.next.store(81, Ordering::SeqCst);
    let target_sb = active_quota_target("block-classic-getnext-perm-target-sb", 0x5155_17AF, ops.clone());
    let special_sb = sb_with_dev("block-classic-getnext-perm-special-sb", 0x5155_17B1);
    install_block_target(&target_sb, &special_sb);
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETNEXTQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 77,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.next_hits.load(Ordering::SeqCst), 0);
}

#[test]
fn sys_quotactl_block_setquota_success_decodes_classic_dqblk_after_lookup_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-setquota-target-sb", 0x5155_17B2, ops);
    let special_sb = sb_with_dev("block-classic-setquota-special-sb", 0x5155_17B3);
    install_block_target(&target_sb, &special_sb);
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
        a0: cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 90,
        a3: &mut dq as *mut IfDqblk as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_setquota_record(&target_sb, 90);
}

#[test]
fn sys_quotactl_block_getinfo_success_encodes_classic_info_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-getinfo-target-sb", 0x5155_17A1, ops.clone());
    let special_sb = sb_with_dev("block-classic-getinfo-special-sb", 0x5155_17A2);
    vfs::quota_setinfo(&target_sb, vfs::QuotaType::User, vfs::MemDqinfo {
        dqi_bgrace: 111,
        dqi_igrace: 222,
        dqi_flags:  0,
        dqi_valid:  IIF_CLASSIC_ALL,
        ..vfs::MemDqinfo::default()
    }).expect("seed quota info");
    install_block_target(&target_sb, &special_sb);
    let mut out = IfDqinfo::default();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETINFO, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut out as *mut IfDqinfo as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(out.dqi_bgrace, 111);
    assert_eq!(out.dqi_igrace, 222);
    assert_eq!(out.dqi_flags, 0);
    assert_eq!(out.dqi_valid, IIF_CLASSIC_ALL);
}

#[test]
fn sys_quotactl_block_setinfo_success_updates_info_after_block_lookup_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-setinfo-target-sb", 0x5155_17A3, ops.clone());
    let special_sb = sb_with_dev("block-classic-setinfo-special-sb", 0x5155_17A4);
    install_block_target(&target_sb, &special_sb);
    let mut info = IfDqinfo {
        dqi_bgrace: 333,
        dqi_igrace: 444,
        dqi_flags:  0,
        dqi_valid:  vfs::IIF_BGRACE | vfs::IIF_IGRACE | vfs::IIF_FLAGS,
    };
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut info as *mut IfDqinfo as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.writes.load(Ordering::SeqCst), 1);
    assert_eq!(ops.bgrace.load(Ordering::SeqCst), 333);
    assert_eq!(ops.igrace.load(Ordering::SeqCst), 444);
    assert_eq!(ops.flags.load(Ordering::SeqCst), 0);
    assert_eq!(ops.valid.load(Ordering::SeqCst), vfs::IIF_ALL);
    let got = vfs::quota_getinfo(&target_sb, vfs::QuotaType::User).expect("updated quota info");
    assert_eq!(got.dqi_bgrace, 333);
    assert_eq!(got.dqi_igrace, 444);
    assert_eq!(got.dqi_flags, 0);
}

#[test]
fn sys_quotactl_block_setinfo_permission_denied_before_usercopy_hosted() {
    let _guard = begin_test();
    install_current(2000, false);
    let ops = Arc::new(InfoOps::new());
    let target_sb = active_quota_target("block-classic-setinfo-perm-target-sb", 0x5155_17A5, ops.clone());
    let special_sb = sb_with_dev("block-classic-setinfo-perm-special-sb", 0x5155_17A6);
    install_block_target(&target_sb, &special_sb);
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(ops.writes.load(Ordering::SeqCst), 0);
}
