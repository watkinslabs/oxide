use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_1790;
const QUOTAON_ADDR: u64 = 0x5155_1791;
const BAD_QUOTAON_ADDR: u64 = 0x5155_1792;
const FS_QSTATV_VERSION1: i8 = 1;
const FS_QUOTA_UDQ_ACCT: u16 = 1 << 0;
const FS_QUOTA_UDQ_ENFD: u16 = 1 << 1;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static QUOTAON_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static FREEZE_TARGET: Mutex<Option<Arc<vfs::SuperBlock>>> = Mutex::new(None);
static FREEZE_PARKS: AtomicU32 = AtomicU32::new(0);
static FREEZE_WAKES: AtomicU32 = AtomicU32::new(0);
static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

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

const _: [(); 160] = [(); core::mem::size_of::<FsQuotaStatv>()];

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        match addr {
            0 | crate::BAD_QUOTAON_ADDR => Err(-(syscall::errno::Errno::Efault.as_i32() as i64)),
            crate::QUOTAON_ADDR => Ok("/quota-file-hosted".into()),
            _ => Ok("/dev/quota-block-hosted".into()),
        }
    }
}

mod pathresolve {
    pub fn resolve_path_raw(raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        match raw {
            "/quota-file-hosted" => crate::QUOTAON_PATH.lock().unwrap().clone().ok_or(vfs::VfsError::Enoent),
            _ => crate::SPECIAL_PATH.lock().unwrap().clone().ok_or(vfs::VfsError::Enoent),
        }
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
    fn name(&self) -> &str { "quota-block-hosted" }
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

struct XfsQstatOps;
impl vfs::SuperOps for XfsQstatOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
        let mut st = vfs::QuotaState::default();
        st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
            accounting: true,
            enforcement: true,
            info: vfs::MemDqinfo { dqi_bgrace: 13, dqi_igrace: 17, dqi_rt_bgrace: 19, dqi_bwarnlimit: 23, dqi_iwarnlimit: 29, dqi_rtbwarnlimit: 31, ..vfs::MemDqinfo::default() },
            file: vfs::QuotaFileStat { ino: 41, blocks: 43, nextents: 47 },
            incoredqs: 53,
        };
        Ok(st)
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

fn sb(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), Arc::new(BlockOps), 0x5155_1791, s_dev, 4096, id.into(), Arc::new(()))
}

fn sb_with_ops(id: &str, s_dev: u64, ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), ops, 0x5155_1791, s_dev, 4096, id.into(), Arc::new(()))
}

fn active_sync_sb(id: &str, s_dev: u64, ops: Arc<DqOps>) -> Arc<vfs::SuperBlock> {
    let sb = sb(id, s_dev);
    vfs::quota_on(&sb, vfs::QuotaType::User, vfs::QFMT_VFS_V1, ops).expect("quota_on");
    sb
}

fn resolved_inode_path(inode_sb: &Arc<vfs::SuperBlock>, ft: vfs::FileType, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x179, vfs::mk_mode(ft, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn clear_paths() {
    *SPECIAL_PATH.lock().unwrap() = None;
    *QUOTAON_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    *FREEZE_TARGET.lock().unwrap() = None;
    FREEZE_PARKS.store(0, Ordering::SeqCst);
    FREEZE_WAKES.store(0, Ordering::SeqCst);
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    vfs::superblock::clear_freeze_wait_hooks();
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

fn install_current(euid: u32, cap_sys_admin: bool) -> &'static sched::Task {
    let task = Box::leak(Box::new(sched::Task::new(0x1790, "quotactl-block-hosted", sched::SchedClass::Normal { weight: 1024 })));
    task.creds.euid.store(euid, Ordering::Release);
    if !cap_sys_admin {
        let mask = !(1u64 << sched::cap::SYS_ADMIN);
        task.creds.cap_effective.fetch_and(mask, Ordering::AcqRel);
    }
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
    task
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
fn sys_quotactl_block_device_uses_rdev_superblock_hosted() {
    let _guard = begin_test();
    let target_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let decoy_ops = Arc::new(DqOps { writes: AtomicU32::new(0) });
    let target_sb = active_sync_sb("target-block-sb", 0x5155_7101, target_ops.clone());
    let decoy_sb = active_sync_sb("decoy-inode-sb", 0x5155_7102, decoy_ops.clone());
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&decoy_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));

    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(target_ops.writes.load(Ordering::SeqCst), 1);
    assert_eq!(decoy_ops.writes.load(Ordering::SeqCst), 0);
    clear_paths();
}

#[test]
fn sys_quotactl_nonblock_special_returns_enotblk_hosted() {
    let _guard = begin_test();
    let inode_sb = sb("regular-special-sb", 0x5155_7103);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&inode_sb, vfs::FileType::Regular, 0));
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Enotblk));
    clear_paths();
}

#[test]
fn sys_quotactl_invalid_type_returns_einval_before_special_lookup_hosted() {
    let _guard = begin_test();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_GETFMT, cmd::MAXQUOTAS),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Einval));
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}

#[test]
fn sys_quotactl_sync_null_special_dispatches_without_path_lookup_hosted() {
    let _guard = begin_test();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SYNC, cmd::USRQUOTA),
        a1: 0,
        a2: 0,
        a3: BAD_QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}

#[test]
fn sys_quotactl_quotaon_null_special_returns_enodev_before_addr_lookup_hosted() {
    let _guard = begin_test();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: 0,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: BAD_QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Enodev));
    assert!(READ_USER_PATH_CALLS.lock().unwrap().is_empty());
}

#[test]
fn sys_quotactl_quotaon_resolves_quota_path_before_block_special_hosted() {
    let _guard = begin_test();
    let target_sb = sb("quotaon-target-sb", 0x5155_7104);
    let special_sb = sb("quotaon-special-inode-sb", 0x5155_7105);
    let quota_sb = sb("quotaon-file-sb", 0x5155_7106);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    *QUOTAON_PATH.lock().unwrap() = Some(resolved_inode_path(&quota_sb, vfs::FileType::Regular, 0));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Esrch));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[QUOTAON_ADDR, SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_quotaon_bad_quota_path_is_deferred_past_special_lookup_hosted() {
    let _guard = begin_test();
    let target_sb = sb("quotaon-defer-target-sb", 0x5155_7107);
    let special_sb = sb("quotaon-defer-special-sb", 0x5155_7108);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: BAD_QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Esrch));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_quotaon_bad_quota_path_does_not_mask_enotblk_hosted() {
    let _guard = begin_test();
    let special_sb = sb("quotaon-enotblk-special-sb", 0x5155_7109);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::Regular, 0));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: BAD_QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Enotblk));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_quotaon_bad_quota_path_does_not_mask_enodev_hosted() {
    let _guard = begin_test();
    let special_sb = sb("quotaon-enodev-special-sb", 0x5155_7110);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, 0x5155_7111));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_QUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: vfs::QFMT_VFS_V1 as u64,
        a3: BAD_QUOTAON_ADDR,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Enodev));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[BAD_QUOTAON_ADDR, SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_write_command_waits_for_frozen_block_superblock_hosted() {
    let _guard = begin_test();
    let target_sb = sb("frozen-target-sb", 0x5155_7112);
    let special_sb = sb("frozen-special-sb", 0x5155_7113);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    *FREEZE_TARGET.lock().unwrap() = Some(target_sb.clone());
    vfs::superblock::set_freeze_wait_hooks(freeze_park_hook, freeze_schedule_hook, freeze_wake_hook);
    target_sb.freeze_super().expect("freeze target superblock");
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SETINFO, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Esrch));
    assert!(!target_sb.is_frozen());
    assert_eq!(target_sb.sb_writers(), 0);
    assert_eq!(FREEZE_PARKS.load(Ordering::SeqCst), 1);
    assert!(FREEZE_WAKES.load(Ordering::SeqCst) >= 1);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_block_setquota_permission_denied_before_usercopy_hosted() {
    let _guard = begin_test();
    install_current(1000, false);
    let target_sb = sb("block-setquota-perm-target-sb", 0x5155_7114);
    let special_sb = sb("block-setquota-perm-special-sb", 0x5155_7115);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Eperm));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_block_setquota_root_reaches_usercopy_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let target_sb = sb("block-setquota-root-target-sb", 0x5155_7116);
    let special_sb = sb("block-setquota-root-special-sb", 0x5155_7117);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_SETQUOTA, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 1000,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Efault));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    clear_paths();
}

#[test]
fn sys_quotactl_block_xfs_qstatv_success_reaches_dispatch_hosted() {
    let _guard = begin_test();
    install_current(0, true);
    let target_sb = sb_with_ops("block-xfs-qstatv-target-sb", 0x5155_7118, Arc::new(XfsQstatOps));
    let special_sb = sb("block-xfs-qstatv-special-sb", 0x5155_7119);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_inode_path(&special_sb, vfs::FileType::BlockDev, target_sb.s_dev as u32));
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    let mut out = FsQuotaStatv { qs_version: FS_QSTATV_VERSION1, ..FsQuotaStatv::default() };
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XGETQSTATV, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: &mut out as *mut FsQuotaStatv as u64,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), 0);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_UDQ_ENFD);
    assert_eq!(out.qs_incoredqs, 53);
    assert_eq!((out.qs_uquota.qfs_ino, out.qs_uquota.qfs_nblks, out.qs_uquota.qfs_nextents), (41, 43, 47));
    assert_eq!((out.qs_btimelimit, out.qs_itimelimit, out.qs_rtbtimelimit), (13, 17, 19));
    assert_eq!((out.qs_bwarnlimit, out.qs_iwarnlimit, out.qs_rtbwarnlimit), (23, 29, 31));
    clear_paths();
}
