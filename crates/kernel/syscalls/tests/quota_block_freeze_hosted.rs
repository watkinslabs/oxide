use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

const SPECIAL_ADDR: u64 = 0x5155_17E0;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static FREEZE_TARGET: Mutex<Option<Arc<vfs::SuperBlock>>> = Mutex::new(None);
static FREEZE_PARKS: AtomicU32 = AtomicU32::new(0);
static FREEZE_WAKES: AtomicU32 = AtomicU32::new(0);
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-block-freeze-hosted".into())
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

struct BlockFreezeType;
impl vfs::FileSystemType for BlockFreezeType {
    fn name(&self) -> &str { "quota-block-freeze-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct BlockFreezeOps;
impl vfs::SuperOps for BlockFreezeOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

fn sb(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockFreezeType), Arc::new(BlockFreezeOps), 0x5155_17E0, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_block_path(inode_sb: &Arc<vfs::SuperBlock>, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x17E0, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-freeze-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *SPECIAL_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    *FREEZE_TARGET.lock().unwrap() = None;
    FREEZE_PARKS.store(0, Ordering::SeqCst);
    FREEZE_WAKES.store(0, Ordering::SeqCst);
    vfs::superblock::clear_freeze_wait_hooks();
    sched::set_current_hook(|| None);
    guard
}

fn install_block_target() -> Arc<vfs::SuperBlock> {
    let target_sb = sb("block-freeze-target-sb", 0x5155_17E1);
    let special_sb = sb("block-freeze-special-sb", 0x5155_17E2);
    vfs::superblock::register_super(&target_sb);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));
    target_sb
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
fn sys_quotactl_xfs_onoff_waits_for_frozen_block_superblock_hosted() {
    let _guard = begin_test();
    let target_sb = install_block_target();
    *FREEZE_TARGET.lock().unwrap() = Some(target_sb.clone());
    vfs::superblock::set_freeze_wait_hooks(freeze_park_hook, freeze_schedule_hook, freeze_wake_hook);
    target_sb.freeze_super().expect("freeze target superblock");
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
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
    vfs::superblock::clear_freeze_wait_hooks();
}

#[test]
fn sys_quotactl_xfs_onoff_waits_for_frozen_readonly_block_superblock_hosted() {
    let _guard = begin_test();
    let target_sb = install_block_target();
    target_sb.set_readonly(true);
    *FREEZE_TARGET.lock().unwrap() = Some(target_sb.clone());
    vfs::superblock::set_freeze_wait_hooks(freeze_park_hook, freeze_schedule_hook, freeze_wake_hook);
    target_sb.freeze_super().expect("freeze readonly target superblock");
    let args = SyscallArgs {
        a0: cmd::qcmd(cmd::Q_XQUOTAON, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    };

    assert_eq!(sys::sys_quotactl(&args), eno(Errno::Erofs));
    assert!(!target_sb.is_frozen());
    assert_eq!(target_sb.sb_writers(), 0);
    assert_eq!(FREEZE_PARKS.load(Ordering::SeqCst), 1);
    assert!(FREEZE_WAKES.load(Ordering::SeqCst) >= 1);
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    vfs::superblock::clear_freeze_wait_hooks();
}
