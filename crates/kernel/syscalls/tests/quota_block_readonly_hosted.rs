// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

static CURRENT_TASK_PTR: AtomicU64 = AtomicU64::new(0);

const SPECIAL_ADDR: u64 = 0x5155_2A10;

static SPECIAL_PATH: Mutex<Option<vfs::VfsPath>> = Mutex::new(None);
static READ_USER_PATH_CALLS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(addr: u64) -> Result<String, i64> {
        crate::READ_USER_PATH_CALLS.lock().unwrap().push(addr);
        Ok("/dev/quota-block-readonly-hosted".into())
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
#[path = "../src/179_quotactl/qidns.rs"]
mod qidns;
#[path = "../src/179_quotactl/sys.rs"]
mod sys;
#[path = "../src/179_quotactl_xfs/core.rs"]
mod xfs;

struct BlockType;
impl vfs::FileSystemType for BlockType {
    fn name(&self) -> &str { "quota-block-readonly-hosted" }
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

fn sb_with_dev(id: &str, s_dev: u64) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(BlockType), Arc::new(BlockOps), 0x5155_2A10, s_dev, 4096, id.into(), Arc::new(()))
}

fn resolved_block_path(inode_sb: &Arc<vfs::SuperBlock>, rdev: u32) -> vfs::VfsPath {
    let ino = vfs::InodeBuilder::new(0x2A1, vfs::mk_mode(vfs::FileType::BlockDev, 0o660),
        vfs::default_inode_ops(), vfs::default_file_ops())
        .sb(Arc::downgrade(inode_sb))
        .rdev(rdev)
        .build();
    let d = vfs::Dentry::new(None, "quota-block-readonly-hosted".into(), Arc::clone(&ino));
    vfs::VfsPath { mnt_id: 0, dentry: d, inode: ino, last_component: None }
}

fn hosted_current_task() -> Option<&'static sched::Task> {
    let ptr = CURRENT_TASK_PTR.load(Ordering::Acquire);
    if ptr == 0 { return None; }
    // SAFETY: tests store leaked Task pointers and clear only between serialized cases.
    Some(unsafe { &*(ptr as *const sched::Task) })
}

/// Publish a privileged caller so a command reaches its own errno instead of
/// stopping at the no-current-task rung. # C: O(1)
fn install_root_current() {
    let task = Box::leak(Box::new(sched::Task::new(0x2a10, "quotactl-block-readonly-hosted",
        sched::SchedClass::Normal { weight: 1024 })));
    CURRENT_TASK_PTR.store(task as *const sched::Task as u64, Ordering::Release);
}

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *SPECIAL_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    CURRENT_TASK_PTR.store(0, Ordering::Release);
    sched::set_current_hook(hosted_current_task);
    guard
}

fn install_readonly_target(target_id: &str, target_dev: u64, special_id: &str, special_dev: u64) -> Arc<vfs::SuperBlock> {
    let target_sb = sb_with_dev(target_id, target_dev);
    let special_sb = sb_with_dev(special_id, special_dev);
    vfs::superblock::register_super(&target_sb);
    target_sb.set_readonly(true);
    *SPECIAL_PATH.lock().unwrap() = Some(resolved_block_path(&special_sb, target_sb.s_dev as u32));
    target_sb
}

fn args(subcmd: u64) -> SyscallArgs {
    SyscallArgs {
        a0: cmd::qcmd(subcmd, cmd::USRQUOTA),
        a1: SPECIAL_ADDR,
        a2: 0,
        a3: 0,
        a4: 0,
        a5: 0,
    }
}

// Device-targeted `quotactl(2)` takes no write reference on the target, so a
// READ-ONLY superblock changes nothing about which errno a command returns.
// Every assertion below is paired: the same command against a writable target
// must produce the same answer.

#[test]
fn block_readonly_classic_write_commands_are_not_rejected_by_a_write_gate_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-classic-target-sb", 0x5155_2A11,
        "block-readonly-classic-special-sb", 0x5155_2A12);

    for subcmd in [cmd::Q_GETQUOTA, cmd::Q_GETNEXTQUOTA, cmd::Q_SETQUOTA, cmd::Q_SETINFO, cmd::Q_QUOTAOFF] {
        READ_USER_PATH_CALLS.lock().unwrap().clear();
        assert_eq!(sys::sys_quotactl(&args(subcmd)), eno(Errno::Esrch),
            "a read-only target must not short-circuit a classic write command to EROFS");
        assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    }
}

#[test]
fn block_writable_and_readonly_targets_agree_on_every_classic_write_command_hosted() {
    let _guard = begin_test();
    let target_sb = install_readonly_target("block-rw-parity-target-sb", 0x5155_2A19,
        "block-rw-parity-special-sb", 0x5155_2A1A);

    for subcmd in [cmd::Q_GETQUOTA, cmd::Q_GETNEXTQUOTA, cmd::Q_SETQUOTA, cmd::Q_SETINFO, cmd::Q_QUOTAOFF] {
        target_sb.set_readonly(true);
        let ro = sys::sys_quotactl(&args(subcmd));
        target_sb.set_readonly(false);
        let rw = sys::sys_quotactl(&args(subcmd));
        assert_eq!(ro, rw, "read-only state must not alter a classic write command's errno");
    }
}

#[test]
fn block_readonly_quotaon_is_not_rejected_by_a_write_gate_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-quotaon-target-sb", 0x5155_2A13,
        "block-readonly-quotaon-special-sb", 0x5155_2A14);

    assert_eq!(sys::sys_quotactl(&args(cmd::Q_QUOTAON)), eno(Errno::Esrch));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[0, SPECIAL_ADDR]);
}

#[test]
fn block_readonly_xfs_write_commands_are_not_rejected_by_a_write_gate_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-xfs-target-sb", 0x5155_2A17,
        "block-readonly-xfs-special-sb", 0x5155_2A18);

    for subcmd in [xfs::Q_XSETQLIM, xfs::Q_XQUOTAON, xfs::Q_XQUOTAOFF, xfs::Q_XQUOTARM] {
        READ_USER_PATH_CALLS.lock().unwrap().clear();
        assert_eq!(sys::sys_quotactl(&args(subcmd)), eno(Errno::Esrch),
            "a read-only target must not short-circuit an XFS write command to EROFS");
        assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    }
}

#[test]
fn block_readonly_quota_sync_is_the_only_command_that_reports_erofs_hosted() {
    // The single read-only rejection quota control has: the XFS quota-sync
    // command names it explicitly. Its writable-target counterpart succeeds.
    let _guard = begin_test();
    let target_sb = install_readonly_target("block-readonly-xqsync-target-sb", 0x5155_2A1B,
        "block-readonly-xqsync-special-sb", 0x5155_2A1C);
    install_root_current();

    assert_eq!(sys::sys_quotactl(&args(xfs::Q_XQUOTASYNC)), eno(Errno::Erofs));
    target_sb.set_readonly(false);
    assert_eq!(sys::sys_quotactl(&args(xfs::Q_XQUOTASYNC)), 0);
}

#[test]
fn block_readonly_getfmt_is_not_rejected_by_write_gate_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-getfmt-target-sb", 0x5155_2A15,
        "block-readonly-getfmt-special-sb", 0x5155_2A16);

    assert_eq!(sys::sys_quotactl(&args(cmd::Q_GETFMT)), eno(Errno::Esrch));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}
