use std::sync::{Arc, Mutex, MutexGuard};
use syscall::{errno::Errno, SyscallArgs};

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
#[path = "../src/179_quotactl/sys.rs"]
mod sys;
#[path = "../src/179_quotactl_xfs.rs"]
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

fn begin_test() -> MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *SPECIAL_PATH.lock().unwrap() = None;
    READ_USER_PATH_CALLS.lock().unwrap().clear();
    sched::set_current_hook(|| None);
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

#[test]
fn block_readonly_classic_write_commands_return_erofs_before_current_task_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-classic-target-sb", 0x5155_2A11,
        "block-readonly-classic-special-sb", 0x5155_2A12);

    for subcmd in [cmd::Q_GETQUOTA, cmd::Q_GETNEXTQUOTA, cmd::Q_SETQUOTA, cmd::Q_SETINFO, cmd::Q_QUOTAOFF] {
        READ_USER_PATH_CALLS.lock().unwrap().clear();
        assert_eq!(sys::sys_quotactl(&args(subcmd)), eno(Errno::Erofs));
        assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    }
}

#[test]
fn block_readonly_quotaon_returns_erofs_after_quota_path_and_special_lookup_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-quotaon-target-sb", 0x5155_2A13,
        "block-readonly-quotaon-special-sb", 0x5155_2A14);

    assert_eq!(sys::sys_quotactl(&args(cmd::Q_QUOTAON)), eno(Errno::Erofs));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[0, SPECIAL_ADDR]);
}

#[test]
fn block_readonly_xfs_write_commands_return_erofs_before_usercopy_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-xfs-target-sb", 0x5155_2A17,
        "block-readonly-xfs-special-sb", 0x5155_2A18);

    for subcmd in [xfs::Q_XSETQLIM, xfs::Q_XQUOTAON, xfs::Q_XQUOTAOFF, xfs::Q_XQUOTARM] {
        READ_USER_PATH_CALLS.lock().unwrap().clear();
        assert_eq!(sys::sys_quotactl(&args(subcmd)), eno(Errno::Erofs));
        assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
    }
}

#[test]
fn block_readonly_getfmt_is_not_rejected_by_write_gate_hosted() {
    let _guard = begin_test();
    let _target_sb = install_readonly_target("block-readonly-getfmt-target-sb", 0x5155_2A15,
        "block-readonly-getfmt-special-sb", 0x5155_2A16);

    assert_eq!(sys::sys_quotactl(&args(cmd::Q_GETFMT)), eno(Errno::Esrch));
    assert_eq!(&*READ_USER_PATH_CALLS.lock().unwrap(), &[SPECIAL_ADDR]);
}
