use super::*;
use std::sync::Arc;

fn qcmd(subcmd: u64, qtype: u64) -> u64 { (subcmd << SUBCMD_SHIFT) | qtype }
fn args(cmd: u64) -> SyscallArgs { SyscallArgs { a0: cmd, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 } }
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }
const TEST_QIF_SPACE: u32 = 1 << 1;

struct QuotaOrderType;
impl vfs::FileSystemType for QuotaOrderType {
    fn name(&self) -> &str { "quota-order" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> { Err(vfs::VfsError::Einval) }
}

struct NoQuotaOps;
impl vfs::SuperOps for NoQuotaOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
}

struct UserQuotaOps;
impl vfs::SuperOps for UserQuotaOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, kind: vfs::QuotaType) -> bool { kind == vfs::QuotaType::User }
}

fn sb_with_ops(ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(QuotaOrderType), ops, 0x51554f54, 0x179, 4096, "quota-order".into(), Arc::new(()))
}

#[test]
fn quotactl_null_special_linux_order() {
    assert_eq!(sys_quotactl(&args(qcmd(Q_SYNC, USRQUOTA))), 0);
    assert_eq!(sys_quotactl(&args(qcmd(Q_GETFMT, USRQUOTA))), err(Errno::Enodev));
    assert_eq!(sys_quotactl(&args(qcmd(Q_QUOTAON, USRQUOTA))), err(Errno::Enodev));
    assert_eq!(sys_quotactl(&args(qcmd(Q_SYNC, MAXQUOTAS))), err(Errno::Einval));
}

#[test]
fn targeted_dispatch_checks_quota_ops_before_type() {
    let sb = sb_with_ops(Arc::new(NoQuotaOps));

    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_GETFMT, USRQUOTA), 0, 0), err(Errno::Enosys));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_GETFMT, MAXQUOTAS), 0, 0), err(Errno::Enosys));
}

#[test]
fn targeted_dispatch_rejects_type_before_current_task() {
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_SYNC, MAXQUOTAS), 0, 0), err(Errno::Einval));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_SYNC, GRPQUOTA), 0, 0), err(Errno::Einval));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_GETFMT, GRPQUOTA), 0, 0), err(Errno::Einval));
}

#[test]
fn targeted_dispatch_classic_supported_type_current_task_order() {
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_SYNC, USRQUOTA), 0, 0), 0);
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_GETINFO, USRQUOTA), 0, 0), err(Errno::Esrch));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_QUOTAOFF, USRQUOTA), 0, 0), err(Errno::Esrch));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_QUOTAON, USRQUOTA), vfs::QFMT_VFS_V1 as u64, 0), err(Errno::Esrch));
}

#[test]
fn targeted_dispatch_quota_usercopy_after_current_task() {
    let sb = sb_with_ops(Arc::new(UserQuotaOps));

    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_GETQUOTA, USRQUOTA), 0, 0), err(Errno::Esrch));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_GETNEXTQUOTA, USRQUOTA), 0, 0), err(Errno::Esrch));
    assert_eq!(quotactl_dispatch_sb(&sb, qcmd(Q_SETQUOTA, USRQUOTA), 0, 0), err(Errno::Esrch));
}

#[test]
fn quotactl_write_classification_matches_linux_classic_and_xfs_split() {
    assert!(!quotactl_cmd_write(qcmd(Q_SYNC, USRQUOTA)));
    assert!(!quotactl_cmd_write(qcmd(Q_GETFMT, USRQUOTA)));
    assert!(!quotactl_cmd_write(qcmd(Q_GETINFO, USRQUOTA)));

    assert!(quotactl_cmd_write(qcmd(Q_GETQUOTA, USRQUOTA)));
    assert!(quotactl_cmd_write(qcmd(Q_GETNEXTQUOTA, USRQUOTA)));
    assert!(quotactl_cmd_write(qcmd(Q_SETQUOTA, USRQUOTA)));
    assert!(quotactl_cmd_write(qcmd(Q_SETINFO, USRQUOTA)));

    assert!(!quotactl_cmd_write(qcmd(xfs::Q_XGETQSTAT, USRQUOTA)));
    assert!(!quotactl_cmd_write(qcmd(xfs::Q_XGETQSTATV, USRQUOTA)));
    assert!(!quotactl_cmd_write(qcmd(xfs::Q_XGETQUOTA, USRQUOTA)));
    assert!(!quotactl_cmd_write(qcmd(xfs::Q_XGETNEXTQUOTA, USRQUOTA)));
    assert!(!quotactl_cmd_write(qcmd(xfs::Q_XQUOTASYNC, USRQUOTA)));

    assert!(quotactl_cmd_write(qcmd(xfs::Q_XQUOTAON, USRQUOTA)));
    assert!(quotactl_cmd_write(qcmd(xfs::Q_XQUOTAOFF, USRQUOTA)));
    assert!(quotactl_cmd_write(qcmd(xfs::Q_XQUOTARM, USRQUOTA)));
    assert!(quotactl_cmd_write(qcmd(xfs::Q_XSETQLIM, USRQUOTA)));
}

#[repr(C)]
struct TestIfDqblk {
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

#[test]
fn classic_setquota_ignores_unknown_dqb_valid_bits() {
    let dq = TestIfDqblk {
        dqb_bhardlimit: 0,
        dqb_bsoftlimit: 0,
        dqb_curspace:   0,
        dqb_ihardlimit: 0,
        dqb_isoftlimit: 0,
        dqb_curinodes:  0,
        dqb_btime:      0,
        dqb_itime:      0,
        dqb_valid:      TEST_QIF_SPACE | (1 << 31),
    };
    let mem = abi::read_dqblk(&dq as *const _ as u64).unwrap();
    assert_eq!(abi::if_dqblk_fieldmask(mem.dqb_valid), vfs::DQB_SPACE);
}
