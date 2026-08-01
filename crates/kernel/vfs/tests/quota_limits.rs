use std::sync::Arc;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{DQB_RTB_COUNT, DQB_RTB_HARD, DQB_RTB_SOFT, DQB_RTB_TIMER, DQB_SPACE, DQB_SPC_HARD, DQB_SPC_SOFT, DQB_SPC_TIMER, DQF_SYS_FILE, DquotOperations, DquotUsage, IIF_BGRACE, IIF_FLAGS, KResult, Kqid, MemDqblk, MemDqinfo, QuotaType, VfsError, dquot_charge_usage};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "quotafs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

#[derive(Default)]
struct QOps;
impl DquotOperations for QOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5155, 0x1234, 4096, "quotafs".into(), Arc::new(()))
}

#[test]
fn quota_setquota_rejects_v0_limits_that_cannot_be_encoded() {
    let sb = sb();
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V0, Arc::new(QOps)).unwrap();
    assert_eq!(vfs::quota_setquota(&sb, Kqid::user(1), MemDqblk {
        dqb_bhardlimit: ((u32::MAX as u64) << 10) + 1,
        ..MemDqblk::new()
    }), Err(VfsError::Erange));
    assert_eq!(vfs::quota_setquota(&sb, Kqid::user(1), MemDqblk {
        dqb_ihardlimit: u32::MAX as u64 + 1,
        ..MemDqblk::new()
    }), Err(VfsError::Erange));
}

#[test]
fn quota_setquota_accepts_v0_maximum_encodable_limits() {
    let sb = sb();
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V0, Arc::new(QOps)).unwrap();
    let dq = MemDqblk {
        dqb_bhardlimit: (u32::MAX as u64) << 10,
        dqb_bsoftlimit: (u32::MAX as u64) << 10,
        dqb_ihardlimit: u32::MAX as u64,
        dqb_isoftlimit: u32::MAX as u64,
        ..MemDqblk::new()
    };
    vfs::quota_setquota(&sb, Kqid::user(1), dq).unwrap();
}

#[test]
fn quota_setquota_rejects_v1_limits_above_linux_core_max() {
    let sb = sb();
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    assert_eq!(vfs::quota_setquota(&sb, Kqid::user(1), MemDqblk {
        dqb_bsoftlimit: i64::MAX as u64 + 1,
        ..MemDqblk::new()
    }), Err(VfsError::Erange));
    assert_eq!(vfs::quota_setquota(&sb, Kqid::user(1), MemDqblk {
        dqb_isoftlimit: i64::MAX as u64 + 1,
        ..MemDqblk::new()
    }), Err(VfsError::Erange));
}

#[test]
fn quota_masked_setquota_checks_only_masked_limit_fields() {
    let sb = sb();
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V0, Arc::new(QOps)).unwrap();
    vfs::quota_setquota_masked(&sb, Kqid::user(1), MemDqblk {
        dqb_bsoftlimit: ((u32::MAX as u64) << 10) + 1,
        dqb_curspace: 4096,
        ..MemDqblk::new()
    }, DQB_SPACE, 0).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, Kqid::user(1)).unwrap().dqb_curspace, 4096);
    assert_eq!(vfs::quota_setquota_masked(&sb, Kqid::user(1), MemDqblk {
        dqb_bsoftlimit: ((u32::MAX as u64) << 10) + 1,
        ..MemDqblk::new()
    }, DQB_SPC_SOFT, 0), Err(VfsError::Erange));
}

#[test]
fn quota_masked_setquota_applies_linux_space_grace_timer_rules() {
    let sb = sb();
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    vfs::quota_setinfo(&sb, QuotaType::User, MemDqinfo { dqi_bgrace: 10, dqi_valid: IIF_BGRACE, ..MemDqinfo::default() }).unwrap();
    let qid = Kqid::user(1);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bsoftlimit: 100, dqb_curspace: 50, dqb_btime: 777, ..MemDqblk::new() }).unwrap();

    vfs::quota_setquota_masked(&sb, qid, MemDqblk { dqb_curspace: 150, ..MemDqblk::new() }, DQB_SPACE, 1000).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, qid).unwrap().dqb_btime, 1010);

    vfs::quota_setquota_masked(&sb, qid, MemDqblk { dqb_curspace: 175, dqb_btime: 2222, ..MemDqblk::new() }, DQB_SPACE | DQB_SPC_TIMER, 2000).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, qid).unwrap().dqb_btime, 2222);

    vfs::quota_setquota_masked(&sb, qid, MemDqblk { dqb_curspace: 50, dqb_btime: 3333, ..MemDqblk::new() }, DQB_SPACE | DQB_SPC_TIMER, 3000).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, qid).unwrap().dqb_btime, 0);
}

#[test]
fn quota_masked_setquota_preserves_linux_space_minus_reserved_semantics() {
    let sb = sb();
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    let qid = Kqid::user(1);
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_rsvspace: 10, ..MemDqblk::new() }).unwrap();
    vfs::quota_setquota_masked(&sb, qid, MemDqblk { dqb_curspace: 5, ..MemDqblk::new() }, DQB_SPACE, 0).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, qid).unwrap().dqb_curspace, 5u64.wrapping_sub(10));
}

#[test]
fn quota_masked_setquota_refuses_realtime_fields_the_generic_backend_cannot_store() {
    // A generic quota file has no realtime-device counters, so naming one is
    // EINVAL — the record must never come back reporting a limit that was
    // silently dropped. The realtime values themselves round-trip through the
    // in-core record; only the SETTER refuses them.
    let sb = sb();
    let qid = Kqid::project(7);
    vfs::quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    for mask in [DQB_RTB_HARD, DQB_RTB_SOFT, DQB_RTB_COUNT, DQB_RTB_TIMER] {
        assert_eq!(vfs::quota_setquota_masked(&sb, qid, MemDqblk {
            dqb_rtb_hardlimit: 8192, dqb_rtb_softlimit: 4096, dqb_rtbcount: 2048, dqb_rtbtimer: 33,
            ..MemDqblk::new()
        }, mask, 0), Err(VfsError::Einval));
    }
    let dq = vfs::quota_getquota(&sb, qid).unwrap();
    assert_eq!((dq.dqb_rtb_hardlimit, dq.dqb_rtb_softlimit, dq.dqb_rtbcount, dq.dqb_rtbtimer),
        (0, 0, 0, 0));
    // The fields the generic backend DOES own are still accepted alongside.
    vfs::quota_setquota_masked(&sb, qid, MemDqblk { dqb_bhardlimit: 4096, ..MemDqblk::new() },
        DQB_SPC_HARD, 0).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, qid).unwrap().dqb_bhardlimit, 4096);
}

#[test]
fn quota_limit_enforcement_can_be_disabled_while_accounting_stays_active() {
    let sb = sb();
    let qid = Kqid::user(1);
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    vfs::quota_setquota(&sb, qid, MemDqblk { dqb_bhardlimit: 100, ..MemDqblk::new() }).unwrap();

    dquot_charge_usage(&sb, 1, 0, 0, DquotUsage { space: 80, reserved_space: 0, inodes: 0 }).unwrap();
    assert_eq!(vfs::quota_disable_limits(&sb, QuotaType::User), Ok(()));
    assert!(!sb.s_dquot.is_enforced(QuotaType::User));
    dquot_charge_usage(&sb, 1, 0, 0, DquotUsage { space: 1000, reserved_space: 0, inodes: 0 }).unwrap();
    assert_eq!(vfs::quota_getquota(&sb, qid).unwrap().dqb_curspace, 1080);

    assert_eq!(vfs::quota_disable_limits(&sb, QuotaType::User), Err(VfsError::Eexist));
    assert_eq!(vfs::quota_enable_limits(&sb, QuotaType::User), Ok(()));
    assert_eq!(vfs::quota_enable_limits(&sb, QuotaType::User), Err(VfsError::Eexist));
    assert_eq!(vfs::quota_enable_limits(&sb, QuotaType::Group), Err(VfsError::Einval));
    assert_eq!(dquot_charge_usage(&sb, 1, 0, 0, DquotUsage { space: 1, reserved_space: 0, inodes: 0 }), Err(VfsError::Edquot));
}

#[test]
fn quota_enable_limits_matches_quotactl_fd_sysfile_quotaon() {
    let sb = sb();

    assert_eq!(vfs::quota_enable_limits(&sb, QuotaType::Project), Err(VfsError::Einval));

    vfs::quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    vfs::quota_disable_limits(&sb, QuotaType::Project).unwrap();

    assert!(sb.s_dquot.is_enabled(QuotaType::Project));
    assert!(!sb.s_dquot.is_enforced(QuotaType::Project));
    assert_eq!(vfs::quota_enable_limits(&sb, QuotaType::Project), Ok(()));
    assert!(sb.s_dquot.is_enabled(QuotaType::Project));
    assert!(sb.s_dquot.is_enforced(QuotaType::Project));
    assert_eq!(vfs::quota_enable_limits(&sb, QuotaType::Project), Err(VfsError::Eexist));
}

#[test]
fn quota_sysfile_active_requires_enabled_sysfile_quota_info() {
    let sb = sb();
    assert!(!vfs::quota_sysfile_active(&sb));

    vfs::quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    assert!(!vfs::quota_sysfile_active(&sb));

    sb.s_dquot.load_info(QuotaType::Project, MemDqinfo {
        dqi_flags: DQF_SYS_FILE,
        dqi_valid: IIF_FLAGS,
        ..MemDqinfo::default()
    });
    assert!(vfs::quota_sysfile_active(&sb));
}

#[test]
fn a_hard_limit_denial_records_the_warning_class_that_named_it() {
    // Every denial and every soft-limit crossing produces a warning record for
    // the netlink transport. This drains the hosted log to prove the class the
    // limit ladder chose actually reaches delivery, rather than being computed
    // and dropped.
    let sb = sb();
    let qid = Kqid::user(4242);
    vfs::quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps)).unwrap();
    vfs::quota_setquota(&sb, qid, MemDqblk {
        dqb_bhardlimit: 100, dqb_ihardlimit: 1, ..MemDqblk::new()
    }).unwrap();
    let _ = vfs::take_logged_warnings();

    assert_eq!(dquot_charge_usage(&sb, 4242, 0, 0,
        DquotUsage { space: 4096, reserved_space: 0, inodes: 0 }), Err(VfsError::Edquot));
    let warnings = vfs::take_logged_warnings();
    assert_eq!(warnings.len(), 1, "one denial, one warning");
    assert_eq!(warnings[0].qid, qid);
    assert_eq!(warnings[0].warn_type, vfs::QuotaWarnType::BHardWarn);

    assert_eq!(dquot_charge_usage(&sb, 4242, 0, 0,
        DquotUsage { space: 0, reserved_space: 0, inodes: 2 }), Err(VfsError::Edquot));
    let warnings = vfs::take_logged_warnings();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].warn_type, vfs::QuotaWarnType::IHardWarn);
}
