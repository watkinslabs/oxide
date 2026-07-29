use super::common::*;
use super::super::*;
use std::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use syscall::errno::Errno;

#[test]
fn xfs_getquota_getnext_copyout_faults_after_fs_hook() {
    struct GetOps {
        get_calls:  AtomicU32,
        next_calls: AtomicU32,
    }
    impl vfs::SuperOps for GetOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<vfs::MemDqblk> {
            self.get_calls.store(qid.id, Ordering::SeqCst);
            Ok(vfs::MemDqblk::new())
        }
        fn quota_get_next_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<(vfs::Kqid, vfs::MemDqblk)> {
            self.next_calls.store(qid.id, Ordering::SeqCst);
            Ok((vfs::Kqid { kind: qid.kind, id: qid.id + 1 }, vfs::MemDqblk::new()))
        }
    }

    let ops = Arc::new(GetOps { get_calls: AtomicU32::new(0), next_calls: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XGETQUOTA, 4096, "xfs-getquota-copyout".into(), Arc::new(()));

    assert_eq!(dispatch(&sb, Q_XGETQUOTA, vfs::QuotaType::User, 1000, 0), eno(Errno::Efault));
    assert_eq!(dispatch(&sb, Q_XGETNEXTQUOTA, vfs::QuotaType::User, 2000, 0), eno(Errno::Efault));
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 1000);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 2000);
}

#[test]
fn xfs_setqlim_id0_splits_info_timers_before_dquot_limits() {
    struct SetOps {
        seq:           AtomicU32,
        info_seq:      AtomicU32,
        info_kind:     AtomicU32,
        info_bgrace:   AtomicU64,
        info_iwarn:    AtomicU32,
        info_valid:    AtomicU32,
        set_seq:       AtomicU32,
        set_kind:      AtomicU32,
        set_id:        AtomicU32,
        set_fieldmask: AtomicU32,
        set_bhard:     AtomicU64,
        set_btime:     AtomicU64,
        set_valid:     AtomicU32,
    }
    impl SetOps {
        fn new() -> Self {
            Self {
                seq: AtomicU32::new(0), info_seq: AtomicU32::new(0), info_kind: AtomicU32::new(u32::MAX),
                info_bgrace: AtomicU64::new(0), info_iwarn: AtomicU32::new(0), info_valid: AtomicU32::new(0),
                set_seq: AtomicU32::new(0), set_kind: AtomicU32::new(u32::MAX), set_id: AtomicU32::new(u32::MAX),
                set_fieldmask: AtomicU32::new(0), set_bhard: AtomicU64::new(0), set_btime: AtomicU64::new(0),
                set_valid: AtomicU32::new(0),
            }
        }
    }
    impl vfs::SuperOps for SetOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_set_info_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_info_xfs(&self, _sb: &vfs::SuperBlock, kind: vfs::QuotaType, info: vfs::MemDqinfo) -> vfs::KResult<()> {
            self.info_seq.store(self.seq.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            self.info_kind.store(kind.slot() as u32, Ordering::SeqCst);
            self.info_bgrace.store(info.dqi_bgrace, Ordering::SeqCst);
            self.info_iwarn.store(info.dqi_iwarnlimit as u32, Ordering::SeqCst);
            self.info_valid.store(info.dqi_valid, Ordering::SeqCst);
            Ok(())
        }
        fn quota_set_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid, dqblk: vfs::MemDqblk, fieldmask: u32, _now_sec: u64) -> vfs::KResult<()> {
            self.set_seq.store(self.seq.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            self.set_kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
            self.set_id.store(qid.id, Ordering::SeqCst);
            self.set_fieldmask.store(fieldmask, Ordering::SeqCst);
            self.set_bhard.store(dqblk.dqb_bhardlimit, Ordering::SeqCst);
            self.set_btime.store(dqblk.dqb_btime as u64, Ordering::SeqCst);
            self.set_valid.store(dqblk.dqb_valid, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(SetOps::new());
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XSETQLIM, 4096, "xfs-setqlim".into(), Arc::new(()));

    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_BTIMER | FS_DQ_IWARNS | FS_DQ_BHARD | FS_DQ_BIGTIME;
    q.d_blk_hardlimit = 9;
    q.d_btimer = 5;
    q.d_btimer_hi = 0x12;
    q.d_iwarns = 77;

    assert_eq!(dispatch(&sb, Q_XSETQLIM, vfs::QuotaType::Group, 0, &mut q as *mut FsDiskQuota as u64), 0);
    assert_eq!(ops.info_seq.load(Ordering::SeqCst), 1);
    assert_eq!(ops.set_seq.load(Ordering::SeqCst), 2);
    assert_eq!(ops.info_kind.load(Ordering::SeqCst), vfs::QuotaType::Group.slot() as u32);
    assert_eq!(ops.info_bgrace.load(Ordering::SeqCst), 5);
    assert_eq!(ops.info_iwarn.load(Ordering::SeqCst), 77);
    assert_eq!(ops.info_valid.load(Ordering::SeqCst), vfs::IIF_BGRACE | vfs::IIF_IWARN);
    assert_eq!(ops.set_kind.load(Ordering::SeqCst), vfs::QuotaType::Group.slot() as u32);
    assert_eq!(ops.set_id.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_fieldmask.load(Ordering::SeqCst), vfs::DQB_SPC_HARD);
    assert_eq!(ops.set_bhard.load(Ordering::SeqCst), 4608);
    assert_eq!(ops.set_btime.load(Ordering::SeqCst), 0x12_0000_0005);
    assert_eq!(ops.set_valid.load(Ordering::SeqCst), (FS_DQ_BHARD | FS_DQ_BIGTIME) as u32);
}

#[test]
fn xfs_setqlim_id0_uses_filesystem_info_hook_without_active_generic_quota() {
    struct InfoHookOps {
        seq:           AtomicU32,
        info_seq:      AtomicU32,
        info_kind:     AtomicU32,
        info_valid:    AtomicU32,
        info_rtbwarn:  AtomicU32,
        set_seq:       AtomicU32,
        set_fieldmask: AtomicU32,
    }
    impl vfs::SuperOps for InfoHookOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_set_info_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_info_xfs(&self, _sb: &vfs::SuperBlock, kind: vfs::QuotaType, info: vfs::MemDqinfo) -> vfs::KResult<()> {
            self.info_seq.store(self.seq.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            self.info_kind.store(kind.slot() as u32, Ordering::SeqCst);
            self.info_valid.store(info.dqi_valid, Ordering::SeqCst);
            self.info_rtbwarn.store(info.dqi_rtbwarnlimit as u32, Ordering::SeqCst);
            Ok(())
        }
        fn quota_set_xfs(&self, _sb: &vfs::SuperBlock, _qid: vfs::Kqid, _dqblk: vfs::MemDqblk, fieldmask: u32, _now_sec: u64) -> vfs::KResult<()> {
            self.set_seq.store(self.seq.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            self.set_fieldmask.store(fieldmask, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(InfoHookOps {
        seq: AtomicU32::new(0), info_seq: AtomicU32::new(0), info_kind: AtomicU32::new(u32::MAX),
        info_valid: AtomicU32::new(0), info_rtbwarn: AtomicU32::new(0), set_seq: AtomicU32::new(0),
        set_fieldmask: AtomicU32::new(u32::MAX),
    });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XSETQLIM, 4096, "xfs-setqlim-info-hook".into(), Arc::new(()));
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_RTBWARNS;
    q.d_rtbwarns = 19;

    assert_eq!(dispatch(&sb, Q_XSETQLIM, vfs::QuotaType::Project, 0, &mut q as *mut FsDiskQuota as u64), 0);
    assert_eq!(ops.info_seq.load(Ordering::SeqCst), 1);
    assert_eq!(ops.set_seq.load(Ordering::SeqCst), 2);
    assert_eq!(ops.info_kind.load(Ordering::SeqCst), vfs::QuotaType::Project.slot() as u32);
    assert_eq!(ops.info_valid.load(Ordering::SeqCst), vfs::IIF_RTBWARN);
    assert_eq!(ops.info_rtbwarn.load(Ordering::SeqCst), 19);
    assert_eq!(ops.set_fieldmask.load(Ordering::SeqCst), 0);
}

#[test]
fn xfs_setqlim_nonzero_warning_only_reaches_empty_limit_update() {
    struct WarnOps {
        calls:     AtomicU32,
        kind:      AtomicU32,
        id:        AtomicU32,
        fieldmask: AtomicU32,
        valid:     AtomicU32,
    }
    impl vfs::SuperOps for WarnOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_set_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid, dqblk: vfs::MemDqblk, fieldmask: u32, _now_sec: u64) -> vfs::KResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
            self.id.store(qid.id, Ordering::SeqCst);
            self.fieldmask.store(fieldmask, Ordering::SeqCst);
            self.valid.store(dqblk.dqb_valid, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(WarnOps {
        calls: AtomicU32::new(0), kind: AtomicU32::new(u32::MAX), id: AtomicU32::new(0),
        fieldmask: AtomicU32::new(u32::MAX), valid: AtomicU32::new(0),
    });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XSETQLIM, 4096, "xfs-setqlim-warn".into(), Arc::new(()));
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_BWARNS;
    q.d_bwarns = 12;

    assert_eq!(dispatch(&sb, Q_XSETQLIM, vfs::QuotaType::User, 1000, &mut q as *mut FsDiskQuota as u64), 0);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 1000);
    assert_eq!(ops.fieldmask.load(Ordering::SeqCst), 0);
    assert_eq!(ops.valid.load(Ordering::SeqCst), FS_DQ_BWARNS as u32);
}

#[test]
fn xfs_setqlim_checks_set_dqblk_support_before_info_update() {
    struct InfoOnlyOps { info_calls: AtomicU32 }
    impl vfs::SuperOps for InfoOnlyOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_set_info_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_info_xfs(&self, _sb: &vfs::SuperBlock, _kind: vfs::QuotaType, _info: vfs::MemDqinfo) -> vfs::KResult<()> {
            self.info_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(InfoOnlyOps { info_calls: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XSETQLIM, 4096, "xfs-setqlim-no-setdqblk".into(), Arc::new(()));
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_BTIMER;
    q.d_btimer = 5;

    assert_eq!(dispatch(&sb, Q_XSETQLIM, vfs::QuotaType::User, 0, &mut q as *mut FsDiskQuota as u64), eno(Errno::Enosys));
    assert_eq!(ops.info_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn xfs_setqlim_missing_info_hook_is_einval_after_set_dqblk_support() {
    struct SetOnlyOps { set_calls: AtomicU32 }
    impl vfs::SuperOps for SetOnlyOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_set_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_set_xfs(&self, _sb: &vfs::SuperBlock, _qid: vfs::Kqid, _dqblk: vfs::MemDqblk, _fieldmask: u32, _now_sec: u64) -> vfs::KResult<()> {
            self.set_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(SetOnlyOps { set_calls: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XSETQLIM, 4096, "xfs-setqlim-no-setinfo".into(), Arc::new(()));
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_IWARNS;
    q.d_iwarns = 9;

    assert_eq!(dispatch(&sb, Q_XSETQLIM, vfs::QuotaType::Group, 0, &mut q as *mut FsDiskQuota as u64), eno(Errno::Einval));
    assert_eq!(ops.set_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn xfs_getquota_calls_fs_hook_and_encodes_output() {
    struct GetOps {
        calls: AtomicU32,
        kind:  AtomicU32,
        id:    AtomicU32,
    }
    impl vfs::SuperOps for GetOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<vfs::MemDqblk> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.kind.store(qid.kind.slot() as u32, Ordering::SeqCst);
            self.id.store(qid.id, Ordering::SeqCst);
            Ok(vfs::MemDqblk {
                dqb_bhardlimit: 4096,
                dqb_bsoftlimit: 2048,
                dqb_curspace: 1536,
                dqb_ihardlimit: 17,
                dqb_isoftlimit: 13,
                dqb_curinodes: 9,
                dqb_btime: 22,
                dqb_itime: 33,
                dqb_rtb_hardlimit: 8192,
                dqb_rtb_softlimit: 4096,
                dqb_rtbcount: 512,
                dqb_rtbtimer: 44,
                ..vfs::MemDqblk::new()
            })
        }
    }

    let ops = Arc::new(GetOps { calls: AtomicU32::new(0), kind: AtomicU32::new(u32::MAX), id: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XGETQUOTA, 4096, "xfs-getquota".into(), Arc::new(()));
    let mut out = empty_quota();

    assert_eq!(dispatch(&sb, Q_XGETQUOTA, vfs::QuotaType::Project, 42, &mut out as *mut FsDiskQuota as u64), 0);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 1);
    assert_eq!(ops.kind.load(Ordering::SeqCst), vfs::QuotaType::Project.slot() as u32);
    assert_eq!(ops.id.load(Ordering::SeqCst), 42);
    assert_eq!(out.d_version, FS_DQUOT_VERSION);
    assert_eq!(out.d_flags, FS_PROJ_QUOTA);
    assert_eq!(out.d_fieldmask, 0);
    assert_eq!(out.d_id, 42);
    assert_eq!(out.d_blk_hardlimit, 8);
    assert_eq!(out.d_bcount, 3);
    assert_eq!(out.d_icount, 9);
    assert_eq!(out.d_btimer, 22);
    assert_eq!(out.d_itimer, 33);
    assert_eq!(out.d_rtb_hardlimit, 16);
    assert_eq!(out.d_rtbcount, 1);
    assert_eq!(out.d_rtbtimer, 44);
}

#[test]
fn xfs_getnextquota_uses_start_id_and_writes_next_id() {
    struct NextOps {
        start_id: AtomicU32,
    }
    impl vfs::SuperOps for NextOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_next_xfs(&self, _sb: &vfs::SuperBlock, qid: vfs::Kqid) -> vfs::KResult<(vfs::Kqid, vfs::MemDqblk)> {
            self.start_id.store(qid.id, Ordering::SeqCst);
            Ok((vfs::Kqid { kind: qid.kind, id: 7000 }, vfs::MemDqblk {
                dqb_bhardlimit: 512,
                dqb_bsoftlimit: 512,
                dqb_curspace: 512,
                dqb_btime: i32::MAX as i64 + 1,
                ..vfs::MemDqblk::new()
            }))
        }
    }

    let ops = Arc::new(NextOps { start_id: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XGETNEXTQUOTA, 4096, "xfs-getnextquota".into(), Arc::new(()));
    let mut out = empty_quota();

    assert_eq!(dispatch(&sb, Q_XGETNEXTQUOTA, vfs::QuotaType::Group, 6999, &mut out as *mut FsDiskQuota as u64), 0);
    assert_eq!(ops.start_id.load(Ordering::SeqCst), 6999);
    assert_eq!(out.d_flags, FS_GROUP_QUOTA);
    assert_eq!(out.d_id, 7000);
    assert_eq!(out.d_fieldmask, FS_DQ_BIGTIME);
    assert_eq!(out.d_blk_hardlimit, 1);
    assert_eq!(out.d_bcount, 1);
    assert_eq!(out.d_btimer, i32::MIN);
    assert_eq!(out.d_btimer_hi, 0);
}

#[test]
fn xfs_quotaon_quotaoff_validate_and_pass_raw_flags() {
    const UNKNOWN_XFS_QUOTA_FLAG: u32 = 1u32 << 31;

    struct OnOffOps {
        on_flags:  AtomicU32,
        off_flags: AtomicU32,
    }
    impl vfs::SuperOps for OnOffOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_enable_xfs(&self, _sb: &vfs::SuperBlock, flags: u32) -> vfs::KResult<()> {
            self.on_flags.store(flags, Ordering::SeqCst);
            Ok(())
        }
        fn quota_enable_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_disable_xfs(&self, _sb: &vfs::SuperBlock, flags: u32) -> vfs::KResult<()> {
            self.off_flags.store(flags, Ordering::SeqCst);
            Ok(())
        }
        fn quota_disable_xfs_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    }

    let ops = Arc::new(OnOffOps { on_flags: AtomicU32::new(0), off_flags: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XQUOTAON, 4096, "xfs-onoff".into(), Arc::new(()));
    let mut flags = FS_QUOTA_UDQ_ACCT as u32 | FS_QUOTA_GDQ_ENFD as u32 | FS_QUOTA_PDQ_ACCT as u32;

    assert_eq!(dispatch(&sb, Q_XQUOTAON, vfs::QuotaType::User, 0, 0), eno(Errno::Efault));
    assert_eq!(dispatch(&sb, Q_XQUOTAOFF, vfs::QuotaType::Project, 0, 0), eno(Errno::Efault));
    assert_eq!(dispatch(&sb, Q_XQUOTAON, vfs::QuotaType::User, 0, &mut flags as *mut u32 as u64), 0);
    assert_eq!(dispatch(&sb, Q_XQUOTAOFF, vfs::QuotaType::Project, 0, &mut flags as *mut u32 as u64), 0);
    assert_eq!(ops.on_flags.load(Ordering::SeqCst), flags);
    assert_eq!(ops.off_flags.load(Ordering::SeqCst), flags);

    let valid_flags = flags;
    flags |= UNKNOWN_XFS_QUOTA_FLAG;
    assert_eq!(dispatch(&sb, Q_XQUOTAON, vfs::QuotaType::User, 0, &mut flags as *mut u32 as u64), eno(Errno::Einval));
    assert_eq!(dispatch(&sb, Q_XQUOTAOFF, vfs::QuotaType::Project, 0, &mut flags as *mut u32 as u64), eno(Errno::Einval));
    assert_eq!(ops.on_flags.load(Ordering::SeqCst), valid_flags);
    assert_eq!(ops.off_flags.load(Ordering::SeqCst), valid_flags);
}

#[test]
fn xfs_quotarm_reads_flags_before_rm_hook_support() {
    let sb = qstat_sb();
    let mut flags = FS_QUOTA_UDQ_ACCT as u32 | FS_QUOTA_PDQ_ENFD as u32;

    assert_eq!(dispatch(&sb, Q_XQUOTARM, vfs::QuotaType::User, 0, 0), eno(Errno::Efault));
    assert_eq!(
        dispatch(&sb, Q_XQUOTARM, vfs::QuotaType::User, 0, &mut flags as *mut u32 as u64),
        eno(Errno::Enosys),
    );
}

#[test]
fn xfs_quotarm_passes_raw_flags_to_filesystem_hook() {
    struct RmOps { flags: AtomicU32 }
    impl vfs::SuperOps for RmOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_remove_xfs(&self, _sb: &vfs::SuperBlock, flags: u32) -> vfs::KResult<()> {
            self.flags.store(flags, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(RmOps { flags: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, 0x5806, 4096, "xfs-rm-order".into(), Arc::new(()));
    let mut flags = FS_QUOTA_UDQ_ACCT as u32 | FS_QUOTA_GDQ_ENFD as u32 | FS_QUOTA_PDQ_ACCT as u32;

    assert_eq!(dispatch(&sb, Q_XQUOTARM, vfs::QuotaType::Project, 0, &mut flags as *mut u32 as u64), 0);
    assert_eq!(ops.flags.load(Ordering::SeqCst), flags);
}

#[test]
fn xfs_quotasync_is_ro_check_then_noop() {
    let sb = qstat_sb();

    assert_eq!(dispatch(&sb, Q_XQUOTASYNC, vfs::QuotaType::User, 0, 0), 0);
    sb.set_readonly(true);
    assert_eq!(dispatch(&sb, Q_XQUOTASYNC, vfs::QuotaType::User, 0, 0), eno(Errno::Erofs));
}
