use super::common::*;
use super::super::*;
use std::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use syscall::errno::Errno;

#[test]
fn xfs_bigtime_timer_roundtrip_sets_only_bigtime_fieldmask() {
    let dq = vfs::MemDqblk {
        dqb_btime: i32::MAX as i64 + 33,
        dqb_itime: -7,
        dqb_rtbtimer: i32::MIN as i64 - 9,
        dqb_bhardlimit: 4096,
        dqb_bsoftlimit: 2048,
        dqb_curspace: 1536,
        dqb_rtb_hardlimit: 8192,
        dqb_rtb_softlimit: 4096,
        dqb_rtbcount: 1024,
        ..vfs::MemDqblk::new()
    };

    let q = mem_to_xfs_quota(vfs::QuotaType::Project, 77, dq);

    assert_eq!(q.d_fieldmask, FS_DQ_BIGTIME);
    assert_eq!(q.d_flags, FS_PROJ_QUOTA);
    assert_eq!(q.d_id, 77);
    assert_eq!(q.d_btimer_hi, (dq.dqb_btime >> 32) as i8);
    assert_eq!(q.d_itimer_hi, (dq.dqb_itime >> 32) as i8);
    assert_eq!(q.d_rtbtimer_hi, (dq.dqb_rtbtimer >> 32) as i8);

    let round = xfs_to_mem_quota(q);
    assert_eq!(round.dqb_btime, dq.dqb_btime);
    assert_eq!(round.dqb_itime, dq.dqb_itime);
    assert_eq!(round.dqb_rtbtimer, dq.dqb_rtbtimer);
    assert_eq!(round.dqb_bhardlimit, dq.dqb_bhardlimit);
    assert_eq!(round.dqb_rtb_hardlimit, dq.dqb_rtb_hardlimit);
}

#[test]
fn xfs_id0_info_timer_ignores_bigtime_high_byte() {
    let q = FsDiskQuota {
        d_version: FS_DQUOT_VERSION,
        d_flags: FS_USER_QUOTA,
        d_fieldmask: FS_DQ_BTIMER | FS_DQ_BIGTIME,
        d_id: 0,
        d_blk_hardlimit: 0,
        d_blk_softlimit: 0,
        d_ino_hardlimit: 0,
        d_ino_softlimit: 0,
        d_bcount: 0,
        d_icount: 0,
        d_itimer: 0,
        d_btimer: -7,
        d_iwarns: 0,
        d_bwarns: 0,
        d_itimer_hi: 0,
        d_btimer_hi: 0x7f,
        d_rtbtimer_hi: 0,
        d_padding2: 0,
        d_rtb_hardlimit: 0,
        d_rtb_softlimit: 0,
        d_rtbcount: 0,
        d_rtbtimer: 0,
        d_rtbwarns: 0,
        d_padding3: 0,
        d_padding4: [0; 8],
    };

    assert_eq!(decode_timer(&q, q.d_btimer, q.d_btimer_hi), 0x7f_ffff_fff9);
    assert_eq!(xfs_info_timer(q.d_btimer), u32::MAX as u64 - 6);
}

#[test]
fn xfs_qstatv_checks_get_state_support_before_user_version() {
    let sb = qstat_sb();

    assert_eq!(dispatch(&sb, Q_XGETQSTATV, vfs::QuotaType::User, 0, 0), eno(Errno::Enosys));
}

#[test]
fn xfs_qstatv_reads_version_before_state_snapshot() {
    struct StateOps { calls: AtomicU32 }
    impl vfs::SuperOps for StateOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vfs::QuotaState::default())
        }
    }

    let ops = Arc::new(StateOps { calls: AtomicU32::new(0) });
    let sb = vfs::SuperBlock::new(Arc::new(QstatType), ops.clone(), 0x51544154, Q_XGETQSTATV, 4096, "xfs-qstatv-version".into(), Arc::new(()));
    let mut wrong_version = 0i8;

    assert_eq!(dispatch(&sb, Q_XGETQSTATV, vfs::QuotaType::User, 0, 0), eno(Errno::Efault));
    assert_eq!(
        dispatch(&sb, Q_XGETQSTATV, vfs::QuotaType::User, 0, &mut wrong_version as *mut i8 as u64),
        eno(Errno::Einval),
    );
    assert_eq!(ops.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn xfs_qgetqstat_maps_filesystem_state_and_project_group_fallback() {
    struct StateOps;
    impl vfs::SuperOps for StateOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
            let mut st = vfs::QuotaState::default();
            st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
                accounting: true,
                enforcement: true,
                info: vfs::MemDqinfo { dqi_bgrace: 11, dqi_igrace: 22, dqi_rt_bgrace: 33, dqi_bwarnlimit: 44, dqi_iwarnlimit: 55, ..vfs::MemDqinfo::default() },
                file: vfs::QuotaFileStat { ino: 101, blocks: 202, nextents: 3 },
                incoredqs: 7,
            };
            st.types[vfs::QuotaType::Group.slot()] = vfs::QuotaTypeState {
                accounting: false,
                enforcement: false,
                file: vfs::QuotaFileStat { ino: 404, blocks: 505, nextents: 6 },
                incoredqs: 8,
                ..vfs::QuotaTypeState::default()
            };
            st.types[vfs::QuotaType::Project.slot()] = vfs::QuotaTypeState {
                accounting: true,
                enforcement: false,
                file: vfs::QuotaFileStat { ino: 707, blocks: 808, nextents: 9 },
                incoredqs: 10,
                ..vfs::QuotaTypeState::default()
            };
            Ok(st)
        }
    }

    let sb = vfs::SuperBlock::new(Arc::new(QstatType), Arc::new(StateOps), 0x51544154, Q_XGETQSTAT, 4096, "xfs-qstat-state".into(), Arc::new(()));
    let mut out = FsQuotaStat::default();

    assert_eq!(dispatch(&sb, Q_XGETQSTAT, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStat as u64), 0);
    assert_eq!(out.qs_version, FS_QSTAT_VERSION);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_UDQ_ENFD | FS_QUOTA_PDQ_ACCT);
    assert_eq!(out.qs_uquota.qfs_ino, 101);
    assert_eq!(out.qs_uquota.qfs_nblks, 202);
    assert_eq!(out.qs_uquota.qfs_nextents, 3);
    assert_eq!(out.qs_gquota.qfs_ino, 707);
    assert_eq!(out.qs_gquota.qfs_nblks, 808);
    assert_eq!(out.qs_gquota.qfs_nextents, 9);
    assert_eq!(out.qs_incoredqs, 25);
    assert_eq!(out.qs_btimelimit, 11);
    assert_eq!(out.qs_itimelimit, 22);
    assert_eq!(out.qs_rtbtimelimit, 33);
    assert_eq!(out.qs_bwarnlimit, 44);
    assert_eq!(out.qs_iwarnlimit, 55);
}

#[test]
fn xfs_qstatv_maps_all_filesystem_state_slots() {
    struct StatevOps;
    impl vfs::SuperOps for StatevOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
            let mut st = vfs::QuotaState::default();
            st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
                accounting: true,
                enforcement: false,
                info: vfs::MemDqinfo { dqi_bgrace: 12, dqi_igrace: 23, dqi_rt_bgrace: 34, dqi_bwarnlimit: 45, dqi_iwarnlimit: 56, dqi_rtbwarnlimit: 67, ..vfs::MemDqinfo::default() },
                file: vfs::QuotaFileStat { ino: 111, blocks: 222, nextents: 3 },
                incoredqs: 4,
            };
            st.types[vfs::QuotaType::Group.slot()] = vfs::QuotaTypeState {
                accounting: false,
                enforcement: false,
                file: vfs::QuotaFileStat { ino: 333, blocks: 444, nextents: 5 },
                incoredqs: 6,
                ..vfs::QuotaTypeState::default()
            };
            st.types[vfs::QuotaType::Project.slot()] = vfs::QuotaTypeState {
                accounting: true,
                enforcement: true,
                file: vfs::QuotaFileStat { ino: 555, blocks: 666, nextents: 7 },
                incoredqs: 8,
                ..vfs::QuotaTypeState::default()
            };
            Ok(st)
        }
    }

    let sb = vfs::SuperBlock::new(Arc::new(QstatType), Arc::new(StatevOps), 0x51544154, Q_XGETQSTATV, 4096, "xfs-qstatv-state".into(), Arc::new(()));
    let mut out = FsQuotaStatv { qs_version: FS_QSTATV_VERSION1, ..FsQuotaStatv::default() };

    assert_eq!(dispatch(&sb, Q_XGETQSTATV, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStatv as u64), 0);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_PDQ_ACCT | FS_QUOTA_PDQ_ENFD);
    assert_eq!((out.qs_uquota.qfs_ino, out.qs_gquota.qfs_ino, out.qs_pquota.qfs_ino), (111, 333, 555));
    assert_eq!((out.qs_uquota.qfs_nblks, out.qs_gquota.qfs_nblks, out.qs_pquota.qfs_nblks), (222, 444, 666));
    assert_eq!((out.qs_uquota.qfs_nextents, out.qs_gquota.qfs_nextents, out.qs_pquota.qfs_nextents), (3, 5, 7));
    assert_eq!(out.qs_incoredqs, 18);
    assert_eq!((out.qs_btimelimit, out.qs_itimelimit, out.qs_rtbtimelimit), (12, 23, 34));
    assert_eq!((out.qs_bwarnlimit, out.qs_iwarnlimit, out.qs_rtbwarnlimit), (45, 56, 67));
}

// A quota inode can exist while its class is inactive. Q_XGETQSTAT reports
// each slot whenever an inode number is present, so an inactive group class
// with a real quota inode is still reported — the project slot only borrows
// the group slot when a project quota inode actually exists.
#[test]
fn xfs_qgetqstat_reports_inactive_group_inode_when_no_project_inode() {
    struct StateOps;
    impl vfs::SuperOps for StateOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
            let mut st = vfs::QuotaState::default();
            st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
                accounting: true,
                file: vfs::QuotaFileStat { ino: 101, blocks: 202, nextents: 3 },
                ..vfs::QuotaTypeState::default()
            };
            // Group accounting is OFF but its quota inode still exists.
            st.types[vfs::QuotaType::Group.slot()] = vfs::QuotaTypeState {
                accounting: false,
                file: vfs::QuotaFileStat { ino: 404, blocks: 505, nextents: 6 },
                ..vfs::QuotaTypeState::default()
            };
            // No project quota inode, so nothing overwrites the group slot.
            st.types[vfs::QuotaType::Project.slot()] = vfs::QuotaTypeState::default();
            Ok(st)
        }
    }

    let sb = vfs::SuperBlock::new(Arc::new(QstatType), Arc::new(StateOps), 0x51544154, Q_XGETQSTAT, 4096, "xfs-qstat-inactive-group".into(), Arc::new(()));
    let mut out = FsQuotaStat::default();

    assert_eq!(dispatch(&sb, Q_XGETQSTAT, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStat as u64), 0);
    assert_eq!(out.qs_gquota.qfs_ino, 404);
    assert_eq!(out.qs_gquota.qfs_nblks, 505);
    assert_eq!(out.qs_gquota.qfs_nextents, 6);
}

// With no quota inode anywhere for a class, its slot stays zeroed.
#[test]
fn xfs_qgetqstat_leaves_absent_class_slots_zeroed() {
    struct StateOps;
    impl vfs::SuperOps for StateOps {
        fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
        fn quota_supported(&self) -> bool { true }
        fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
        fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
        fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
            let mut st = vfs::QuotaState::default();
            st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
                accounting: true,
                file: vfs::QuotaFileStat { ino: 101, blocks: 202, nextents: 3 },
                ..vfs::QuotaTypeState::default()
            };
            Ok(st)
        }
    }

    let sb = vfs::SuperBlock::new(Arc::new(QstatType), Arc::new(StateOps), 0x51544154, Q_XGETQSTAT, 4096, "xfs-qstat-absent".into(), Arc::new(()));
    let mut out = FsQuotaStat::default();

    assert_eq!(dispatch(&sb, Q_XGETQSTAT, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStat as u64), 0);
    assert_eq!(out.qs_uquota.qfs_ino, 101);
    assert_eq!((out.qs_gquota.qfs_ino, out.qs_gquota.qfs_nblks, out.qs_gquota.qfs_nextents), (0, 0, 0));
}
