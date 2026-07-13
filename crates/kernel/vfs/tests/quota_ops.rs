use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    DQB_SPACE, Dquot, DquotOperations, DquotUsage, Kqid, KResult, MemDqblk, QuotaType, VfsError,
    dquot_charge_usage, dquot_release_usage, quota_getnextquota, quota_getquota, quota_off, quota_on,
    quota_setquota, quota_setquota_masked, quota_sync,
};

struct TType;
impl FileSystemType for TType {
    fn name(&self) -> &str { "quotaops" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct TOps;
impl SuperOps for TOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

#[derive(Default)]
struct QOps {
    allocs:    AtomicUsize,
    acquires:  AtomicUsize,
    dirties:   AtomicUsize,
    writes:    AtomicUsize,
    info_writes: AtomicUsize,
    releases:  AtomicUsize,
    frees:     AtomicUsize,
    next:      AtomicUsize,
    next_hits: AtomicUsize,
    stat_hits: AtomicUsize,
}

impl DquotOperations for QOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn alloc_dquot(&self, qid: Kqid) -> vfs::DquotRef {
        self.allocs.fetch_add(1, Ordering::SeqCst);
        Dquot::new(qid)
    }
    fn acquire_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.acquires.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn mark_dirty(&self, _dq: &Dquot) -> KResult<()> {
        self.dirties.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn write_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn write_info(&self, _kind: QuotaType, _info: vfs::MemDqinfo) -> KResult<()> {
        self.info_writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn release_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn free_file_info(&self, _kind: QuotaType) -> KResult<()> {
        self.frees.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn file_stat(&self, kind: QuotaType) -> KResult<vfs::QuotaFileStat> {
        self.stat_hits.fetch_add(1, Ordering::SeqCst);
        Ok(vfs::QuotaFileStat { ino: 10 + kind.slot() as u64, blocks: 20 + kind.slot() as u64, nextents: 1 + kind.slot() as u32 })
    }
    fn get_next_id(&self, qid: Kqid) -> KResult<Option<Kqid>> {
        self.next_hits.fetch_add(1, Ordering::SeqCst);
        let id = self.next.load(Ordering::SeqCst) as u32;
        if id == 0 { Ok(None) } else { Ok(Some(Kqid { kind: qid.kind, id })) }
    }
}

#[derive(Default)]
struct DirtySeqOps {
    calls:  AtomicUsize,
    fail_a: AtomicUsize,
    fail_b: AtomicUsize,
}

impl DquotOperations for DirtySeqOps {
    fn as_any(&self) -> &dyn core::any::Any { self }
    fn alloc_dquot(&self, qid: Kqid) -> vfs::DquotRef { Dquot::new(qid) }
    fn mark_dirty(&self, _dq: &Dquot) -> KResult<()> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.fail_a.load(Ordering::SeqCst) { return Err(VfsError::Eio); }
        if call == self.fail_b.load(Ordering::SeqCst) { return Err(VfsError::Euclean); }
        Ok(())
    }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5155, 0x8123, 4096, "quotaops".into(), Arc::new(()))
}

fn sb_with_ops(ops: Arc<dyn SuperOps>) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), ops, 0x5155, 0x8123, 4096, "quotaops".into(), Arc::new(()))
}

#[test]
fn quota_operations_are_selected_per_quota_type() {
    let sb = sb();
    let user = Arc::new(QOps::default());
    let group = Arc::new(QOps::default());
    group.next.store(77, Ordering::SeqCst);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, user.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, group.clone()).unwrap();

    let dq = sb.s_dquot.dqget(Kqid::user(1000)).unwrap();
    sb.s_dquot.dqput(dq);
    assert_eq!(user.allocs.load(Ordering::SeqCst), 1);
    assert_eq!(group.allocs.load(Ordering::SeqCst), 0);
    assert_eq!(user.acquires.load(Ordering::SeqCst), 1);
    assert_eq!(group.acquires.load(Ordering::SeqCst), 0);

    quota_setquota(&sb, Kqid::user(1000), MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    assert_eq!(user.dirties.load(Ordering::SeqCst), 1);
    assert_eq!(group.dirties.load(Ordering::SeqCst), 0);
    quota_sync(&sb, QuotaType::User).unwrap();
    assert_eq!(user.writes.load(Ordering::SeqCst), 1);
    assert_eq!(group.writes.load(Ordering::SeqCst), 0);

    let usage = DquotUsage { space: 8192, reserved_space: 0, inodes: 0 };
    dquot_charge_usage(&sb, 2000, 3000, 0, usage).unwrap();
    assert_eq!(user.dirties.load(Ordering::SeqCst), 2);
    assert_eq!(group.dirties.load(Ordering::SeqCst), 1);
    dquot_release_usage(&sb, 2000, 3000, 0, usage).unwrap();
    assert_eq!(user.dirties.load(Ordering::SeqCst), 3);
    assert_eq!(group.dirties.load(Ordering::SeqCst), 2);

    let (qid, _) = quota_getnextquota(&sb, Kqid::group(1)).unwrap();
    assert_eq!(qid, Kqid::group(77));
    assert_eq!(user.next_hits.load(Ordering::SeqCst), 0);
    assert_eq!(group.next_hits.load(Ordering::SeqCst), 1);

    quota_off(&sb, QuotaType::User).unwrap();
    assert_eq!(user.releases.load(Ordering::SeqCst), 2);
    assert_eq!(group.releases.load(Ordering::SeqCst), 0);
    assert_eq!(user.frees.load(Ordering::SeqCst), 1);
    assert_eq!(group.frees.load(Ordering::SeqCst), 0);
    let (qid, _) = quota_getnextquota(&sb, Kqid::group(77)).unwrap();
    assert_eq!(qid, Kqid::group(77));
}

#[test]
fn dquot_release_usage_dirty_failure_rolls_back_released_classes() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let usage = DquotUsage { space: 100, reserved_space: 0, inodes: 1 };
    dquot_charge_usage(&sb, 10, 20, 0, usage).unwrap();
    ops.fail_a.store(4, Ordering::SeqCst);

    assert_eq!(dquot_release_usage(&sb, 10, 20, 0, usage), Err(VfsError::Eio));
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curspace, 100);
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curinodes, 1);
    assert_eq!(quota_getquota(&sb, Kqid::group(20)).unwrap().dqb_curspace, 100);
    assert_eq!(quota_getquota(&sb, Kqid::group(20)).unwrap().dqb_curinodes, 1);
}

#[test]
fn dquot_release_usage_current_restore_dirty_failure_surfaces_rollback_error() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let usage = DquotUsage { space: 100, reserved_space: 0, inodes: 1 };
    dquot_charge_usage(&sb, 10, 20, 0, usage).unwrap();
    ops.fail_a.store(2, Ordering::SeqCst);
    ops.fail_b.store(3, Ordering::SeqCst);

    assert_eq!(dquot_release_usage(&sb, 10, 20, 0, usage), Err(VfsError::Euclean));

    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curspace, 100);
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curinodes, 1);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn dquot_release_usage_prior_rollback_dirty_failure_surfaces_rollback_error() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let usage = DquotUsage { space: 100, reserved_space: 0, inodes: 1 };
    dquot_charge_usage(&sb, 10, 20, 0, usage).unwrap();
    ops.fail_a.store(4, Ordering::SeqCst);
    ops.fail_b.store(5, Ordering::SeqCst);

    assert_eq!(dquot_release_usage(&sb, 10, 20, 0, usage), Err(VfsError::Euclean));

    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curspace, 100);
    assert_eq!(quota_getquota(&sb, Kqid::group(20)).unwrap().dqb_curspace, 100);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 6);
}

#[test]
fn dquot_charge_usage_dirty_failure_rolls_back_charged_classes() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    ops.fail_a.store(2, Ordering::SeqCst);

    assert_eq!(dquot_charge_usage(&sb, 10, 20, 0, DquotUsage { space: 100, reserved_space: 0, inodes: 1 }), Err(VfsError::Eio));

    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curspace, 0);
    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curinodes, 0);
    assert_eq!(quota_getquota(&sb, Kqid::group(20)).unwrap().dqb_curspace, 0);
    assert_eq!(quota_getquota(&sb, Kqid::group(20)).unwrap().dqb_curinodes, 0);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 4);
}

#[test]
fn dquot_charge_usage_returns_rollback_dirty_failure() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    ops.fail_a.store(2, Ordering::SeqCst);
    ops.fail_b.store(3, Ordering::SeqCst);

    assert_eq!(dquot_charge_usage(&sb, 10, 20, 0, DquotUsage { space: 100, reserved_space: 0, inodes: 1 }), Err(VfsError::Euclean));

    assert_eq!(quota_getquota(&sb, Kqid::user(10)).unwrap().dqb_curspace, 0);
    assert_eq!(quota_getquota(&sb, Kqid::group(20)).unwrap().dqb_curspace, 0);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 4);
}

#[test]
fn quota_setquota_dirty_failure_restores_old_record() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    let qid = Kqid::user(10);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 100, dqb_curinodes: 1, ..MemDqblk::new() }).unwrap();
    ops.fail_a.store(2, Ordering::SeqCst);

    assert_eq!(
        quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 900, dqb_curinodes: 9, ..MemDqblk::new() }),
        Err(VfsError::Eio)
    );

    let got = quota_getquota(&sb, qid).unwrap();
    assert_eq!(got.dqb_curspace, 100);
    assert_eq!(got.dqb_curinodes, 1);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn quota_setquota_masked_dirty_failure_restores_old_record() {
    let sb = sb();
    let ops = Arc::new(DirtySeqOps::default());
    let qid = Kqid::user(11);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 100, dqb_curinodes: 1, ..MemDqblk::new() }).unwrap();
    ops.fail_a.store(2, Ordering::SeqCst);

    assert_eq!(
        quota_setquota_masked(&sb, qid, MemDqblk { dqb_curspace: 900, ..MemDqblk::new() }, DQB_SPACE, 0),
        Err(VfsError::Eio)
    );

    let got = quota_getquota(&sb, qid).unwrap();
    assert_eq!(got.dqb_curspace, 100);
    assert_eq!(got.dqb_curinodes, 1);
    assert_eq!(ops.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn quota_off_clears_per_type_info_and_operations() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    sb.s_dquot.load_info(QuotaType::User, vfs::MemDqinfo {
        dqi_bgrace: 11,
        dqi_igrace: 22,
        dqi_flags:  vfs::DQF_SYS_FILE,
        dqi_valid:  vfs::IIF_BGRACE | vfs::IIF_IGRACE | vfs::IIF_FLAGS,
        ..vfs::MemDqinfo::default()
    });

    quota_off(&sb, QuotaType::User).unwrap();

    let info = sb.s_dquot.info(QuotaType::User);
    assert_eq!(sb.s_dquot.format(QuotaType::User), 0);
    assert_eq!(info.dqi_bgrace, 0);
    assert_eq!(info.dqi_igrace, 0);
    assert_eq!(info.dqi_flags, 0);
    assert!(sb.s_dquot.operations(QuotaType::User).is_none());
    assert_eq!(ops.frees.load(Ordering::SeqCst), 1);
}

#[test]
fn quota_setinfo_validates_before_active_check_like_linux() {
    let sb = sb();
    assert_eq!(vfs::quota_setinfo(&sb, QuotaType::User, vfs::MemDqinfo {
        dqi_valid: 1 << 31,
        ..vfs::MemDqinfo::default()
    }), Err(VfsError::Einval));
    assert_eq!(vfs::quota_setinfo(&sb, QuotaType::User, vfs::MemDqinfo {
        dqi_valid: vfs::IIF_BGRACE,
        ..vfs::MemDqinfo::default()
    }), Err(VfsError::Esrch));
}

#[test]
fn quota_setinfo_forces_filesystem_info_write_like_linux() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    vfs::quota_setinfo(&sb, QuotaType::User, vfs::MemDqinfo {
        dqi_bgrace: 33,
        dqi_valid: vfs::IIF_BGRACE,
        ..vfs::MemDqinfo::default()
    }).unwrap();
    assert_eq!(ops.info_writes.load(Ordering::SeqCst), 1);
    assert_eq!(vfs::quota_getinfo(&sb, QuotaType::User).unwrap().dqi_bgrace, 33);
}

#[test]
fn default_quota_get_state_exports_backend_state_like_linux() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    sb.s_dquot.load_info(QuotaType::User, vfs::MemDqinfo {
        dqi_bgrace: 44,
        dqi_valid: vfs::IIF_BGRACE,
        ..vfs::MemDqinfo::default()
    });
    let _held = sb.s_dquot.dqget(Kqid::user(123)).unwrap();

    let state = ops.get_state(&sb).unwrap();
    let user = state.types[QuotaType::User.slot()];
    let group = state.types[QuotaType::Group.slot()];

    assert!(user.accounting);
    assert!(user.enforcement);
    assert_eq!(user.info.dqi_bgrace, 44);
    assert_eq!(user.file, vfs::QuotaFileStat { ino: 10, blocks: 20, nextents: 1 });
    assert_eq!(user.incoredqs, 1);
    assert!(!group.accounting);
    assert_eq!(group.file, vfs::QuotaFileStat::default());
    assert_eq!(ops.stat_hits.load(Ordering::SeqCst), 1);
}

#[test]
fn xfs_quota_remove_is_filesystem_superblock_hook() {
    struct RmOps { flags: AtomicU32 }
    impl SuperOps for RmOps {
        fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
        fn quota_remove_xfs(&self, _sb: &SuperBlock, flags: u32) -> KResult<()> {
            self.flags.store(flags, Ordering::SeqCst);
            Ok(())
        }
    }

    let default = sb();
    assert_eq!(default.s_op.quota_remove_xfs(&default, 7), Err(VfsError::Enosys));

    let ops = Arc::new(RmOps { flags: AtomicU32::new(0) });
    let sb = sb_with_ops(ops.clone());
    sb.s_op.quota_remove_xfs(&sb, 5).unwrap();
    assert_eq!(ops.flags.load(Ordering::SeqCst), 5);
}

#[test]
fn xfs_quota_on_off_are_filesystem_superblock_hooks_with_raw_flags() {
    const USER_ACCT: u32 = 1 << 0;
    const USER_ENFD: u32 = 1 << 1;
    const GROUP_ACCT: u32 = 1 << 2;
    const PROJECT_ENFD: u32 = 1 << 5;

    struct XfsOps { on: AtomicU32, off: AtomicU32 }
    impl SuperOps for XfsOps {
        fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
        fn quota_enable_xfs(&self, _sb: &SuperBlock, flags: u32) -> KResult<()> {
            self.on.store(flags, Ordering::SeqCst);
            Ok(())
        }
        fn quota_enable_xfs_supported(&self, _sb: &SuperBlock) -> bool { true }
        fn quota_disable_xfs(&self, _sb: &SuperBlock, flags: u32) -> KResult<()> {
            self.off.store(flags, Ordering::SeqCst);
            Ok(())
        }
        fn quota_disable_xfs_supported(&self, _sb: &SuperBlock) -> bool { true }
    }

    let default = sb();
    assert_eq!(default.s_op.quota_enable_xfs(&default, USER_ACCT), Err(VfsError::Enosys));
    assert_eq!(default.s_op.quota_disable_xfs(&default, USER_ENFD), Err(VfsError::Enosys));
    assert!(!default.s_op.quota_enable_xfs_supported(&default));
    assert!(!default.s_op.quota_disable_xfs_supported(&default));

    let ops = Arc::new(XfsOps { on: AtomicU32::new(0), off: AtomicU32::new(0) });
    let sb = sb_with_ops(ops.clone());
    let on_flags = USER_ACCT | USER_ENFD | GROUP_ACCT;
    let off_flags = USER_ENFD | PROJECT_ENFD;
    assert!(sb.s_op.quota_enable_xfs_supported(&sb));
    assert!(sb.s_op.quota_disable_xfs_supported(&sb));
    sb.s_op.quota_enable_xfs(&sb, on_flags).unwrap();
    sb.s_op.quota_disable_xfs(&sb, off_flags).unwrap();

    assert_eq!(ops.on.load(Ordering::SeqCst), on_flags);
    assert_eq!(ops.off.load(Ordering::SeqCst), off_flags);
}

#[test]
fn xfs_quota_state_is_filesystem_superblock_hook() {
    struct StateOps;
    impl SuperOps for StateOps {
        fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
        fn quota_get_state(&self, _sb: &SuperBlock) -> KResult<vfs::QuotaState> {
            let mut st = vfs::QuotaState::default();
            st.types[QuotaType::Project.slot()].accounting = true;
            st.types[QuotaType::Project.slot()].file = vfs::QuotaFileStat { ino: 44, blocks: 55, nextents: 2 };
            Ok(st)
        }
    }

    let default = sb();
    assert_eq!(default.s_op.quota_get_state(&default), Err(VfsError::Enosys));

    let sb = sb_with_ops(Arc::new(StateOps));
    let st = sb.s_op.quota_get_state(&sb).unwrap();
    assert!(st.types[QuotaType::Project.slot()].accounting);
    assert_eq!(st.types[QuotaType::Project.slot()].file.ino, 44);
}

#[test]
fn default_xfs_dqblk_hooks_delegate_to_generic_quota_core() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    ops.next.store(7, Ordering::SeqCst);
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();

    sb.s_op.quota_set_xfs(&sb, Kqid::user(7), MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }, vfs::DQB_SPACE, 99).unwrap();
    assert_eq!(ops.dirties.load(Ordering::SeqCst), 1);
    assert_eq!(sb.s_op.quota_get_xfs(&sb, Kqid::user(7)).unwrap().dqb_curspace, 4096);

    let (next, dqblk) = sb.s_op.quota_get_next_xfs(&sb, Kqid::user(1)).unwrap();
    assert_eq!(next, Kqid::user(7));
    assert_eq!(dqblk.dqb_curspace, 4096);
    assert_eq!(ops.next_hits.load(Ordering::SeqCst), 1);
}

#[test]
fn xfs_dqblk_hooks_are_filesystem_superblock_hooks() {
    struct XfsDqOps {
        get_id:  AtomicU32,
        next_id: AtomicU32,
        set_id:  AtomicU32,
        set_mask: AtomicU32,
        set_now: AtomicUsize,
    }
    impl SuperOps for XfsDqOps {
        fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
        fn quota_get_xfs(&self, _sb: &SuperBlock, qid: Kqid) -> KResult<MemDqblk> {
            self.get_id.store(qid.id, Ordering::SeqCst);
            Ok(MemDqblk { dqb_curspace: 11, ..MemDqblk::new() })
        }
        fn quota_get_next_xfs(&self, _sb: &SuperBlock, qid: Kqid) -> KResult<(Kqid, MemDqblk)> {
            self.next_id.store(qid.id, Ordering::SeqCst);
            Ok((Kqid { kind: qid.kind, id: 42 }, MemDqblk { dqb_curspace: 22, ..MemDqblk::new() }))
        }
        fn quota_set_xfs(&self, _sb: &SuperBlock, qid: Kqid, dqblk: MemDqblk, fieldmask: u32, now_sec: u64) -> KResult<()> {
            assert_eq!(dqblk.dqb_curspace, 33);
            self.set_id.store(qid.id, Ordering::SeqCst);
            self.set_mask.store(fieldmask, Ordering::SeqCst);
            self.set_now.store(now_sec as usize, Ordering::SeqCst);
            Ok(())
        }
    }

    let ops = Arc::new(XfsDqOps {
        get_id: AtomicU32::new(0),
        next_id: AtomicU32::new(0),
        set_id: AtomicU32::new(0),
        set_mask: AtomicU32::new(0),
        set_now: AtomicUsize::new(0),
    });
    let sb = sb_with_ops(ops.clone());

    assert_eq!(sb.s_op.quota_get_xfs(&sb, Kqid::project(12)).unwrap().dqb_curspace, 11);
    let (next, dqblk) = sb.s_op.quota_get_next_xfs(&sb, Kqid::project(13)).unwrap();
    sb.s_op.quota_set_xfs(&sb, Kqid::project(14), MemDqblk { dqb_curspace: 33, ..MemDqblk::new() }, vfs::DQB_SPACE | vfs::DQB_RTB_TIMER, 123).unwrap();

    assert_eq!(ops.get_id.load(Ordering::SeqCst), 12);
    assert_eq!(ops.next_id.load(Ordering::SeqCst), 13);
    assert_eq!(next, Kqid::project(42));
    assert_eq!(dqblk.dqb_curspace, 22);
    assert_eq!(ops.set_id.load(Ordering::SeqCst), 14);
    assert_eq!(ops.set_mask.load(Ordering::SeqCst), vfs::DQB_SPACE | vfs::DQB_RTB_TIMER);
    assert_eq!(ops.set_now.load(Ordering::SeqCst), 123);
}
