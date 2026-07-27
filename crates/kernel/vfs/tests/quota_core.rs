use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    Dquot, DquotLimits, DquotOperations, DquotTransferIds, DquotUsage, FileType,
    InodeBuilder, Kqid, KResult, QuotaCtlCmd, QuotaCtlCred, QuotaLimit, QuotaType, VfsError,
    default_file_ops, default_inode_ops, dquot_charge_usage, dquot_initialize, dquot_release_usage, dquot_transfer_inode,
    dquot_drop_type, inode_dquot, mk_mode, quota_getfmt, quota_getinfo, quota_getquota, quota_off, quota_on,
    quota_check_quotactl_permission, quota_setinfo, quota_setquota, quota_shutdown, quota_sync, simple_setattr, Iattr, MemDqblk, MemDqinfo,
    ATTR_UID, IDENTITY,
};

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
struct QOps {
    allocs:   AtomicUsize,
    acquires: AtomicUsize,
    inits:    AtomicUsize,
    dirties:  AtomicUsize,
    writes:   AtomicUsize,
    write_fail: AtomicUsize,
    releases: AtomicUsize,
    next:     AtomicUsize,
    next_hits: AtomicUsize,
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
    fn initialize(&self, _inode: &vfs::Inode) -> KResult<()> {
        self.inits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn mark_dirty(&self, _dq: &Dquot) -> KResult<()> {
        self.dirties.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn write_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.write_fail.load(Ordering::SeqCst) != 0 {
            self.write_fail.fetch_sub(1, Ordering::SeqCst);
            return Err(VfsError::Eio);
        }
        Ok(())
    }
    fn release_dquot(&self, _dq: &Dquot) -> KResult<()> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn get_next_id(&self, qid: Kqid) -> KResult<Option<Kqid>> {
        self.next_hits.fetch_add(1, Ordering::SeqCst);
        let id = self.next.load(Ordering::SeqCst) as u32;
        if id == 0 { Ok(None) } else { Ok(Some(Kqid { kind: qid.kind, id })) }
    }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(TType), Arc::new(TOps), 0x5155, 0x1234, 4096, "quotafs".into(), Arc::new(()))
}

fn inode(sb: &Arc<SuperBlock>, uid: u32, gid: u32, projid: u32) -> vfs::InodeRef {
    sb.iget(0x44, || {
        InodeBuilder::new(0x44, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
            .sb(Arc::downgrade(sb))
            .owner(uid, gid)
            .projid(projid)
            .build()
    })
}

fn quota_cred(euid: u32, egid: u32, cap_sys_admin: bool) -> QuotaCtlCred {
    QuotaCtlCred { euid, egid, cap_sys_admin, groups: vfs::GroupList::empty() }
}

#[test]
fn dqget_uses_superblock_cache_and_hooks() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    sb.s_dquot.set_operations(QuotaType::Project, ops.clone()); sb.s_dquot.enable(QuotaType::Project, vfs::QFMT_VFS_V1);

    let a = sb.s_dquot.dqget(Kqid::project(7)).unwrap();
    let b = sb.s_dquot.dqget(Kqid::project(7)).unwrap();

    assert!(Arc::ptr_eq(&a, &b), "dqget returns canonical cached dquot");
    assert_eq!(ops.allocs.load(Ordering::SeqCst), 1, "one cache allocation");
    assert_eq!(ops.acquires.load(Ordering::SeqCst), 2, "each dqget acquires");
}

#[test]
fn quotactl_permission_matches_linux_owner_and_admin_rules() {
    let mut cred = quota_cred(1000, 100, false);

    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetFmt, QuotaType::Project, 99, &cred), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetInfo, QuotaType::Project, 99, &cred), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::Sync, QuotaType::Project, 99, &cred), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetQuota, QuotaType::User, 1000, &cred), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetQuota, QuotaType::User, 1001, &cred), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetQuota, QuotaType::Group, 100, &cred), Ok(()));

    cred.groups = vfs::GroupList::from_slice(&[200]);
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetQuota, QuotaType::Group, 200, &cred), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetQuota, QuotaType::Project, 7, &cred), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetNextQuota, QuotaType::User, 1000, &cred), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::SetQuota, QuotaType::User, 1000, &cred), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::QuotaOn, QuotaType::User, 0, &cred), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::QuotaOff, QuotaType::User, 0, &cred), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::SetInfo, QuotaType::User, 0, &cred), Err(VfsError::Eperm));

    cred.cap_sys_admin = true;
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::GetNextQuota, QuotaType::User, 1000, &cred), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::SetQuota, QuotaType::User, 1000, &cred), Ok(()));
}

#[test]
fn dquot_initialize_attaches_active_inode_slots() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let ino = inode(&sb, 1000, 100, 55);

    dquot_initialize(&ino).unwrap();

    assert_eq!(inode_dquot(&ino, QuotaType::User).unwrap().id(), Kqid::user(1000));
    assert_eq!(inode_dquot(&ino, QuotaType::Group).unwrap().id(), Kqid::group(100));
    assert_eq!(inode_dquot(&ino, QuotaType::Project).unwrap().id(), Kqid::project(55));
    assert_eq!(ops.inits.load(Ordering::SeqCst), 1, "initialize hook ran");
}

#[test]
fn inode_transfer_moves_user_group_project_usage() {
    let sb = sb();
    sb.s_dquot.enable(QuotaType::User, vfs::QFMT_VFS_V1);
    sb.s_dquot.enable(QuotaType::Group, vfs::QFMT_VFS_V1);
    sb.s_dquot.enable(QuotaType::Project, vfs::QFMT_VFS_V1);
    let ino = inode(&sb, 1, 2, 3);
    let usage = DquotUsage::inode(4096, 512);
    dquot_initialize(&ino).unwrap();
    inode_dquot(&ino, QuotaType::User).unwrap().charge(usage).unwrap();
    inode_dquot(&ino, QuotaType::Group).unwrap().charge(usage).unwrap();
    inode_dquot(&ino, QuotaType::Project).unwrap().charge(usage).unwrap();

    dquot_transfer_inode(&ino, usage, DquotTransferIds { uid: Some(10), gid: Some(20), projid: Some(30) }).unwrap();

    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(1)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::group(2)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::project(3)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(inode_dquot(&ino, QuotaType::User).unwrap().id(), Kqid::user(10));
    assert_eq!(inode_dquot(&ino, QuotaType::Group).unwrap().id(), Kqid::group(20));
    assert_eq!(inode_dquot(&ino, QuotaType::Project).unwrap().usage(), usage);
    assert!(sb.s_dquot.dquots().lookup(Kqid::user(1)).unwrap().is_dirty());
    assert!(sb.s_dquot.dquots().lookup(Kqid::user(10)).unwrap().is_dirty());
    assert!(sb.s_dquot.dquots().lookup(Kqid::project(3)).unwrap().is_dirty());
    assert!(sb.s_dquot.dquots().lookup(Kqid::project(30)).unwrap().is_dirty());
}

#[test]
fn inode_transfer_edquot_keeps_old_charges_and_slots() {
    let sb = sb();
    sb.s_dquot.enable(QuotaType::User, vfs::QFMT_VFS_V1);
    sb.s_dquot.enable(QuotaType::Group, vfs::QFMT_VFS_V1);
    sb.s_dquot.enable(QuotaType::Project, vfs::QFMT_VFS_V1);
    let ino = inode(&sb, 1, 2, 3);
    let usage = DquotUsage::inode(4096, 0);
    dquot_initialize(&ino).unwrap();
    inode_dquot(&ino, QuotaType::User).unwrap().charge(usage).unwrap();
    inode_dquot(&ino, QuotaType::Group).unwrap().charge(usage).unwrap();
    inode_dquot(&ino, QuotaType::Project).unwrap().charge(usage).unwrap();
    sb.s_dquot.dquots().set_limits(Kqid::project(30), DquotLimits {
        space: QuotaLimit::hard(1024),
        reserved_space: QuotaLimit::unlimited(),
        inodes: QuotaLimit::unlimited(),
    });

    assert_eq!(
        dquot_transfer_inode(&ino, usage, DquotTransferIds { uid: Some(10), gid: Some(20), projid: Some(30) }),
        Err(VfsError::Edquot)
    );

    assert_eq!(inode_dquot(&ino, QuotaType::User).unwrap().id(), Kqid::user(1));
    assert_eq!(inode_dquot(&ino, QuotaType::Group).unwrap().id(), Kqid::group(2));
    assert_eq!(inode_dquot(&ino, QuotaType::Project).unwrap().id(), Kqid::project(3));
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(1)).unwrap().usage(), usage);
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::group(2)).unwrap().usage(), usage);
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::project(3)).unwrap().usage(), usage);
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::project(30)).unwrap().usage(), DquotUsage::zero());
}

#[test]
fn quota_control_get_set_sync_and_off_target_superblock() {
    let sb = sb();
    let ops = Arc::new(QOps::default());

    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    assert_eq!(quota_getfmt(&sb, QuotaType::User).unwrap(), 4);

    let dqblk = MemDqblk {
        dqb_bhardlimit: 8192,
        dqb_bsoftlimit: 4096,
        dqb_curspace: 2048,
        dqb_rsvspace: 512,
        dqb_ihardlimit: 8,
        dqb_isoftlimit: 4,
        dqb_curinodes: 2,
        dqb_btime: 11, dqb_itime: 22, dqb_rtb_hardlimit: 0, dqb_rtb_softlimit: 0, dqb_rtbcount: 0, dqb_rtbtimer: 0,
        dqb_valid: 0xffff,
    };
    quota_setquota(&sb, Kqid::user(1000), dqblk).unwrap();
    assert_eq!(ops.dirties.load(Ordering::SeqCst), 1);
    assert_eq!(quota_getquota(&sb, Kqid::user(1000)).unwrap(), dqblk);

    quota_sync(&sb, QuotaType::User).unwrap();
    assert_eq!(ops.writes.load(Ordering::SeqCst), 1);
    quota_sync(&sb, QuotaType::User).unwrap();
    assert_eq!(ops.writes.load(Ordering::SeqCst), 1);
    assert!(!sb.s_dquot.dquots().lookup(Kqid::user(1000)).unwrap().is_dirty());

    let ino = inode(&sb, 1000, 1, 1);
    dquot_initialize(&ino).unwrap();
    assert!(inode_dquot(&ino, QuotaType::User).is_some());

    quota_off(&sb, QuotaType::User).unwrap();
    assert!(!sb.s_dquot.is_enabled(QuotaType::User));
    assert!(inode_dquot(&ino, QuotaType::User).is_none());
    assert!(sb.s_dquot.dquots().lookup(Kqid::user(1000)).is_none());
    assert!(ops.releases.load(Ordering::SeqCst) >= 1);
}

#[test]
fn dquot_drop_type_detaches_inode_ref_but_keeps_enabled_cache() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    let qid = Kqid::user(1000);
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    dquot_initialize(&ino).unwrap();

    dquot_drop_type(&ino, QuotaType::User);

    assert_eq!(ops.writes.load(Ordering::SeqCst), 0);
    assert_eq!(ops.releases.load(Ordering::SeqCst), 0);
    assert!(sb.s_dquot.dquots().lookup(qid).is_some());
    assert!(inode_dquot(&ino, QuotaType::User).is_none());
}

#[test]
fn dquot_drop_type_keeps_snapshot_dquot_cached() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    let qid = Kqid::user(1000);
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    dquot_initialize(&ino).unwrap();
    let held = inode_dquot(&ino, QuotaType::User).unwrap();

    dquot_drop_type(&ino, QuotaType::User);

    assert_eq!(ops.writes.load(Ordering::SeqCst), 0);
    assert_eq!(ops.releases.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&held, &sb.s_dquot.dquots().lookup(qid).unwrap()));
}

#[test]
fn public_dqput_releases_active_ref_without_dropping_enabled_cache() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    let qid = Kqid::user(1000);
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    dquot_initialize(&ino).unwrap();
    let held = sb.s_dquot.dqget(qid).unwrap();
    dquot_drop_type(&ino, QuotaType::User);
    assert_eq!(ops.releases.load(Ordering::SeqCst), 0);
    vfs::dqput(held);
    assert_eq!((ops.writes.load(Ordering::SeqCst), ops.releases.load(Ordering::SeqCst)), (0, 0));
    assert!(sb.s_dquot.dquots().lookup(qid).is_some());
}

#[test]
fn quota_sync_keeps_dirty_when_write_fails() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let qid = Kqid::user(1000);
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    ops.write_fail.store(1, Ordering::SeqCst);
    assert_eq!(quota_sync(&sb, QuotaType::User), Err(VfsError::Eio));
    assert!(sb.s_dquot.dquots().lookup(qid).unwrap().is_dirty());
    assert_eq!(ops.writes.load(Ordering::SeqCst), 1);
}

#[test]
fn dqput_last_active_ref_keeps_dirty_dquot_cached_while_enabled() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let ino = inode(&sb, 1000, 1, 1);
    let qid = Kqid::user(1000);
    quota_setquota(&sb, qid, MemDqblk { dqb_curspace: 4096, ..MemDqblk::new() }).unwrap();
    dquot_initialize(&ino).unwrap();
    let held = sb.s_dquot.dqget(qid).unwrap();
    dquot_drop_type(&ino, QuotaType::User);
    ops.write_fail.store(1, Ordering::SeqCst);
    vfs::dqput(held);
    assert_eq!((ops.writes.load(Ordering::SeqCst), ops.releases.load(Ordering::SeqCst)), (0, 0));
    assert!(sb.s_dquot.dquots().lookup(qid).is_some());
}

#[test]
fn quota_control_reports_enabled_format_per_class() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V0, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops).unwrap();

    assert_eq!(quota_getfmt(&sb, QuotaType::User).unwrap(), vfs::QFMT_VFS_V0);
    assert_eq!(quota_getfmt(&sb, QuotaType::Group).unwrap(), vfs::QFMT_VFS_V1);
}

#[test]
fn quota_getinfo_setinfo_honors_linux_valid_and_flag_masks() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();

    quota_setinfo(&sb, QuotaType::User, MemDqinfo {
        dqi_bgrace: 99,
        dqi_igrace: 0,
        dqi_flags:  0,
        dqi_valid:  vfs::IIF_BGRACE,
        ..MemDqinfo::default()
    }).unwrap();

    let info = quota_getinfo(&sb, QuotaType::User).unwrap();
    assert_eq!(info.dqi_bgrace, 99);
    assert_eq!(info.dqi_igrace, 0);
    assert_eq!(info.dqi_flags, 0);
    assert_eq!(info.dqi_valid, vfs::IIF_ALL);
    quota_setinfo(&sb, QuotaType::User, MemDqinfo { dqi_rt_bgrace: 44, dqi_bwarnlimit: 3, dqi_iwarnlimit: 4, dqi_rtbwarnlimit: 5,
        dqi_valid: vfs::IIF_RT_BGRACE | vfs::IIF_BWARN | vfs::IIF_IWARN | vfs::IIF_RTBWARN, ..MemDqinfo::default() }).unwrap();
    let info = quota_getinfo(&sb, QuotaType::User).unwrap();
    assert_eq!((info.dqi_rt_bgrace, info.dqi_bwarnlimit, info.dqi_iwarnlimit, info.dqi_rtbwarnlimit), (44, 3, 4, 5));
    assert_eq!(quota_setinfo(&sb, QuotaType::User, MemDqinfo {
        dqi_flags:  vfs::DQF_ROOT_SQUASH,
        dqi_valid:  vfs::IIF_FLAGS,
        ..MemDqinfo::default()
    }), Err(VfsError::Einval));
    assert_eq!(quota_setinfo(&sb, QuotaType::User, MemDqinfo {
        dqi_flags:  vfs::DQF_SYS_FILE,
        dqi_valid:  vfs::IIF_FLAGS,
        ..MemDqinfo::default()
    }), Err(VfsError::Einval));
    assert_eq!(quota_setinfo(&sb, QuotaType::User, MemDqinfo {
        dqi_valid:  vfs::IIF_ALL << 1,
        ..MemDqinfo::default()
    }), Err(VfsError::Einval));
}

#[test]
fn quota_mem_dqblk_preserves_signed_linux_time64_t_timers() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();
    let dq = MemDqblk { dqb_btime: -1, dqb_itime: i64::MIN + 1, ..MemDqblk::new() };

    quota_setquota(&sb, Kqid::user(42), dq).unwrap();

    let got = vfs::quota_getquota(&sb, Kqid::user(42)).unwrap();
    assert_eq!(got.dqb_btime, -1);
    assert_eq!(got.dqb_itime, i64::MIN + 1);
}

#[test]
fn quota_shutdown_disables_all_active_classes() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, ops).unwrap();
    let ino = inode(&sb, 10, 20, 30);
    dquot_initialize(&ino).unwrap();

    quota_shutdown(&sb).unwrap();

    assert_eq!(sb.s_dquot.enabled_mask(), 0);
    assert!(inode_dquot(&ino, QuotaType::User).is_none());
    assert!(inode_dquot(&ino, QuotaType::Project).is_none());
}

#[test]
fn dquot_charge_and_release_usage_hits_all_active_classes() {
    let sb = sb();
    let ops = Arc::new(QOps::default());
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, ops.clone()).unwrap();
    let usage = DquotUsage { space: 8192, reserved_space: 0, inodes: 0 };

    dquot_charge_usage(&sb, 10, 20, 30, usage).unwrap();

    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(10)).unwrap().usage(), usage);
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::group(20)).unwrap().usage(), usage);
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::project(30)).unwrap().usage(), usage);
    assert_eq!(ops.dirties.load(Ordering::SeqCst), 3);

    dquot_release_usage(&sb, 10, 20, 30, usage).unwrap();

    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(10)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::group(20)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::project(30)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(ops.dirties.load(Ordering::SeqCst), 6);
}

#[test]
fn dquot_charge_usage_edquot_rolls_back_prior_classes() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();
    quota_on(&sb, QuotaType::Group, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();
    quota_on(&sb, QuotaType::Project, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();
    sb.s_dquot.dquots().set_limits(Kqid::project(30), DquotLimits {
        space: QuotaLimit::hard(4096),
        reserved_space: QuotaLimit::unlimited(),
        inodes: QuotaLimit::unlimited(),
    });
    let usage = DquotUsage { space: 8192, reserved_space: 0, inodes: 0 };

    assert_eq!(dquot_charge_usage(&sb, 10, 20, 30, usage), Err(VfsError::Edquot));

    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(10)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::group(20)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::project(30)).unwrap().usage(), DquotUsage::zero());
}

#[test]
fn simple_setattr_chown_moves_user_quota_charge() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();
    let ino = inode(&sb, 1, 2, 3);
    ino.set_blocks(8);
    let usage = DquotUsage { space: 4096, reserved_space: 0, inodes: 1 };
    dquot_initialize(&ino).unwrap();
    inode_dquot(&ino, QuotaType::User).unwrap().charge(usage).unwrap();

    simple_setattr(&ino, &IDENTITY, &Iattr { valid: ATTR_UID, uid: 10, ..Default::default() }).unwrap();

    assert_eq!(ino.uid(), Some(10));
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(1)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(10)).unwrap().usage(), usage);
    assert_eq!(inode_dquot(&ino, QuotaType::User).unwrap().id(), Kqid::user(10));
}

#[test]
fn simple_setattr_chown_edquot_preserves_owner_and_charge() {
    let sb = sb();
    quota_on(&sb, QuotaType::User, vfs::QFMT_VFS_V1, Arc::new(QOps::default())).unwrap();
    let ino = inode(&sb, 1, 2, 3);
    ino.set_blocks(8);
    let usage = DquotUsage { space: 4096, reserved_space: 0, inodes: 1 };
    dquot_initialize(&ino).unwrap();
    inode_dquot(&ino, QuotaType::User).unwrap().charge(usage).unwrap();
    sb.s_dquot.dquots().set_limits(Kqid::user(10), DquotLimits {
        space: QuotaLimit::hard(1024),
        reserved_space: QuotaLimit::unlimited(),
        inodes: QuotaLimit::unlimited(),
    });

    assert_eq!(
        simple_setattr(&ino, &IDENTITY, &Iattr { valid: ATTR_UID, uid: 10, ..Default::default() }),
        Err(VfsError::Edquot)
    );

    assert_eq!(ino.uid(), Some(1));
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(1)).unwrap().usage(), usage);
    assert_eq!(sb.s_dquot.dquots().lookup(Kqid::user(10)).unwrap().usage(), DquotUsage::zero());
    assert_eq!(inode_dquot(&ino, QuotaType::User).unwrap().id(), Kqid::user(1));
}
