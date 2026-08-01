// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use syscall::errno::Errno;

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

const FS_DQ_BHARD:      u16 = 1 << 3;
const FS_DQ_BTIMER:     u16 = 1 << 6;
const FS_DQ_IWARNS:     u16 = 1 << 10;
const FS_DQ_BWARNS:     u16 = 1 << 9;
const FS_DQ_BIGTIME:    u16 = 1 << 15;
const FS_QUOTA_UDQ_ACCT: u32 = 1 << 0;
const FS_QUOTA_GDQ_ENFD: u32 = 1 << 3;
const FS_QUOTA_PDQ_ACCT: u32 = 1 << 4;
const FS_QUOTA_PDQ_ENFD: u32 = 1 << 5;
const UNKNOWN_XFS_QUOTA_FLAG: u32 = 1 << 31;

#[repr(C)]
#[derive(Clone, Copy)]
struct FsDiskQuota {
    d_version: i8,
    d_flags: i8,
    d_fieldmask: u16,
    d_id: u32,
    d_blk_hardlimit: u64,
    d_blk_softlimit: u64,
    d_ino_hardlimit: u64,
    d_ino_softlimit: u64,
    d_bcount: u64,
    d_icount: u64,
    d_itimer: i32,
    d_btimer: i32,
    d_iwarns: u16,
    d_bwarns: u16,
    d_itimer_hi: i8,
    d_btimer_hi: i8,
    d_rtbtimer_hi: i8,
    d_padding2: i8,
    d_rtb_hardlimit: u64,
    d_rtb_softlimit: u64,
    d_rtbcount: u64,
    d_rtbtimer: i32,
    d_rtbwarns: u16,
    d_padding3: i16,
    d_padding4: [u8; 8],
}

fn empty_quota() -> FsDiskQuota {
    FsDiskQuota {
        d_version: 0, d_flags: 0, d_fieldmask: 0, d_id: 0, d_blk_hardlimit: 0, d_blk_softlimit: 0,
        d_ino_hardlimit: 0, d_ino_softlimit: 0, d_bcount: 0, d_icount: 0, d_itimer: 0, d_btimer: 0,
        d_iwarns: 0, d_bwarns: 0, d_itimer_hi: 0, d_btimer_hi: 0, d_rtbtimer_hi: 0, d_padding2: 0,
        d_rtb_hardlimit: 0, d_rtb_softlimit: 0, d_rtbcount: 0, d_rtbtimer: 0, d_rtbwarns: 0,
        d_padding3: 0, d_padding4: [0; 8],
    }
}

mod namei_common {
    pub fn errno_from_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }
    pub fn read_user_path(_addr: u64) -> Result<String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

mod pathresolve {
    pub fn resolve_path_raw(_raw: &str, _follow: bool) -> vfs::KResult<vfs::VfsPath> {
        Err(vfs::VfsError::Enoent)
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
#[path = "../src/179_quotactl_xfs/core.rs"]
mod xfs;

struct XfsType;
impl vfs::FileSystemType for XfsType {
    fn name(&self) -> &str { "quota-xfs-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

struct XfsOps {
    get_calls:  AtomicU32,
    next_calls: AtomicU32,
}

struct OnOffOps {
    on_flags:  AtomicU32,
    off_flags: AtomicU32,
}

impl OnOffOps {
    fn new() -> Self { Self { on_flags: AtomicU32::new(0), off_flags: AtomicU32::new(0) } }
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

impl XfsOps {
    fn new() -> Self {
        Self { get_calls: AtomicU32::new(0), next_calls: AtomicU32::new(0) }
    }
}

impl vfs::SuperOps for XfsOps {
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

fn sb_with_ops(ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(XfsType), ops, 0x5155_5800, 0x5800, 4096, "quota-xfs-hosted".into(), Arc::new(()))
}

#[test]
fn xfs_getquota_getnext_copyout_faults_after_fs_hook_hosted() {
    let ops = Arc::new(XfsOps::new());
    let sb = sb_with_ops(ops.clone());

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQUOTA, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 1000), 0), eno(Errno::Efault));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETNEXTQUOTA, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 2000), 0), eno(Errno::Efault));
    assert_eq!(ops.get_calls.load(Ordering::SeqCst), 1000);
    assert_eq!(ops.next_calls.load(Ordering::SeqCst), 2000);
}

#[test]
fn xfs_qstatv_checks_get_state_support_before_user_version_hosted() {
    let sb = sb_with_ops(Arc::new(XfsOps::new()));

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTATV, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), 0), eno(Errno::Enosys));
}

#[test]
fn xfs_quotasync_readonly_check_precedes_noop_success_hosted() {
    let sb = sb_with_ops(Arc::new(XfsOps::new()));

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTASYNC, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), 0), 0);
    sb.set_readonly(true);
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTASYNC, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), 0), eno(Errno::Erofs));
}

#[test]
fn xfs_quotaon_quotaoff_validate_and_pass_raw_flags_hosted() {
    let ops = Arc::new(OnOffOps::new());
    let sb = sb_with_ops(ops.clone());
    let mut flags = FS_QUOTA_UDQ_ACCT | FS_QUOTA_GDQ_ENFD | FS_QUOTA_PDQ_ACCT;

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTAON, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), 0), eno(Errno::Efault));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTAOFF, vfs::QuotaType::Project, &qidns::QuotaIdCtx::initial(vfs::QuotaType::Project, 0), 0), eno(Errno::Efault));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTAON, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), &mut flags as *mut u32 as u64), 0);
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTAOFF, vfs::QuotaType::Project, &qidns::QuotaIdCtx::initial(vfs::QuotaType::Project, 0), &mut flags as *mut u32 as u64), 0);
    assert_eq!(ops.on_flags.load(Ordering::SeqCst), flags);
    assert_eq!(ops.off_flags.load(Ordering::SeqCst), flags);

    let valid_flags = flags;
    flags |= UNKNOWN_XFS_QUOTA_FLAG;
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTAON, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), &mut flags as *mut u32 as u64), eno(Errno::Einval));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTAOFF, vfs::QuotaType::Project, &qidns::QuotaIdCtx::initial(vfs::QuotaType::Project, 0), &mut flags as *mut u32 as u64), eno(Errno::Einval));
    assert_eq!(ops.on_flags.load(Ordering::SeqCst), valid_flags);
    assert_eq!(ops.off_flags.load(Ordering::SeqCst), valid_flags);
}

#[test]
fn xfs_quotarm_reads_flags_before_support_and_passes_raw_flags_hosted() {
    let sb = sb_with_ops(Arc::new(XfsOps::new()));
    let mut flags = FS_QUOTA_UDQ_ACCT | FS_QUOTA_PDQ_ENFD;

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTARM, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), 0), eno(Errno::Efault));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTARM, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), &mut flags as *mut u32 as u64), eno(Errno::Enosys));

    let ops = Arc::new(RmOps { flags: AtomicU32::new(0) });
    let sb = sb_with_ops(ops.clone());
    flags = FS_QUOTA_UDQ_ACCT | FS_QUOTA_GDQ_ENFD | FS_QUOTA_PDQ_ACCT;
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XQUOTARM, vfs::QuotaType::Project, &qidns::QuotaIdCtx::initial(vfs::QuotaType::Project, 0), &mut flags as *mut u32 as u64), 0);
    assert_eq!(ops.flags.load(Ordering::SeqCst), flags);
}

#[test]
fn xfs_setqlim_support_ordering_hosted() {
    let info_ops = Arc::new(InfoOnlyOps { info_calls: AtomicU32::new(0) });
    let sb = sb_with_ops(info_ops.clone());
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_BTIMER;
    q.d_btimer = 5;

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XSETQLIM, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 0), &mut q as *mut FsDiskQuota as u64), eno(Errno::Enosys));
    assert_eq!(info_ops.info_calls.load(Ordering::SeqCst), 0);

    let set_ops = Arc::new(SetOnlyOps { set_calls: AtomicU32::new(0) });
    let sb = sb_with_ops(set_ops.clone());
    q.d_fieldmask = FS_DQ_IWARNS;
    q.d_iwarns = 9;
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XSETQLIM, vfs::QuotaType::Group, &qidns::QuotaIdCtx::initial(vfs::QuotaType::Group, 0), &mut q as *mut FsDiskQuota as u64), eno(Errno::Einval));
    assert_eq!(set_ops.set_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn xfs_setqlim_id0_splits_info_before_dquot_limits_hosted() {
    let ops = Arc::new(SetOps::new());
    let sb = sb_with_ops(ops.clone());
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_BTIMER | FS_DQ_IWARNS | FS_DQ_BHARD | FS_DQ_BIGTIME;
    q.d_blk_hardlimit = 9;
    q.d_btimer = 5;
    q.d_btimer_hi = 0x12;
    q.d_iwarns = 77;

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XSETQLIM, vfs::QuotaType::Group, &qidns::QuotaIdCtx::initial(vfs::QuotaType::Group, 0), &mut q as *mut FsDiskQuota as u64), 0);
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
fn xfs_setqlim_nonzero_warning_only_reaches_empty_limit_update_hosted() {
    let ops = Arc::new(SetOps::new());
    let sb = sb_with_ops(ops.clone());
    let mut q = empty_quota();
    q.d_fieldmask = FS_DQ_BWARNS;
    q.d_bwarns = 12;

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XSETQLIM, vfs::QuotaType::User, &qidns::QuotaIdCtx::initial(vfs::QuotaType::User, 1000), &mut q as *mut FsDiskQuota as u64), 0);
    assert_eq!(ops.info_seq.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_seq.load(Ordering::SeqCst), 1);
    assert_eq!(ops.set_kind.load(Ordering::SeqCst), vfs::QuotaType::User.slot() as u32);
    assert_eq!(ops.set_id.load(Ordering::SeqCst), 1000);
    assert_eq!(ops.set_fieldmask.load(Ordering::SeqCst), 0);
    assert_eq!(ops.set_valid.load(Ordering::SeqCst), FS_DQ_BWARNS as u32);
}
