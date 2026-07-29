use std::sync::Arc;
use super::super::FsDiskQuota;

pub(super) struct QstatType;
impl vfs::FileSystemType for QstatType {
    fn name(&self) -> &str { "xfs-qstat-order" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> { Err(vfs::VfsError::Einval) }
}

pub(super) struct QstatOps;
impl vfs::SuperOps for QstatOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

pub(super) fn qstat_sb() -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(QstatType), Arc::new(QstatOps), 0x51544154, 0x5808, 4096, "xfs-qstat-order".into(), Arc::new(()))
}

pub(super) fn empty_quota() -> FsDiskQuota {
    FsDiskQuota {
        d_version: 0,
        d_flags: 0,
        d_fieldmask: 0,
        d_id: 0,
        d_blk_hardlimit: 0,
        d_blk_softlimit: 0,
        d_ino_hardlimit: 0,
        d_ino_softlimit: 0,
        d_bcount: 0,
        d_icount: 0,
        d_itimer: 0,
        d_btimer: 0,
        d_iwarns: 0,
        d_bwarns: 0,
        d_itimer_hi: 0,
        d_btimer_hi: 0,
        d_rtbtimer_hi: 0,
        d_padding2: 0,
        d_rtb_hardlimit: 0,
        d_rtb_softlimit: 0,
        d_rtbcount: 0,
        d_rtbtimer: 0,
        d_rtbwarns: 0,
        d_padding3: 0,
        d_padding4: [0; 8],
    }
}
