// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use syscall::errno::Errno;

fn eno(e: Errno) -> i64 { -(e.as_i32() as i64) }

const FS_QSTAT_VERSION: i8 = 1;
const FS_QSTATV_VERSION1: i8 = 1;
const FS_QUOTA_UDQ_ACCT: u16 = 1 << 0;
const FS_QUOTA_UDQ_ENFD: u16 = 1 << 1;
const FS_QUOTA_PDQ_ACCT: u16 = 1 << 4;
const FS_QUOTA_PDQ_ENFD: u16 = 1 << 5;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQfilestat { qfs_ino: u64, qfs_nblks: u64, qfs_nextents: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQuotaStat {
    qs_version: i8,
    qs_flags: u16,
    qs_pad: i8,
    qs_uquota: FsQfilestat,
    qs_gquota: FsQfilestat,
    qs_incoredqs: u32,
    qs_btimelimit: i32,
    qs_itimelimit: i32,
    qs_rtbtimelimit: i32,
    qs_bwarnlimit: u16,
    qs_iwarnlimit: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQfilestatv { qfs_ino: u64, qfs_nblks: u64, qfs_nextents: u32, qfs_pad: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FsQuotaStatv {
    qs_version: i8,
    qs_pad1: u8,
    qs_flags: u16,
    qs_incoredqs: u32,
    qs_uquota: FsQfilestatv,
    qs_gquota: FsQfilestatv,
    qs_pquota: FsQfilestatv,
    qs_btimelimit: i32,
    qs_itimelimit: i32,
    qs_rtbtimelimit: i32,
    qs_bwarnlimit: u16,
    qs_iwarnlimit: u16,
    qs_rtbwarnlimit: u16,
    qs_pad3: u16,
    qs_pad4: u32,
    qs_pad2: [u64; 7],
}

const _: [(); 80] = [(); core::mem::size_of::<FsQuotaStat>()];
const _: [(); 160] = [(); core::mem::size_of::<FsQuotaStatv>()];

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
#[path = "../src/179_quotactl_xfs.rs"]
mod xfs;

struct XfsQstatType;
impl vfs::FileSystemType for XfsQstatType {
    fn name(&self) -> &str { "quota-xfs-qstat-hosted" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Einval)
    }
}

fn sb_with_ops(ops: Arc<dyn vfs::SuperOps>) -> Arc<vfs::SuperBlock> {
    vfs::SuperBlock::new(Arc::new(XfsQstatType), ops, 0x5155_5354, 0x5154, 4096, "quota-xfs-qstat-hosted".into(), Arc::new(()))
}

fn mapped_state() -> vfs::QuotaState {
    let mut st = vfs::QuotaState::default();
    st.types[vfs::QuotaType::User.slot()] = vfs::QuotaTypeState {
        accounting: true,
        enforcement: true,
        info: vfs::MemDqinfo {
            dqi_bgrace: 11, dqi_igrace: 22, dqi_rt_bgrace: 33,
            dqi_bwarnlimit: 44, dqi_iwarnlimit: 55, dqi_rtbwarnlimit: 66,
            ..vfs::MemDqinfo::default()
        },
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
        enforcement: true,
        file: vfs::QuotaFileStat { ino: 707, blocks: 808, nextents: 9 },
        incoredqs: 10,
        ..vfs::QuotaTypeState::default()
    };
    st
}

struct VersionOps { calls: AtomicU32 }
impl vfs::SuperOps for VersionOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vfs::QuotaState::default())
    }
}

struct NoStateOps;
impl vfs::SuperOps for NoStateOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
}

struct FailingStateOps;
impl vfs::SuperOps for FailingStateOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
        Err(vfs::VfsError::Eio)
    }
}

struct StateOps;
impl vfs::SuperOps for StateOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Ok(vfs::SbStatFs::default()) }
    fn quota_supported(&self) -> bool { true }
    fn quota_type_supported(&self, _kind: vfs::QuotaType) -> bool { true }
    fn quota_get_state_supported(&self, _sb: &vfs::SuperBlock) -> bool { true }
    fn quota_get_state(&self, _sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> { Ok(mapped_state()) }
}

#[test]
fn xfs_qstatv_reads_version_before_state_snapshot_hosted() {
    let ops = Arc::new(VersionOps { calls: AtomicU32::new(0) });
    let sb = sb_with_ops(ops.clone());
    let mut wrong_version = 0i8;

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTATV, vfs::QuotaType::User, 0, 0), eno(Errno::Efault));
    assert_eq!(
        xfs::dispatch(&sb, xfs::Q_XGETQSTATV, vfs::QuotaType::User, 0, &mut wrong_version as *mut i8 as u64),
        eno(Errno::Einval),
    );
    assert_eq!(ops.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn xfs_qgetqstat_checks_get_state_support_before_copyout_hosted() {
    let sb = sb_with_ops(Arc::new(NoStateOps));

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTAT, vfs::QuotaType::User, 0, 0), eno(Errno::Enosys));
}

#[test]
fn xfs_qstat_state_error_precedes_copyout_hosted() {
    let sb = sb_with_ops(Arc::new(FailingStateOps));
    let mut outv = FsQuotaStatv { qs_version: FS_QSTATV_VERSION1, ..FsQuotaStatv::default() };

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTAT, vfs::QuotaType::User, 0, 0), eno(Errno::Eio));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTATV, vfs::QuotaType::User, 0, &mut outv as *mut FsQuotaStatv as u64), eno(Errno::Eio));
}

#[test]
fn xfs_qstat_zero_flags_return_enosys_hosted() {
    let sb = sb_with_ops(Arc::new(VersionOps { calls: AtomicU32::new(0) }));
    let mut out = FsQuotaStat::default();
    let mut outv = FsQuotaStatv { qs_version: FS_QSTATV_VERSION1, ..FsQuotaStatv::default() };

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTAT, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStat as u64), eno(Errno::Enosys));
    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTATV, vfs::QuotaType::User, 0, &mut outv as *mut FsQuotaStatv as u64), eno(Errno::Enosys));
}

#[test]
fn xfs_qgetqstat_maps_filesystem_state_and_project_group_fallback_hosted() {
    let sb = sb_with_ops(Arc::new(StateOps));
    let mut out = FsQuotaStat::default();

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTAT, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStat as u64), 0);
    assert_eq!(out.qs_version, FS_QSTAT_VERSION);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_UDQ_ENFD | FS_QUOTA_PDQ_ACCT | FS_QUOTA_PDQ_ENFD);
    assert_eq!((out.qs_uquota.qfs_ino, out.qs_uquota.qfs_nblks, out.qs_uquota.qfs_nextents), (101, 202, 3));
    assert_eq!((out.qs_gquota.qfs_ino, out.qs_gquota.qfs_nblks, out.qs_gquota.qfs_nextents), (707, 808, 9));
    assert_eq!(out.qs_incoredqs, 25);
    assert_eq!((out.qs_btimelimit, out.qs_itimelimit, out.qs_rtbtimelimit), (11, 22, 33));
    assert_eq!((out.qs_bwarnlimit, out.qs_iwarnlimit), (44, 55));
}

#[test]
fn xfs_qstatv_maps_all_filesystem_state_slots_hosted() {
    let sb = sb_with_ops(Arc::new(StateOps));
    let mut out = FsQuotaStatv { qs_version: FS_QSTATV_VERSION1, ..FsQuotaStatv::default() };

    assert_eq!(xfs::dispatch(&sb, xfs::Q_XGETQSTATV, vfs::QuotaType::User, 0, &mut out as *mut FsQuotaStatv as u64), 0);
    assert_eq!(out.qs_flags, FS_QUOTA_UDQ_ACCT | FS_QUOTA_UDQ_ENFD | FS_QUOTA_PDQ_ACCT | FS_QUOTA_PDQ_ENFD);
    assert_eq!((out.qs_uquota.qfs_ino, out.qs_gquota.qfs_ino, out.qs_pquota.qfs_ino), (101, 404, 707));
    assert_eq!((out.qs_uquota.qfs_nblks, out.qs_gquota.qfs_nblks, out.qs_pquota.qfs_nblks), (202, 505, 808));
    assert_eq!((out.qs_uquota.qfs_nextents, out.qs_gquota.qfs_nextents, out.qs_pquota.qfs_nextents), (3, 6, 9));
    assert_eq!(out.qs_incoredqs, 25);
    assert_eq!((out.qs_btimelimit, out.qs_itimelimit, out.qs_rtbtimelimit), (11, 22, 33));
    assert_eq!((out.qs_bwarnlimit, out.qs_iwarnlimit, out.qs_rtbwarnlimit), (44, 55, 66));
}
