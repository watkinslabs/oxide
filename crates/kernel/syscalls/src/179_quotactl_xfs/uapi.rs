// XFS quotactl UAPI table: the FS_DQ_* field bits
// and their aggregate masks are transcribed complete so a `d_fieldmask` a
// future command consults is already named here. Aggregates that no command
// currently tests (`FS_DQ_VFS_MASK`) are unreferenced by design.
#![allow(dead_code, reason = "complete XFS quotactl UAPI constant table; unreferenced aggregate masks are the point")]

pub(super) const FS_DQUOT_VERSION: i8 = 1;
pub(super) const FS_QSTAT_VERSION: i8 = 1;
pub(super) const FS_QSTATV_VERSION1: i8 = 1;
pub(super) const FS_DQ_ISOFT: u16 = 1 << 0;
pub(super) const FS_DQ_IHARD: u16 = 1 << 1;
pub(super) const FS_DQ_BSOFT: u16 = 1 << 2;
pub(super) const FS_DQ_BHARD: u16 = 1 << 3;
pub(super) const FS_DQ_RTBSOFT: u16 = 1 << 4;
pub(super) const FS_DQ_RTBHARD: u16 = 1 << 5;
pub(super) const FS_DQ_BTIMER: u16 = 1 << 6;
pub(super) const FS_DQ_ITIMER: u16 = 1 << 7;
pub(super) const FS_DQ_RTBTIMER: u16 = 1 << 8;
pub(super) const FS_DQ_BWARNS: u16 = 1 << 9;
pub(super) const FS_DQ_IWARNS: u16 = 1 << 10;
pub(super) const FS_DQ_RTBWARNS: u16 = 1 << 11;
pub(super) const FS_DQ_BCOUNT: u16 = 1 << 12;
pub(super) const FS_DQ_ICOUNT: u16 = 1 << 13;
pub(super) const FS_DQ_RTBCOUNT: u16 = 1 << 14;
pub(super) const FS_DQ_BIGTIME: u16 = 1 << 15;
pub(super) const FS_DQ_TIMER_MASK: u16 = FS_DQ_BTIMER | FS_DQ_ITIMER | FS_DQ_RTBTIMER;
pub(super) const FS_DQ_WARNS_MASK: u16 = FS_DQ_BWARNS | FS_DQ_IWARNS | FS_DQ_RTBWARNS;
pub(super) const FS_DQ_VFS_MASK: u16 = FS_DQ_ISOFT | FS_DQ_IHARD | FS_DQ_BSOFT | FS_DQ_BHARD
    | FS_DQ_RTBSOFT | FS_DQ_RTBHARD | FS_DQ_BTIMER | FS_DQ_ITIMER | FS_DQ_RTBTIMER
    | FS_DQ_BCOUNT | FS_DQ_ICOUNT | FS_DQ_RTBCOUNT;
pub(super) const FS_USER_QUOTA: i8 = 1 << 0;
pub(super) const FS_PROJ_QUOTA: i8 = 1 << 1;
pub(super) const FS_GROUP_QUOTA: i8 = 1 << 2;
pub(super) const FS_QUOTA_UDQ_ACCT: u16 = 1 << 0;
pub(super) const FS_QUOTA_UDQ_ENFD: u16 = 1 << 1;
pub(super) const FS_QUOTA_GDQ_ACCT: u16 = 1 << 2;
pub(super) const FS_QUOTA_GDQ_ENFD: u16 = 1 << 3;
pub(super) const FS_QUOTA_PDQ_ACCT: u16 = 1 << 4;
pub(super) const FS_QUOTA_PDQ_ENFD: u16 = 1 << 5;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct FsDiskQuota {
    pub d_version: i8,
    pub d_flags: i8,
    pub d_fieldmask: u16,
    pub d_id: u32,
    pub d_blk_hardlimit: u64,
    pub d_blk_softlimit: u64,
    pub d_ino_hardlimit: u64,
    pub d_ino_softlimit: u64,
    pub d_bcount: u64,
    pub d_icount: u64,
    pub d_itimer: i32,
    pub d_btimer: i32,
    pub d_iwarns: u16,
    pub d_bwarns: u16,
    pub d_itimer_hi: i8,
    pub d_btimer_hi: i8,
    pub d_rtbtimer_hi: i8,
    pub d_padding2: i8,
    pub d_rtb_hardlimit: u64,
    pub d_rtb_softlimit: u64,
    pub d_rtbcount: u64,
    pub d_rtbtimer: i32,
    pub d_rtbwarns: u16,
    pub d_padding3: i16,
    pub d_padding4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct FsQfilestat { pub qfs_ino: u64, pub qfs_nblks: u64, pub qfs_nextents: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct FsQuotaStat {
    pub qs_version: i8,
    pub qs_flags: u16,
    pub qs_pad: i8,
    pub qs_uquota: FsQfilestat,
    pub qs_gquota: FsQfilestat,
    pub qs_incoredqs: u32,
    pub qs_btimelimit: i32,
    pub qs_itimelimit: i32,
    pub qs_rtbtimelimit: i32,
    pub qs_bwarnlimit: u16,
    pub qs_iwarnlimit: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct FsQfilestatv { pub qfs_ino: u64, pub qfs_nblks: u64, pub qfs_nextents: u32, pub qfs_pad: u32 }

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct FsQuotaStatv {
    pub qs_version: i8,
    pub qs_pad1: u8,
    pub qs_flags: u16,
    pub qs_incoredqs: u32,
    pub qs_uquota: FsQfilestatv,
    pub qs_gquota: FsQfilestatv,
    pub qs_pquota: FsQfilestatv,
    pub qs_btimelimit: i32,
    pub qs_itimelimit: i32,
    pub qs_rtbtimelimit: i32,
    pub qs_bwarnlimit: u16,
    pub qs_iwarnlimit: u16,
    pub qs_rtbwarnlimit: u16,
    pub qs_pad3: u16,
    pub qs_pad4: u32,
    pub qs_pad2: [u64; 7],
}

const _: [(); 112] = [(); core::mem::size_of::<FsDiskQuota>()];
const _: [(); 80] = [(); core::mem::size_of::<FsQuotaStat>()];
const _: [(); 160] = [(); core::mem::size_of::<FsQuotaStatv>()];
