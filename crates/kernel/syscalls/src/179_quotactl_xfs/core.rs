use syscall::errno::Errno;

use super::{abi::{user_range, write_raw}, dispatch::{qid, quota_now_sec}, eno};
#[path = "uapi.rs"] mod uapi;
pub use super::cmd::{Q_XGETNEXTQUOTA, Q_XGETQSTAT, Q_XGETQSTATV, Q_XGETQUOTA, Q_XQUOTAOFF, Q_XQUOTAON, Q_XQUOTARM, Q_XQUOTASYNC, Q_XSETQLIM};
use uapi::*;

/// Dispatch XFS-compatible quotactl commands through the generic VFS quota core.
/// # C: O(N_dq)+FS
pub fn dispatch(sb: &vfs::SuperBlock, subcmd: u64, kind: vfs::QuotaType, id: u64, addr: u64) -> i64 {
    match subcmd {
        Q_XGETQUOTA => get_quota(sb, kind, id, addr),
        Q_XGETNEXTQUOTA => get_next_quota(sb, kind, id, addr),
        Q_XSETQLIM => set_qlim(sb, kind, id, addr),
        Q_XGETQSTAT => get_qstat(sb, kind, addr),
        Q_XGETQSTATV => get_qstatv(sb, kind, addr),
        Q_XQUOTASYNC => if sb.sb_rdonly() { eno(Errno::Erofs) } else { 0 },
        Q_XQUOTAON => quota_enable(sb, addr),
        Q_XQUOTAOFF => quota_disable(sb, addr),
        Q_XQUOTARM => quota_remove(sb, addr),
        _ => eno(Errno::Einval),
    }
}

/// Translate an XFS-compatible quotactl subcommand to permission class. # C: O(1)
pub fn command(subcmd: u64) -> Option<vfs::QuotaCtlCmd> {
    match subcmd {
        Q_XQUOTAON => Some(vfs::QuotaCtlCmd::XQuotaOn),
        Q_XQUOTAOFF => Some(vfs::QuotaCtlCmd::XQuotaOff),
        Q_XGETQUOTA => Some(vfs::QuotaCtlCmd::XGetQuota),
        Q_XSETQLIM => Some(vfs::QuotaCtlCmd::XSetQlim),
        Q_XGETQSTAT => Some(vfs::QuotaCtlCmd::XGetQstat),
        Q_XQUOTARM => Some(vfs::QuotaCtlCmd::XQuotaRm),
        Q_XQUOTASYNC => Some(vfs::QuotaCtlCmd::XQuotaSync),
        Q_XGETQSTATV => Some(vfs::QuotaCtlCmd::XGetQstatv),
        Q_XGETNEXTQUOTA => Some(vfs::QuotaCtlCmd::XGetNextQuota),
        _ => None,
    }
}

fn get_quota(sb: &vfs::SuperBlock, kind: vfs::QuotaType, id: u64, addr: u64) -> i64 {
    let dq = match sb.s_op.quota_get_xfs(sb, qid(kind, id)) { Ok(d) => d, Err(e) => return crate::namei_common::errno_from_vfs(e) };
    write_quota(addr, kind, id as u32, dq)
}

fn get_next_quota(sb: &vfs::SuperBlock, kind: vfs::QuotaType, id: u64, addr: u64) -> i64 {
    let (next, dq) = match sb.s_op.quota_get_next_xfs(sb, qid(kind, id)) { Ok(d) => d, Err(e) => return crate::namei_common::errno_from_vfs(e) };
    write_quota(addr, kind, next.id, dq)
}

fn set_qlim(sb: &vfs::SuperBlock, kind: vfs::QuotaType, id: u64, addr: u64) -> i64 {
    let mut q = match read_quota(addr) { Ok(q) => q, Err(rv) => return rv };
    if !sb.s_op.quota_set_xfs_supported(sb) { return eno(Errno::Enosys); }
    let qid = qid(kind, id);
    if id == 0 && q.d_fieldmask & (FS_DQ_TIMER_MASK | FS_DQ_WARNS_MASK) != 0 {
        if !sb.s_op.quota_set_info_xfs_supported(sb) { return eno(Errno::Einval); }
        let info = vfs::MemDqinfo {
            dqi_bgrace: if q.d_fieldmask & FS_DQ_BTIMER != 0 { xfs_info_timer(q.d_btimer) } else { 0 },
            dqi_igrace: if q.d_fieldmask & FS_DQ_ITIMER != 0 { xfs_info_timer(q.d_itimer) } else { 0 },
            dqi_rt_bgrace: if q.d_fieldmask & FS_DQ_RTBTIMER != 0 { xfs_info_timer(q.d_rtbtimer) } else { 0 },
            dqi_bwarnlimit: if q.d_fieldmask & FS_DQ_BWARNS != 0 { q.d_bwarns } else { 0 },
            dqi_iwarnlimit: if q.d_fieldmask & FS_DQ_IWARNS != 0 { q.d_iwarns } else { 0 },
            dqi_rtbwarnlimit: if q.d_fieldmask & FS_DQ_RTBWARNS != 0 { q.d_rtbwarns } else { 0 },
            dqi_flags: 0,
            dqi_valid: ifinfo_mask(q.d_fieldmask),
        };
        if let Err(e) = sb.s_op.quota_set_info_xfs(sb, kind, info) { return crate::namei_common::errno_from_vfs(e); }
        q.d_fieldmask &= !(FS_DQ_TIMER_MASK | FS_DQ_WARNS_MASK);
    }
    sb.s_op.quota_set_xfs(sb, qid, xfs_to_mem_quota(q), xfs_fieldmask(q.d_fieldmask), quota_now_sec()).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
}

fn get_qstat(sb: &vfs::SuperBlock, kind: vfs::QuotaType, addr: u64) -> i64 {
    let state = match quota_state(sb) { Ok(s) => s, Err(e) => return crate::namei_common::errno_from_vfs(e) };
    let flags = quota_state_flags(&state);
    let info = state.types[kind.slot()].info;
    // Quota inodes may exist while the class is inactive, so each slot is
    // reported whenever its inode number is present. Q_XGETQSTAT has no
    // project slot, so project state borrows the group slot — but only when
    // group accounting is off, and only if a project quota inode exists.
    let mut uquota = FsQfilestat::default();
    if state.types[vfs::QuotaType::User.slot()].file.ino != 0 { uquota = qfilestat(&state, vfs::QuotaType::User); }
    let mut gquota = FsQfilestat::default();
    if state.types[vfs::QuotaType::Group.slot()].file.ino != 0 { gquota = qfilestat(&state, vfs::QuotaType::Group); }
    if state.types[vfs::QuotaType::Project.slot()].file.ino != 0
        && !state.types[vfs::QuotaType::Group.slot()].accounting {
        gquota = qfilestat(&state, vfs::QuotaType::Project);
    }
    if flags == 0 { return eno(Errno::Enosys); }
    let out = FsQuotaStat {
        qs_version: FS_QSTAT_VERSION,
        qs_flags: flags,
        qs_uquota: uquota,
        qs_gquota: gquota,
        qs_incoredqs: incore_dquots(&state),
        qs_btimelimit: info.dqi_bgrace as i32,
        qs_itimelimit: info.dqi_igrace as i32,
        qs_rtbtimelimit: info.dqi_rt_bgrace as i32,
        qs_bwarnlimit: info.dqi_bwarnlimit,
        qs_iwarnlimit: info.dqi_iwarnlimit,
        ..FsQuotaStat::default()
    };
    write_raw(addr, out)
}

fn get_qstatv(sb: &vfs::SuperBlock, kind: vfs::QuotaType, addr: u64) -> i64 {
    if !sb.s_op.quota_get_state_supported(sb) { return eno(Errno::Enosys); }
    if !user_range(addr, core::mem::size_of::<i8>() as u64) { return eno(Errno::Efault); }
    // SAFETY: user range validated for the version byte; trap handling is owned by the arch usercopy path.
    let version = unsafe { core::ptr::read_volatile(addr as *const i8) };
    if version != FS_QSTATV_VERSION1 { return eno(Errno::Einval); }
    let state = match quota_state(sb) { Ok(s) => s, Err(e) => return crate::namei_common::errno_from_vfs(e) };
    let flags = quota_state_flags(&state);
    let info = state.types[kind.slot()].info;
    let uquota = qfilestatv(&state, vfs::QuotaType::User);
    let gquota = qfilestatv(&state, vfs::QuotaType::Group);
    let pquota = qfilestatv(&state, vfs::QuotaType::Project);
    if flags == 0 { return eno(Errno::Enosys); }
    let out = FsQuotaStatv {
        qs_version: FS_QSTATV_VERSION1,
        qs_flags: flags,
        qs_incoredqs: incore_dquots(&state),
        qs_uquota: uquota,
        qs_gquota: gquota,
        qs_pquota: pquota,
        qs_btimelimit: info.dqi_bgrace as i32,
        qs_itimelimit: info.dqi_igrace as i32,
        qs_rtbtimelimit: info.dqi_rt_bgrace as i32,
        qs_bwarnlimit: info.dqi_bwarnlimit,
        qs_iwarnlimit: info.dqi_iwarnlimit,
        qs_rtbwarnlimit: info.dqi_rtbwarnlimit,
        ..FsQuotaStatv::default()
    };
    write_raw(addr, out)
}

fn read_quota(addr: u64) -> Result<FsDiskQuota, i64> {
    if !user_range(addr, core::mem::size_of::<FsDiskQuota>() as u64) { return Err(eno(Errno::Efault)); }
    // SAFETY: user range validated for an fs_disk_quota-sized load; trap handling is owned by the arch usercopy path.
    Ok(unsafe { core::ptr::read_volatile(addr as *const FsDiskQuota) })
}

fn read_flags(addr: u64) -> Result<u32, i64> {
    if !user_range(addr, core::mem::size_of::<u32>() as u64) { return Err(eno(Errno::Efault)); }
    // SAFETY: user range validated for a u32-sized load; trap handling is owned by the arch usercopy path.
    Ok(unsafe { core::ptr::read_volatile(addr as *const u32) })
}

pub(super) fn quota_enable(sb: &vfs::SuperBlock, addr: u64) -> i64 {
    let flags = match read_flags(addr) { Ok(f) => f, Err(rv) => return rv };
    if !sb.s_op.quota_enable_xfs_supported(sb) { return eno(Errno::Enosys); }
    if flags & !quota_flag_mask() != 0 { return eno(Errno::Einval); }
    sb.s_op.quota_enable_xfs(sb, flags).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
}

fn quota_disable(sb: &vfs::SuperBlock, addr: u64) -> i64 {
    let flags = match read_flags(addr) { Ok(f) => f, Err(rv) => return rv };
    if !sb.s_op.quota_disable_xfs_supported(sb) { return eno(Errno::Enosys); }
    if flags & !quota_flag_mask() != 0 { return eno(Errno::Einval); }
    sb.s_op.quota_disable_xfs(sb, flags).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
}

fn quota_remove(sb: &vfs::SuperBlock, addr: u64) -> i64 {
    let flags = match read_flags(addr) { Ok(f) => f, Err(rv) => return rv };
    sb.s_op.quota_remove_xfs(sb, flags).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
}

fn write_quota(addr: u64, kind: vfs::QuotaType, id: u32, dq: vfs::MemDqblk) -> i64 {
    write_raw(addr, mem_to_xfs_quota(kind, id, dq))
}

fn mem_to_xfs_quota(kind: vfs::QuotaType, id: u32, dq: vfs::MemDqblk) -> FsDiskQuota {
    let bigtime = timer_needs_bigtime(dq.dqb_itime)
        || timer_needs_bigtime(dq.dqb_btime)
        || timer_needs_bigtime(dq.dqb_rtbtimer);
    let mut out = FsDiskQuota {
        d_version: FS_DQUOT_VERSION,
        d_flags: quota_flag(kind),
        d_fieldmask: if bigtime { FS_DQ_BIGTIME } else { 0 },
        d_id: id,
        d_blk_hardlimit: stoqb512(dq.dqb_bhardlimit),
        d_blk_softlimit: stoqb512(dq.dqb_bsoftlimit),
        d_ino_hardlimit: dq.dqb_ihardlimit,
        d_ino_softlimit: dq.dqb_isoftlimit,
        d_bcount: stoqb512(dq.dqb_curspace),
        d_icount: dq.dqb_curinodes,
        d_itimer: dq.dqb_itime as i32,
        d_btimer: dq.dqb_btime as i32,
        d_iwarns: 0,
        d_bwarns: 0,
        d_itimer_hi: 0,
        d_btimer_hi: 0,
        d_rtbtimer_hi: 0,
        d_padding2: 0,
        d_rtb_hardlimit: stoqb512(dq.dqb_rtb_hardlimit),
        d_rtb_softlimit: stoqb512(dq.dqb_rtb_softlimit),
        d_rtbcount: stoqb512(dq.dqb_rtbcount),
        d_rtbtimer: dq.dqb_rtbtimer as i32,
        d_rtbwarns: 0,
        d_padding3: 0,
        d_padding4: [0; 8],
    };
    encode_timer(dq.dqb_itime, bigtime, &mut out.d_itimer, &mut out.d_itimer_hi);
    encode_timer(dq.dqb_btime, bigtime, &mut out.d_btimer, &mut out.d_btimer_hi);
    encode_timer(dq.dqb_rtbtimer, bigtime, &mut out.d_rtbtimer, &mut out.d_rtbtimer_hi);
    out
}

fn xfs_to_mem_quota(q: FsDiskQuota) -> vfs::MemDqblk {
    vfs::MemDqblk {
        dqb_bhardlimit: qbtos512(q.d_blk_hardlimit),
        dqb_bsoftlimit: qbtos512(q.d_blk_softlimit),
        dqb_curspace:   qbtos512(q.d_bcount),
        dqb_rsvspace:   0,
        dqb_ihardlimit: q.d_ino_hardlimit,
        dqb_isoftlimit: q.d_ino_softlimit,
        dqb_curinodes:  q.d_icount,
        dqb_btime:      decode_timer(&q, q.d_btimer, q.d_btimer_hi),
        dqb_itime:      decode_timer(&q, q.d_itimer, q.d_itimer_hi),
        dqb_rtb_hardlimit: qbtos512(q.d_rtb_hardlimit),
        dqb_rtb_softlimit: qbtos512(q.d_rtb_softlimit),
        dqb_rtbcount:      qbtos512(q.d_rtbcount),
        dqb_rtbtimer:      decode_timer(&q, q.d_rtbtimer, q.d_rtbtimer_hi),
        dqb_valid:      q.d_fieldmask as u32,
    }
}

fn xfs_fieldmask(fieldmask: u16) -> u32 {
    let mut mask = 0;
    if fieldmask & FS_DQ_BHARD != 0 { mask |= vfs::DQB_SPC_HARD; }
    if fieldmask & FS_DQ_BSOFT != 0 { mask |= vfs::DQB_SPC_SOFT; }
    if fieldmask & FS_DQ_IHARD != 0 { mask |= vfs::DQB_INO_HARD; }
    if fieldmask & FS_DQ_ISOFT != 0 { mask |= vfs::DQB_INO_SOFT; }
    if fieldmask & FS_DQ_BCOUNT != 0 { mask |= vfs::DQB_SPACE; }
    if fieldmask & FS_DQ_ICOUNT != 0 { mask |= vfs::DQB_INO_COUNT; }
    if fieldmask & FS_DQ_BTIMER != 0 { mask |= vfs::DQB_SPC_TIMER; }
    if fieldmask & FS_DQ_ITIMER != 0 { mask |= vfs::DQB_INO_TIMER; }
    if fieldmask & FS_DQ_RTBHARD != 0 { mask |= vfs::DQB_RTB_HARD; }
    if fieldmask & FS_DQ_RTBSOFT != 0 { mask |= vfs::DQB_RTB_SOFT; }
    if fieldmask & FS_DQ_RTBCOUNT != 0 { mask |= vfs::DQB_RTB_COUNT; }
    if fieldmask & FS_DQ_RTBTIMER != 0 { mask |= vfs::DQB_RTB_TIMER; }
    mask
}

fn quota_state(sb: &vfs::SuperBlock) -> vfs::KResult<vfs::QuotaState> {
    sb.s_op.quota_get_state(sb)
}

fn quota_state_flags(state: &vfs::QuotaState) -> u16 {
    let mut flags = 0;
    if state.types[vfs::QuotaType::User.slot()].accounting { flags |= FS_QUOTA_UDQ_ACCT; }
    if state.types[vfs::QuotaType::Group.slot()].accounting { flags |= FS_QUOTA_GDQ_ACCT; }
    if state.types[vfs::QuotaType::Project.slot()].accounting { flags |= FS_QUOTA_PDQ_ACCT; }
    if state.types[vfs::QuotaType::User.slot()].enforcement { flags |= FS_QUOTA_UDQ_ENFD; }
    if state.types[vfs::QuotaType::Group.slot()].enforcement { flags |= FS_QUOTA_GDQ_ENFD; }
    if state.types[vfs::QuotaType::Project.slot()].enforcement { flags |= FS_QUOTA_PDQ_ENFD; }
    flags
}

fn quota_flag_mask() -> u32 {
    (FS_QUOTA_UDQ_ACCT | FS_QUOTA_GDQ_ACCT | FS_QUOTA_PDQ_ACCT) as u32
        | enforce_flag(vfs::QuotaType::User) | enforce_flag(vfs::QuotaType::Group) | enforce_flag(vfs::QuotaType::Project)
}

fn enforce_flag(kind: vfs::QuotaType) -> u32 {
    match kind {
        vfs::QuotaType::User => FS_QUOTA_UDQ_ENFD as u32,
        vfs::QuotaType::Group => FS_QUOTA_GDQ_ENFD as u32,
        vfs::QuotaType::Project => FS_QUOTA_PDQ_ENFD as u32,
    }
}

fn incore_dquots(state: &vfs::QuotaState) -> u32 {
    state.types.iter().map(|s| s.incoredqs).sum()
}

fn qfilestat(state: &vfs::QuotaState, kind: vfs::QuotaType) -> FsQfilestat {
    let st = state.types[kind.slot()].file;
    FsQfilestat { qfs_ino: st.ino, qfs_nblks: st.blocks, qfs_nextents: st.nextents }
}

fn qfilestatv(state: &vfs::QuotaState, kind: vfs::QuotaType) -> FsQfilestatv {
    let st = state.types[kind.slot()].file;
    FsQfilestatv { qfs_ino: st.ino, qfs_nblks: st.blocks, qfs_nextents: st.nextents, qfs_pad: 0 }
}

fn quota_flag(kind: vfs::QuotaType) -> i8 {
    match kind {
        vfs::QuotaType::User => FS_USER_QUOTA,
        vfs::QuotaType::Group => FS_GROUP_QUOTA,
        vfs::QuotaType::Project => FS_PROJ_QUOTA,
    }
}

fn ifinfo_mask(fieldmask: u16) -> u32 {
    let mut mask = 0;
    if fieldmask & FS_DQ_BTIMER != 0 { mask |= vfs::IIF_BGRACE; }
    if fieldmask & FS_DQ_ITIMER != 0 { mask |= vfs::IIF_IGRACE; }
    if fieldmask & FS_DQ_RTBTIMER != 0 { mask |= vfs::IIF_RT_BGRACE; }
    if fieldmask & FS_DQ_BWARNS != 0 { mask |= vfs::IIF_BWARN; }
    if fieldmask & FS_DQ_IWARNS != 0 { mask |= vfs::IIF_IWARN; }
    if fieldmask & FS_DQ_RTBWARNS != 0 { mask |= vfs::IIF_RTBWARN; }
    mask
}

fn stoqb512(space: u64) -> u64 { space.saturating_add(511) >> 9 }
fn qbtos512(blocks: u64) -> u64 { blocks.checked_shl(9).unwrap_or(u64::MAX) }

fn xfs_info_timer(v: i32) -> u64 { v as u32 as u64 }

fn decode_timer(q: &FsDiskQuota, lo: i32, hi: i8) -> i64 {
    if q.d_fieldmask & FS_DQ_BIGTIME != 0 { (lo as u32 as i64) | ((hi as i64) << 32) } else { lo as i64 }
}

fn timer_needs_bigtime(t: i64) -> bool {
    t > i32::MAX as i64 || t < i32::MIN as i64
}

fn encode_timer(t: i64, bigtime: bool, lo: &mut i32, hi: &mut i8) {
    *lo = t as i32;
    if bigtime {
        *hi = (t >> 32) as i8;
    }
}
