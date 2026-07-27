use core::sync::atomic::Ordering;
use syscall::errno::Errno;

use super::{abi::{dqinfo_classic_valid, if_dqblk_fieldmask, read_dqblk, read_dqinfo, write_dqblk, write_dqinfo, write_next_dqblk, write_u32}, cmd::*, eno, xfs};

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// Global/no-target command dispatch for legacy `quotactl`. # C: O(N_sb*N_dq)
pub fn quotactl_dispatch(cmd: u64) -> i64 {
    let subcmd = cmd >> SUBCMD_SHIFT;
    let qtype = cmd & QTYPE_MASK;

    if subcmd == Q_SYNC {
        let kind = if qtype < MAXQUOTAS { quota_type(qtype) } else { None };
        return vfs::quota_sync_all(kind).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs);
    }
    if qtype >= MAXQUOTAS { return eno(Errno::Einval); }
    eno(Errno::Esrch)
}

/// Targeted command dispatch for `quotactl_fd` and future block-device
/// `quotactl` target resolution. # C: O(log N)+FS
pub fn quotactl_dispatch_sb(sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64) -> i64 {
    quotactl_dispatch_sb_locked(sb, cmd, id, addr, Ok(None))
}

fn quotactl_dispatch_sb_locked(
    sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64,
    quotaon_path: Result<Option<&vfs::VfsPath>, i64>,
) -> i64 {
    if quotactl_cmd_onoff(cmd) {
        sb.with_s_umount_write(|| quotactl_dispatch_sb_with_path(sb, cmd, id, addr, quotaon_path))
    } else {
        sb.with_s_umount_read(|| quotactl_dispatch_sb_with_path(sb, cmd, id, addr, quotaon_path))
    }
}

pub(super) fn quotactl_dispatch_sb_block(
    sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64,
    quotaon_path: Result<Option<&vfs::VfsPath>, i64>,
) -> i64 {
    loop {
        let rv = if quotactl_cmd_onoff(cmd) {
            sb.with_s_umount_write(|| quotactl_dispatch_sb_block_inner(sb, cmd, id, addr, quotaon_path))
        } else {
            sb.with_s_umount_read(|| quotactl_dispatch_sb_block_inner(sb, cmd, id, addr, quotaon_path))
        };
        match rv {
            Some(rv) => return rv,
            None => {
                if !sb.wait_until_thawed() { return eno(Errno::Erofs); }
            }
        }
    }
}

fn quotactl_dispatch_sb_block_inner(
    sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64,
    quotaon_path: Result<Option<&vfs::VfsPath>, i64>,
) -> Option<i64> {
    if quotactl_cmd_write(cmd) {
        if sb.is_frozen() { return None; }
        if sb.is_readonly() { return Some(eno(Errno::Erofs)); }
    }
    Some(quotactl_dispatch_sb_with_path(sb, cmd, id, addr, quotaon_path))
}

fn quotactl_dispatch_sb_with_path(
    sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64,
    quotaon_path: Result<Option<&vfs::VfsPath>, i64>,
) -> i64 {
    let subcmd = cmd >> SUBCMD_SHIFT;
    let qtype = cmd & QTYPE_MASK;

    if !sb.s_op.quota_supported() { return eno(Errno::Enosys); }
    let Some(kind) = quota_type(qtype) else { return eno(Errno::Einval); };
    if !sb.s_op.quota_type_supported(kind) { return eno(Errno::Einval); }

    if subcmd == Q_SYNC {
        if !sb.s_op.quota_sync_supported(sb, kind) { return eno(Errno::Enosys); }
        return sb.s_op.quota_sync(sb, kind).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs);
    }

    let cur = match current_task() {
        Some(c) => c, None => return eno(Errno::Esrch),
    };
    let qcred = current_quota_cred(cur);
    let Some(qcmd) = quota_cmd(subcmd) else {
        if qcred.cap_sys_admin { return eno(Errno::Einval); }
        return eno(Errno::Eperm);
    };
    if let Err(e) = vfs::quota_check_quotactl_permission(qcmd, kind, id as u32, &qcred) {
        return crate::namei_common::errno_from_vfs(e);
    }

    match subcmd {
        Q_QUOTAOFF => {
            if sb.s_op.quota_disable_supported(sb, kind) {
                return sb.s_op.quota_disable(sb, kind).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs);
            }
            sb.s_op.quota_off(sb, kind).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
        }
        Q_GETFMT => {
            let fmt = match vfs::quota_getfmt(sb, kind) { Ok(f) => f, Err(e) => return crate::namei_common::errno_from_vfs(e) };
            write_u32(addr, fmt)
        }
        Q_GETQUOTA => {
            let dq = match vfs::quota_getquota(sb, qid(kind, id)) { Ok(d) => d, Err(e) => return crate::namei_common::errno_from_vfs(e) };
            write_dqblk(addr, dq)
        }
        Q_GETNEXTQUOTA => {
            let (next, dq) = match vfs::quota_getnextquota(sb, qid(kind, id)) { Ok(d) => d, Err(e) => return crate::namei_common::errno_from_vfs(e) };
            write_next_dqblk(addr, next.id, dq)
        }
        Q_SETQUOTA => {
            let dqblk = match read_dqblk(addr) { Ok(d) => d, Err(rv) => return rv };
            let qid = qid(kind, id);
            let fieldmask = if_dqblk_fieldmask(dqblk.dqb_valid);
            vfs::quota_setquota_masked(sb, qid, dqblk, fieldmask, quota_now_sec()).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
        }
        Q_GETINFO => {
            if !sb.s_op.quota_get_state_supported(sb) { return eno(Errno::Enosys); }
            let state = match sb.s_op.quota_get_state(sb) { Ok(s) => s, Err(e) => return crate::namei_common::errno_from_vfs(e) };
            let type_state = state.types[kind.slot()];
            if !type_state.accounting { return eno(Errno::Esrch); }
            let mut info = type_state.info;
            info.dqi_valid = vfs::IIF_ALL;
            write_dqinfo(addr, info)
        }
        Q_SETINFO => {
            let info = match read_dqinfo(addr) { Ok(i) => i, Err(rv) => return rv };
            if !sb.s_op.quota_set_info_xfs_supported(sb) { return eno(Errno::Enosys); }
            if !dqinfo_classic_valid(info) { return eno(Errno::Einval); }
            sb.s_op.quota_set_info_xfs(sb, kind, info).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
        }
        Q_QUOTAON => {
            if sb.s_op.quota_enable_supported(sb, kind) {
                return sb.s_op.quota_enable(sb, kind).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs);
            }
            if !sb.s_op.quota_on_supported(sb, kind) { return eno(Errno::Enosys); }
            let owned;
            let qpath = match quotaon_path {
                Ok(Some(p)) => p,
                Ok(None) => {
                    owned = match resolve_quotaon_path(addr) { Ok(p) => p, Err(rv) => return rv };
                    &owned
                }
                Err(rv) => return rv,
            };
            sb.s_op.quota_on(sb, kind, id as u32, Some(qpath)).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs)
        }
        _ => xfs::dispatch(sb, subcmd, kind, id, addr),
    }
}

/// Targeted dispatch for `quotactl_fd`; Linux passes an invalid quota-file path
/// for `Q_QUOTAON`, so sysfile filesystems route it to quota-enable flags.
/// # C: O(log N)+FS
pub fn quotactl_dispatch_sb_fd(sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64) -> i64 {
    if quotactl_cmd_onoff(cmd) {
        sb.with_s_umount_write(|| quotactl_dispatch_sb_fd_inner(sb, cmd, id, addr))
    } else {
        sb.with_s_umount_read(|| quotactl_dispatch_sb_fd_inner(sb, cmd, id, addr))
    }
}

fn quotactl_dispatch_sb_fd_inner(sb: &vfs::SuperBlock, cmd: u64, id: u64, addr: u64) -> i64 {
    let subcmd = cmd >> SUBCMD_SHIFT;
    let qtype = cmd & QTYPE_MASK;

    if qtype >= MAXQUOTAS { return eno(Errno::Einval); }
    if !sb.s_op.quota_supported() { return eno(Errno::Enosys); }
    let Some(kind) = quota_type(qtype) else { return eno(Errno::Einval); };
    if !sb.s_op.quota_type_supported(kind) { return eno(Errno::Einval); }
    if subcmd != Q_QUOTAON { return quotactl_dispatch_sb_with_path(sb, cmd, id, addr, Ok(None)); }

    let cur = match current_task() {
        Some(c) => c, None => return eno(Errno::Esrch),
    };
    let qcred = current_quota_cred(cur);
    if let Err(e) = vfs::quota_check_quotactl_permission(vfs::QuotaCtlCmd::QuotaOn, kind, id as u32, &qcred) {
        return crate::namei_common::errno_from_vfs(e);
    }
    if sb.s_op.quota_enable_supported(sb, kind) {
        return sb.s_op.quota_enable(sb, kind).map(|_| 0).unwrap_or_else(crate::namei_common::errno_from_vfs);
    }
    if !sb.s_op.quota_on_supported(sb, kind) { return eno(Errno::Enosys); }
    eno(Errno::Einval)
}

/// Core no-target fallback retained for legacy callers until block-device
/// target lookup is wired.
/// # C: O(1)
pub fn quotactl_noquota_dispatch(cmd: u64, id: u64) -> i64 {
    let subcmd = cmd >> SUBCMD_SHIFT;
    let qtype = cmd & QTYPE_MASK;

    // Q_SYNC is special-cased first in Linux: it accepts any type and needs no
    // specific fs (syncs all quota-enabled filesystems). None are enabled here,
    // so there is nothing to sync — success, exactly as Linux returns.
    if subcmd == Q_SYNC { return 0; }

    if qtype >= MAXQUOTAS { return eno(Errno::Einval); }

    let cur = match current_task() {
        Some(c) => c, None => return eno(Errno::Esrch),
    };

    match subcmd {
        Q_QUOTAON | Q_QUOTAOFF | Q_SETQUOTA | Q_SETINFO | Q_GETFMT | Q_GETINFO | Q_GETQUOTA | Q_GETNEXTQUOTA
        | Q_XQUOTAON | Q_XQUOTAOFF | Q_XQUOTARM | Q_XGETQSTAT | Q_XGETQSTATV
        | Q_XSETQLIM | Q_XGETQUOTA | Q_XGETNEXTQUOTA | Q_XQUOTASYNC => {
            let Some(kind) = quota_type(qtype) else { return eno(Errno::Einval); };
            let Some(qcmd) = quota_cmd(subcmd) else { return eno(Errno::Einval); };
            let qcred = current_quota_cred(cur);
            if let Err(e) = vfs::quota_check_quotactl_permission(qcmd, kind, id as u32, &qcred) {
                return crate::namei_common::errno_from_vfs(e);
            }
            eno(Errno::Esrch)
        }
        // Unknown subcmd -> EINVAL (do_quotactl switch default).
        _ => eno(Errno::Einval),
    }
}

pub(super) fn resolve_quotaon_path(addr: u64) -> Result<vfs::VfsPath, i64> {
    let raw = crate::namei_common::read_user_path(addr)?;
    crate::pathresolve::resolve_path_raw(&raw, true).map_err(crate::namei_common::errno_from_vfs)
}

fn quota_type(qtype: u64) -> Option<vfs::QuotaType> {
    match qtype {
        USRQUOTA => Some(vfs::QuotaType::User),
        GRPQUOTA => Some(vfs::QuotaType::Group),
        PRJQUOTA => Some(vfs::QuotaType::Project),
        _ => None,
    }
}

fn quota_cmd(subcmd: u64) -> Option<vfs::QuotaCtlCmd> {
    match subcmd {
        Q_SYNC => Some(vfs::QuotaCtlCmd::Sync),
        Q_QUOTAON => Some(vfs::QuotaCtlCmd::QuotaOn),
        Q_QUOTAOFF => Some(vfs::QuotaCtlCmd::QuotaOff),
        Q_GETFMT => Some(vfs::QuotaCtlCmd::GetFmt),
        Q_GETINFO => Some(vfs::QuotaCtlCmd::GetInfo),
        Q_SETINFO => Some(vfs::QuotaCtlCmd::SetInfo),
        Q_GETQUOTA => Some(vfs::QuotaCtlCmd::GetQuota),
        Q_SETQUOTA => Some(vfs::QuotaCtlCmd::SetQuota),
        Q_GETNEXTQUOTA => Some(vfs::QuotaCtlCmd::GetNextQuota),
        _ => xfs::command(subcmd),
    }
}

fn current_quota_cred(cur: &sched::Task) -> vfs::QuotaCtlCred {
    vfs::QuotaCtlCred {
        euid: cur.creds.euid.load(Ordering::Acquire),
        egid: cur.creds.egid.load(Ordering::Acquire),
        cap_sys_admin: cur.has_cap(sched::cap::SYS_ADMIN),
        groups: cur.creds.vfs_group_list(),
    }
}

pub(super) fn qid(kind: vfs::QuotaType, id: u64) -> vfs::Kqid {
    match kind {
        vfs::QuotaType::User => vfs::Kqid::user(id as u32),
        vfs::QuotaType::Group => vfs::Kqid::group(id as u32),
        vfs::QuotaType::Project => vfs::Kqid::project(id as u32),
    }
}

pub(super) fn quota_now_sec() -> u64 {
    vfs::inode_times::realtime_now_ns() / vfs::superblock::NSEC_PER_SEC
}
