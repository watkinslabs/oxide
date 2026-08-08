extern crate alloc;

use alloc::sync::Arc;

use crate::superblock::{SuperBlock, fs_supers};
use crate::types::{KResult, VfsError};

use super::dquot::DquotSet;
use super::ids::{Kqid, QuotaType};
use super::inode::dquot_drop_type_on;
use super::limits::{DQF_ROOT_SQUASH, DQF_SETINFO_MASK, IIF_ALL, IIF_FLAGS, MemDqblk, MemDqinfo};
use super::ops::DquotOperations;

pub const QFMT_VFS_OLD: u32 = 1;
pub const QFMT_VFS_V1: u32 = 4;
pub const QFMT_VFS_V0: u32 = 2;
/// In-memory quota format: the live dquot IS the record. A filesystem with no
/// persistent store carries its limits nowhere else, so a class using this
/// format has nothing to reload a dropped dquot from.
pub const QFMT_SHMEM: u32 = 5;

/// Enable one quota class with filesystem dquot operations. # C: O(1)
pub fn quota_on(sb: &SuperBlock, kind: QuotaType, fmt: u32, ops: Arc<dyn DquotOperations>) -> KResult<()> {
    if sb.s_dquot.is_enabled(kind) || sb.s_dquot.is_closing(kind) { return Err(VfsError::Ebusy); }
    sb.s_dquot.set_operations(kind, ops);
    sb.s_dquot.enable(kind, fmt);
    Ok(())
}

/// Disable one quota class, detach inode slots, and drop cached dquots. # C: O(N_ino+N_dq)
pub fn quota_off(sb: &SuperBlock, kind: QuotaType) -> KResult<()> {
    if !sb.s_dquot.begin_disable(kind) && !sb.s_dquot.is_closing(kind) { return Err(VfsError::Esrch); }
    let mut first = Ok(());
    if let Some(ops) = sb.s_dquot.operations(kind) {
        if let Err(e) = write_kind(sb.s_dquot.dquots(), kind, ops.as_ref()) {
            first = Err(e);
        }
    }
    sb.for_each_inode(|inode| dquot_drop_type_on(sb, inode, kind));
    if let Some(ops) = sb.s_dquot.operations(kind) {
        if let Err(e) = ops.write_info(kind, sb.s_dquot.info(kind)) {
            if first.is_ok() { first = Err(e); }
        }
    }
    sb.s_dquot.wait_for_kind_quiesced(kind);
    let mut drop_first = Ok(());
    for dq in sb.s_dquot.dquots().by_kind(kind) {
        if let Err(e) = sb.s_dquot.drop_inactive_dquot(dq) {
            if drop_first.is_ok() { drop_first = Err(e); }
        }
    }
    if let Err(e) = drop_first {
        if first.is_ok() { first = Err(e); }
        return first;
    }
    if let Some(ops) = sb.s_dquot.operations(kind) {
        if let Err(e) = ops.free_file_info(kind) {
            if first.is_ok() { first = Err(e); }
        }
    }
    if first.is_err() { return first; }
    sb.s_dquot.disable(kind);
    sb.s_dquot.clear_info(kind);
    sb.s_dquot.clear_operations(kind);
    first
}

/// Enable limit enforcement for an accounting-active quota class. # C: O(1)
pub fn quota_enable_limits(sb: &SuperBlock, kind: QuotaType) -> KResult<()> {
    sb.s_dquot.enable_limits(kind)
}

/// Disable limit enforcement while retaining quota accounting state. # C: O(1)
pub fn quota_disable_limits(sb: &SuperBlock, kind: QuotaType) -> KResult<()> {
    sb.s_dquot.disable_limits(kind)
}

/// True when any quota class is active from a filesystem system quota file. # C: O(MAXQUOTAS)
pub fn quota_sysfile_active(sb: &SuperBlock) -> bool {
    [QuotaType::User, QuotaType::Group, QuotaType::Project]
        .into_iter()
        .any(|kind| sb.s_dquot.is_enabled(kind) && sb.s_dquot.info(kind).dqi_flags & super::limits::DQF_SYS_FILE != 0)
}

/// Suspend active system-file quotas for RW→RO remount. # C: O(MAXQUOTAS*(N_ino+N_dq))
pub fn quota_suspend_sysfiles(sb: &SuperBlock) -> KResult<()> {
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        if !sb.s_dquot.is_enabled(kind) || sb.s_dquot.info(kind).dqi_flags & super::limits::DQF_SYS_FILE == 0 { continue; }
        quota_sync(sb, kind)?;
    }
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        if !sb.s_dquot.is_enabled(kind) || sb.s_dquot.info(kind).dqi_flags & super::limits::DQF_SYS_FILE == 0 { continue; }
        sb.for_each_inode(|inode| dquot_drop_type_on(sb, inode, kind));
        sb.s_dquot.suspend(kind)?;
    }
    Ok(())
}

/// Final superblock quota teardown used by unmount. # C: O(MAXQUOTAS*(N_ino+N_dq))
pub fn quota_shutdown(sb: &SuperBlock) -> KResult<()> {
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        if sb.s_dquot.is_enabled(kind) || sb.s_dquot.is_closing(kind) { quota_off(sb, kind)?; }
    }
    Ok(())
}

/// Active on-disk quota format. # C: O(1)
pub fn quota_getfmt(sb: &SuperBlock, kind: QuotaType) -> KResult<u32> {
    if !sb.s_dquot.is_enabled(kind) { return Err(VfsError::Esrch); }
    Ok(sb.s_dquot.format(kind))
}

/// Read quota-file info for one active class. # C: O(1)
pub fn quota_getinfo(sb: &SuperBlock, kind: QuotaType) -> KResult<MemDqinfo> {
    if !sb.s_dquot.is_enabled(kind) { return Err(VfsError::Esrch); }
    Ok(sb.s_dquot.info(kind))
}

/// Update quota-file info for one active class. # C: O(1)
pub fn quota_setinfo(sb: &SuperBlock, kind: QuotaType, info: MemDqinfo) -> KResult<()> {
    if info.dqi_valid & !IIF_ALL != 0 { return Err(VfsError::Einval); }
    if info.dqi_valid & IIF_FLAGS != 0 && info.dqi_flags & !DQF_SETINFO_MASK != 0 { return Err(VfsError::Einval); }
    if !sb.s_dquot.is_enabled(kind) { return Err(VfsError::Esrch); }
    if info.dqi_valid & IIF_FLAGS != 0 && info.dqi_flags & DQF_ROOT_SQUASH != 0 && sb.s_dquot.format(kind) != QFMT_VFS_OLD { return Err(VfsError::Einval); }
    let old = sb.s_dquot.info(kind);
    sb.s_dquot.set_info(kind, info);
    match sb.s_dquot.operations(kind) {
        Some(ops) => {
            if let Err(e) = ops.write_info(kind, sb.s_dquot.info(kind)) {
                sb.s_dquot.load_info(kind, old);
                return Err(e);
            }
            Ok(())
        }
        None => Ok(()),
    }
}

/// Read one quota record. # C: O(log N)+FS
pub fn quota_getquota(sb: &SuperBlock, qid: Kqid) -> KResult<MemDqblk> {
    if !sb.s_dquot.is_enabled(qid.kind) { return Err(VfsError::Esrch); }
    let dq = sb.s_dquot.dqget(qid)?;
    let dqblk = dq.dqblk();
    sb.s_dquot.dqput(dq);
    Ok(dqblk)
}

/// Read the lowest persistent quota record at or after `qid.id`. # C: FS-dependent
pub fn quota_getnextquota(sb: &SuperBlock, qid: Kqid) -> KResult<(Kqid, MemDqblk)> {
    if !sb.s_dquot.is_enabled(qid.kind) { return Err(VfsError::Esrch); }
    let ops = sb.s_dquot.operations(qid.kind).ok_or(VfsError::Enosys)?;
    let next = ops.get_next_id(qid)?.ok_or(VfsError::Enoent)?;
    if next.kind != qid.kind { return Err(VfsError::Einval); }
    let dq = sb.s_dquot.dqget(next)?;
    let dqblk = dq.dqblk();
    sb.s_dquot.dqput(dq);
    Ok((next, dqblk))
}

/// Replace one quota record and mark it dirty for backend persistence. # C: O(log N)+FS
pub fn quota_setquota(sb: &SuperBlock, qid: Kqid, dqblk: MemDqblk) -> KResult<()> {
    if !sb.s_dquot.is_enabled(qid.kind) { return Err(VfsError::Esrch); }
    dqblk.validate_limits_for_format(sb.s_dquot.format(qid.kind))?;
    let dq = sb.s_dquot.dqget(qid)?;
    let old = dq.dqblk();
    let old_dirty = dq.is_dirty();
    dq.set_dqblk(dqblk);
    dq.mark_dirty();
    let ret = match sb.s_dquot.operations(qid.kind) {
        Some(ops) => ops.mark_dirty(dq.as_ref()),
        None => Ok(()),
    };
    if ret.is_err() { restore_dqblk(dq.as_ref(), old, old_dirty); }
    sb.s_dquot.dqput(dq);
    ret?;
    Ok(())
}

/// Apply Linux masked quota record updates and mark the dquot dirty. # C: O(log N)+FS
pub fn quota_setquota_masked(sb: &SuperBlock, qid: Kqid, dqblk: MemDqblk, fieldmask: u32, now_sec: u64) -> KResult<()> {
    if !sb.s_dquot.is_enabled(qid.kind) { return Err(VfsError::Esrch); }
    dqblk.validate_masked_limits_for_format(sb.s_dquot.format(qid.kind), fieldmask)?;
    let dq = sb.s_dquot.dqget(qid)?;
    let info = sb.s_dquot.info(qid.kind);
    let old = dq.dqblk();
    let old_dirty = dq.is_dirty();
    let ret = dq.set_dqblk_masked(dqblk, fieldmask, info, now_sec);
    if ret.is_ok() {
        dq.mark_dirty();
        if let Some(ops) = sb.s_dquot.operations(qid.kind) {
            if let Err(e) = ops.mark_dirty(dq.as_ref()) {
                restore_dqblk(dq.as_ref(), old, old_dirty);
                sb.s_dquot.dqput(dq);
                return Err(e);
            }
        }
    }
    sb.s_dquot.dqput(dq);
    ret
}

fn restore_dqblk(dq: &super::dquot::Dquot, old: MemDqblk, old_dirty: bool) {
    dq.set_dqblk(old);
    if old_dirty { dq.mark_dirty(); } else { dq.clear_dirty(); }
}

/// Persist every cached dquot for one active quota class. # C: O(N_dq)+FS
pub fn quota_sync(sb: &SuperBlock, kind: QuotaType) -> KResult<()> {
    if !sb.s_dquot.is_enabled(kind) { return Ok(()); }
    if let Some(ops) = sb.s_dquot.operations(kind) {
        write_kind(sb.s_dquot.dquots(), kind, ops.as_ref())?;
        ops.write_info(kind, sb.s_dquot.info(kind))?;
    }
    Ok(())
}

/// Global `Q_SYNC` across all registered superblocks. # C: O(N_sb*N_dq)+FS
pub fn quota_sync_all(kind: Option<QuotaType>) -> KResult<()> {
    for sb in fs_supers() {
        match kind {
            Some(k) => quota_sync(&sb, k)?,
            None => {
                for k in [QuotaType::User, QuotaType::Group, QuotaType::Project] { quota_sync(&sb, k)?; }
            }
        }
    }
    Ok(())
}

fn write_kind(set: &DquotSet, kind: QuotaType, ops: &dyn DquotOperations) -> KResult<()> {
    let mut first = Ok(());
    for dq in set.by_kind(kind) {
        if !dq.is_dirty() { continue; }
        if let Err(e) = ops.write_dquot(dq.as_ref()) {
            if first.is_ok() { first = Err(e); }
            continue;
        }
        dq.clear_dirty();
    }
    first
}
