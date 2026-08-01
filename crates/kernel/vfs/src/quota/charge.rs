use crate::types::{KResult, VfsError};

use super::limits::{MemDqblk, MemDqinfo};
use super::warn::QuotaWarnType;

/// `DQUOT_SPACE_WARN`: generate warnings and start the block grace timer when
/// the soft limit is first crossed. Absent for preallocation.
pub const DQUOT_SPACE_WARN: u32 = 0x1;
/// `DQUOT_SPACE_RESERVE`: charge `dqb_rsvspace` instead of `dqb_curspace`.
pub const DQUOT_SPACE_RESERVE: u32 = 0x2;
/// `DQUOT_SPACE_NOFAIL`: run warning/grace generation but never fail.
pub const DQUOT_SPACE_NOFAIL: u32 = 0x4;

/// Per-class inputs the limit ladder needs beyond the dquot record itself.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChargeCtx {
    /// Grace periods for the quota class (`dqi_bgrace`/`dqi_igrace`).
    pub info:      MemDqinfo,
    /// Wall-clock seconds used for grace-timer comparisons.
    pub now_sec:   u64,
    /// `sb_has_quota_limits_enabled`: accounting-only classes never fail.
    pub enforced:  bool,
    /// `ignore_hardlimit()`: CAP_SYS_RESOURCE, subject to root-squash.
    pub ignore_hardlimit: bool,
}

/// Outcome of one limit-ladder evaluation: updated record, admission result,
/// and the warning class the operation raised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChargeOutcome {
    pub dqblk: MemDqblk,
    pub result: KResult<()>,
    pub warn: QuotaWarnType,
}

/// `dquot_add_space`: block-limit ladder over the combined used+reserved
/// total. `space` charges `dqb_curspace`, `rsv_space` charges `dqb_rsvspace`;
/// both count toward the same limits. # C: O(1)
pub fn add_space(mut dqblk: MemDqblk, space: u64, rsv_space: u64, flags: u32, ctx: ChargeCtx) -> ChargeOutcome {
    let mut result = Ok(());
    let mut warn = QuotaWarnType::NoWarn;
    let warn_enabled = flags & DQUOT_SPACE_WARN != 0;
    if ctx.enforced && !is_fake(dqblk) {
        let tspace = dqblk.dqb_curspace
            .saturating_add(dqblk.dqb_rsvspace)
            .saturating_add(space)
            .saturating_add(rsv_space);
        if dqblk.dqb_bhardlimit != 0 && tspace > dqblk.dqb_bhardlimit && !ctx.ignore_hardlimit {
            if warn_enabled { warn = QuotaWarnType::BHardWarn; }
            result = Err(VfsError::Edquot);
        } else if dqblk.dqb_bsoftlimit != 0 && tspace > dqblk.dqb_bsoftlimit
            && dqblk.dqb_btime != 0 && grace_expired(dqblk.dqb_btime, ctx.now_sec)
            && !ctx.ignore_hardlimit {
            if warn_enabled { warn = QuotaWarnType::BSoftLongWarn; }
            result = Err(VfsError::Edquot);
        } else if dqblk.dqb_bsoftlimit != 0 && tspace > dqblk.dqb_bsoftlimit && dqblk.dqb_btime == 0 {
            if warn_enabled {
                warn = QuotaWarnType::BSoftWarn;
                dqblk.dqb_btime = grace_deadline(ctx.now_sec, ctx.info.dqi_bgrace);
            } else {
                // Preallocation is never allowed past the soft limit.
                result = Err(VfsError::Edquot);
            }
        }
    }
    if flags & DQUOT_SPACE_NOFAIL != 0 { result = Ok(()); }
    if result.is_ok() {
        dqblk.dqb_rsvspace = dqblk.dqb_rsvspace.saturating_add(rsv_space);
        dqblk.dqb_curspace = dqblk.dqb_curspace.saturating_add(space);
    }
    ChargeOutcome { dqblk, result, warn }
}

/// `dquot_add_inodes`: inode-count limit ladder. # C: O(1)
pub fn add_inodes(mut dqblk: MemDqblk, inodes: u64, ctx: ChargeCtx) -> ChargeOutcome {
    let newinodes = dqblk.dqb_curinodes.saturating_add(inodes);
    let mut result = Ok(());
    let mut warn = QuotaWarnType::NoWarn;
    if ctx.enforced && !is_fake(dqblk) {
        if dqblk.dqb_ihardlimit != 0 && newinodes > dqblk.dqb_ihardlimit && !ctx.ignore_hardlimit {
            warn = QuotaWarnType::IHardWarn;
            result = Err(VfsError::Edquot);
        } else if dqblk.dqb_isoftlimit != 0 && newinodes > dqblk.dqb_isoftlimit
            && dqblk.dqb_itime != 0 && grace_expired(dqblk.dqb_itime, ctx.now_sec)
            && !ctx.ignore_hardlimit {
            warn = QuotaWarnType::ISoftLongWarn;
            result = Err(VfsError::Edquot);
        } else if dqblk.dqb_isoftlimit != 0 && newinodes > dqblk.dqb_isoftlimit && dqblk.dqb_itime == 0 {
            warn = QuotaWarnType::ISoftWarn;
            dqblk.dqb_itime = grace_deadline(ctx.now_sec, ctx.info.dqi_igrace);
        }
    }
    if result.is_ok() { dqblk.dqb_curinodes = newinodes; }
    ChargeOutcome { dqblk, result, warn }
}

/// `info_bdq_free`: warning class raised by dropping `space` bytes. # C: O(1)
pub fn bdq_free_warn(dqblk: MemDqblk, space: u64, enforced: bool) -> QuotaWarnType {
    let tspace = dqblk.dqb_curspace.saturating_add(dqblk.dqb_rsvspace);
    if !enforced || is_fake(dqblk) || tspace <= dqblk.dqb_bsoftlimit { return QuotaWarnType::NoWarn; }
    let next = tspace.saturating_sub(space);
    if next <= dqblk.dqb_bsoftlimit { return QuotaWarnType::BSoftBelow; }
    if tspace >= dqblk.dqb_bhardlimit && next < dqblk.dqb_bhardlimit { return QuotaWarnType::BHardBelow; }
    QuotaWarnType::NoWarn
}

/// `info_idq_free`: warning class raised by dropping `inodes`. # C: O(1)
pub fn idq_free_warn(dqblk: MemDqblk, inodes: u64, enforced: bool) -> QuotaWarnType {
    if !enforced || is_fake(dqblk) || dqblk.dqb_curinodes <= dqblk.dqb_isoftlimit { return QuotaWarnType::NoWarn; }
    let newinodes = dqblk.dqb_curinodes.saturating_sub(inodes);
    if newinodes <= dqblk.dqb_isoftlimit { return QuotaWarnType::ISoftBelow; }
    if dqblk.dqb_curinodes >= dqblk.dqb_ihardlimit && newinodes < dqblk.dqb_ihardlimit { return QuotaWarnType::IHardBelow; }
    QuotaWarnType::NoWarn
}

/// `dquot_decr_space`: drop used space, clearing grace under the soft limit. # C: O(1)
pub fn decr_space(mut dqblk: MemDqblk, number: u64) -> MemDqblk {
    dqblk.dqb_curspace = dqblk.dqb_curspace.saturating_sub(number);
    clear_block_grace_under_soft(&mut dqblk);
    dqblk
}

/// `dquot_free_reserved_space`: drop reserved space. # C: O(1)
pub fn free_reserved_space(mut dqblk: MemDqblk, number: u64) -> MemDqblk {
    dqblk.dqb_rsvspace = dqblk.dqb_rsvspace.saturating_sub(number);
    clear_block_grace_under_soft(&mut dqblk);
    dqblk
}

/// `dquot_decr_inodes`: drop inode count, clearing grace under the soft limit. # C: O(1)
pub fn decr_inodes(mut dqblk: MemDqblk, number: u64) -> MemDqblk {
    dqblk.dqb_curinodes = dqblk.dqb_curinodes.saturating_sub(number);
    if dqblk.dqb_curinodes <= dqblk.dqb_isoftlimit { dqblk.dqb_itime = 0; }
    dqblk
}

/// `dquot_claim_space_nodirty`: convert reserved space into used space. # C: O(1)
pub fn claim_space(mut dqblk: MemDqblk, number: u64) -> MemDqblk {
    let number = number.min(dqblk.dqb_rsvspace);
    dqblk.dqb_rsvspace -= number;
    dqblk.dqb_curspace = dqblk.dqb_curspace.saturating_add(number);
    dqblk
}

/// `dquot_reclaim_space_nodirty`: convert used space back into reserved. # C: O(1)
pub fn reclaim_space(mut dqblk: MemDqblk, number: u64) -> MemDqblk {
    let number = number.min(dqblk.dqb_curspace);
    dqblk.dqb_curspace -= number;
    dqblk.dqb_rsvspace = dqblk.dqb_rsvspace.saturating_add(number);
    dqblk
}

/// `test_bit(DQ_FAKE_B)`: a record with no limits at all is never checked. # C: O(1)
pub const fn is_fake(dqblk: MemDqblk) -> bool {
    dqblk.dqb_bhardlimit == 0 && dqblk.dqb_bsoftlimit == 0
        && dqblk.dqb_ihardlimit == 0 && dqblk.dqb_isoftlimit == 0
        && dqblk.dqb_rtb_hardlimit == 0 && dqblk.dqb_rtb_softlimit == 0
}

fn clear_block_grace_under_soft(dqblk: &mut MemDqblk) {
    if dqblk.dqb_curspace.saturating_add(dqblk.dqb_rsvspace) <= dqblk.dqb_bsoftlimit { dqblk.dqb_btime = 0; }
}

fn grace_expired(timer: i64, now_sec: u64) -> bool {
    timer < 0 || now_sec >= timer as u64
}

fn grace_deadline(now_sec: u64, grace: u64) -> i64 {
    now_sec.saturating_add(grace).min(i64::MAX as u64) as i64
}

#[cfg(test)]
#[path = "charge/tests.rs"]
mod tests;
