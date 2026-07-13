use crate::types::{KResult, VfsError};

use super::dquot::{Dquot, lock_accounting};
use super::ids::{QuotaType, MAXQUOTAS};
use super::limits::MemDqinfo;
use super::usage::DquotUsage;

/// One old/new dquot pair in Linux `__dquot_transfer` slot form. # C: O(1)
#[derive(Clone, Copy, Debug)]
pub struct DquotTransferSlot<'a> {
    pub old: Option<&'a Dquot>,
    pub new: Option<&'a Dquot>,
}

impl<'a> DquotTransferSlot<'a> {
    /// Empty transfer slot. # C: O(1)
    pub const fn empty() -> Self { Self { old: None, new: None } }
    /// Transfer usage from `old` to `new`. Both dquots must have the same class. # C: O(1)
    pub const fn new(old: &'a Dquot, new: &'a Dquot) -> Self { Self { old: Some(old), new: Some(new) } }
    /// Project-quota transfer slot for `FS_IOC_FSSETXATTR` project-id change. # C: O(1)
    pub const fn project(old: &'a Dquot, new: &'a Dquot) -> Self { Self::new(old, new) }
    fn kind(self) -> KResult<Option<QuotaType>> {
        match (self.old, self.new) {
            (None, None) => Ok(None),
            (Some(dq), None) | (None, Some(dq)) => Ok(Some(dq.id().kind)),
            (Some(old), Some(new)) => {
                if old.id().kind != new.id().kind { return Err(VfsError::Einval); }
                Ok(Some(old.id().kind))
            }
        }
    }
    pub(super) fn unchanged(self) -> bool {
        matches!((self.old, self.new), (Some(old), Some(new)) if old.id() == new.id())
    }
}

/// Linux-shaped `__dquot_transfer`: precheck destination limits, then move one
/// inode's charged usage from old dquot slots to new dquot slots atomically.
/// # C: O(slots)
pub fn __dquot_transfer(usage: DquotUsage, slots: &[DquotTransferSlot<'_>]) -> KResult<()> {
    if usage.is_zero() { return Ok(()); }
    let _acct = lock_accounting();
    let mut seen = [false; MAXQUOTAS];
    for slot in slots {
        let Some(kind) = slot.kind()? else { continue; };
        let idx = kind_index(kind);
        if seen[idx] { return Err(VfsError::Einval); }
        seen[idx] = true;
        if slot.unchanged() { continue; }
        if let Some(old) = slot.old {
            if !old.can_release_nogate(usage) { return Err(VfsError::Einval); }
        }
        if let Some(new) = slot.new {
            if !new.admits_nogate(usage) { return Err(VfsError::Edquot); }
        }
    }
    let mut applied = 0usize;
    for slot in slots {
        if slot.unchanged() { continue; }
        if let Err(e) = apply_slot(*slot, usage) {
            if let Err(rb) = rollback(slots, applied, usage) { return Err(rb); }
            return Err(e);
        }
        applied += 1;
    }
    Ok(())
}

/// Compatibility wrapper for the local public name. # C: O(slots)
pub fn dquot_transfer(usage: DquotUsage, slots: &[DquotTransferSlot<'_>]) -> KResult<()> {
    __dquot_transfer(usage, slots)
}

/// Grace-aware transfer used by inode owner/project changes. # C: O(slots)
pub fn dquot_transfer_with_grace(usage: DquotUsage, slots: &[DquotTransferSlot<'_>], info: [MemDqinfo; MAXQUOTAS], now_sec: u64) -> KResult<()> {
    dquot_transfer_with_grace_mask(usage, slots, info, now_sec, [true; MAXQUOTAS])
}

/// Grace-aware transfer with per-class limit enforcement state. # C: O(slots)
pub fn dquot_transfer_with_grace_mask(usage: DquotUsage, slots: &[DquotTransferSlot<'_>], info: [MemDqinfo; MAXQUOTAS], now_sec: u64, enforce: [bool; MAXQUOTAS]) -> KResult<()> {
    if usage.is_zero() { return Ok(()); }
    let _acct = lock_accounting();
    let mut seen = [false; MAXQUOTAS];
    for slot in slots {
        let Some(kind) = slot.kind()? else { continue; };
        let idx = kind_index(kind);
        if seen[idx] { return Err(VfsError::Einval); }
        seen[idx] = true;
        if slot.unchanged() { continue; }
        if let Some(old) = slot.old {
            if !old.can_release_nogate(usage) { return Err(VfsError::Einval); }
        }
        if enforce[idx] {
            if let Some(new) = slot.new {
                if !new.admits_nogate_with_grace(usage, info[idx], now_sec) { return Err(VfsError::Edquot); }
            }
        }
    }
    let mut applied = 0usize;
    for slot in slots {
        if slot.unchanged() { continue; }
        if let Err(e) = apply_slot_with_grace(*slot, usage, info, now_sec, enforce) {
            if let Err(rb) = rollback(slots, applied, usage) { return Err(rb); }
            return Err(e);
        }
        applied += 1;
    }
    Ok(())
}

fn apply_slot(slot: DquotTransferSlot<'_>, usage: DquotUsage) -> KResult<()> {
    if let Some(old) = slot.old { old.release_nogate(usage)?; }
    if let Some(new) = slot.new { new.charge_nogate(usage)?; }
    Ok(())
}

fn apply_slot_with_grace(slot: DquotTransferSlot<'_>, usage: DquotUsage, info: [MemDqinfo; MAXQUOTAS], now_sec: u64, enforce: [bool; MAXQUOTAS]) -> KResult<()> {
    if let Some(old) = slot.old { old.release_nogate(usage)?; }
    if let Some(new) = slot.new {
        let idx = kind_index(new.id().kind);
        if enforce[idx] { new.charge_nogate_with_grace(usage, info[idx], now_sec)?; } else { new.charge_usage_nogate(usage)?; }
    }
    Ok(())
}

fn rollback(slots: &[DquotTransferSlot<'_>], applied: usize, usage: DquotUsage) -> KResult<()> {
    for slot in slots.iter().take(applied).rev() {
        if slot.unchanged() { continue; }
        if let Some(new) = slot.new { new.release_nogate(usage)?; }
        if let Some(old) = slot.old { old.charge_usage_nogate(usage)?; }
    }
    Ok(())
}

pub(super) fn rollback_transferred_usage(slots: &[DquotTransferSlot<'_>], usage: DquotUsage) -> KResult<()> {
    rollback(slots, slots.len(), usage)
}

fn kind_index(kind: QuotaType) -> usize {
    match kind {
        QuotaType::User    => 0,
        QuotaType::Group   => 1,
        QuotaType::Project => 2,
    }
}
