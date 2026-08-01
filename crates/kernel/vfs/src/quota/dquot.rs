extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use sync::{Guard, Spinlock};

use crate::superblock::SuperBlock;
use crate::types::{KResult, VfsError};

use super::charge::{self, ChargeCtx, DQUOT_SPACE_WARN};
use super::ids::{QuotaId, QuotaType};
use super::limits::{DQB_INO_COUNT, DQB_INO_HARD, DQB_INO_SOFT, DQB_INO_TIMER, DQB_RTB_COUNT, DQB_RTB_HARD, DQB_RTB_SOFT, DQB_RTB_TIMER, DQB_SPACE, DQB_SPC_HARD, DQB_SPC_SOFT, DQB_SPC_TIMER, DQB_VFS_MASK, DquotLimits, MemDqblk, MemDqinfo};
use super::usage::DquotUsage;
use super::warn::QuotaWarnType;

pub(super) struct QuotaAccountingClass;
impl sync::LockClass for QuotaAccountingClass { fn rank() -> u16 { 33 } fn name() -> &'static str { "QuotaAccountingClass" } }

struct DquotLockClass;
impl sync::LockClass for DquotLockClass { fn rank() -> u16 { 34 } fn name() -> &'static str { "DquotLockClass" } }

struct DquotOwnerLockClass;
impl sync::LockClass for DquotOwnerLockClass { fn rank() -> u16 { 31 } fn name() -> &'static str { "DquotOwnerLockClass" } }

struct DquotSetLockClass;
impl sync::LockClass for DquotSetLockClass { fn rank() -> u16 { 34 } fn name() -> &'static str { "DquotSetLockClass" } }

static ACCOUNTING_LOCK: Spinlock<(), QuotaAccountingClass> = Spinlock::new(());

pub(super) fn lock_accounting() -> Guard<'static, (), QuotaAccountingClass> {
    ACCOUNTING_LOCK.lock()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DquotState {
    dqblk: MemDqblk,
    fake:  bool,
}

impl DquotState {
    const fn new(limits: DquotLimits) -> Self {
        let dqblk = MemDqblk::from_limits_usage(limits, DquotUsage::zero());
        Self { dqblk, fake: fake_dqblk(dqblk) }
    }
}

/// Reason a quota mutation refused, paired with the warning it raised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChargeResult {
    pub result: KResult<()>,
    pub warn:   QuotaWarnType,
}

/// One Linux `struct dquot`: identity plus canonical usage/limit counters. # C: O(1)
pub struct Dquot {
    id: QuotaId,
    owner: Spinlock<Weak<SuperBlock>, DquotOwnerLockClass>,
    st: Spinlock<DquotState, DquotLockClass>,
    refs: AtomicUsize,
    dirty: AtomicBool,
}

impl fmt::Debug for Dquot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dquot").field("id", &self.id).field("dqblk", &self.dqblk()).finish()
    }
}

/// Shared dquot reference. # C: O(1)
pub type DquotRef = Arc<Dquot>;

impl Dquot {
    /// Allocate a dquot with zero usage and unlimited limits. # C: O(1)
    pub fn new(id: QuotaId) -> DquotRef {
        Self::with_limits(id, DquotLimits::unlimited())
    }
    /// Allocate a dquot with zero usage and explicit limits. # C: O(1)
    pub fn with_limits(id: QuotaId, limits: DquotLimits) -> DquotRef {
        Arc::new(Self { id, owner: Spinlock::new(Weak::new()), st: Spinlock::new(DquotState::new(limits)), refs: AtomicUsize::new(0), dirty: AtomicBool::new(false) })
    }
    /// Dquot identity key. # C: O(1)
    pub fn id(&self) -> QuotaId { self.id }
    /// Owning superblock for Linux global `dqput`. # C: O(1)
    pub fn owner_super(&self) -> Option<Arc<SuperBlock>> { self.owner.lock().upgrade() }
    pub(super) fn bind_owner(&self, sb: &Arc<SuperBlock>) -> KResult<()> {
        let mut owner = self.owner.lock();
        if let Some(cur) = owner.upgrade() {
            if !Arc::ptr_eq(&cur, sb) { return Err(VfsError::Einval); }
            return Ok(());
        }
        *owner = Arc::downgrade(sb);
        Ok(())
    }
    /// Current charged usage snapshot. # C: O(1)
    pub fn usage(&self) -> DquotUsage { self.st.lock().dqblk.usage() }
    /// Current limit snapshot. # C: O(1)
    pub fn limits(&self) -> DquotLimits { self.st.lock().dqblk.limits() }
    /// Current Linux `mem_dqblk` snapshot. # C: O(1)
    pub fn dqblk(&self) -> MemDqblk { self.st.lock().dqblk }
    /// Linux `DQ_FAKE_B`: no hard/soft limits only usage. # C: O(1)
    pub fn is_fake(&self) -> bool { self.st.lock().fake }
    /// Acquire one Linux dquot reference. # C: O(1)
    pub(super) fn acquire_ref(&self) { self.refs.fetch_add(1, Ordering::AcqRel); }
    /// Release one Linux dquot reference; true when no active users remain. # C: O(1)
    pub(super) fn release_ref(&self) -> bool {
        let mut old = self.refs.load(Ordering::Acquire);
        loop {
            if old == 0 { return false; }
            match self.refs.compare_exchange_weak(old, old - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return old == 1,
                Err(next) => old = next,
            }
        }
    }
    /// Active Linux dquot reference count. # C: O(1)
    pub(super) fn active_refs(&self) -> usize { self.refs.load(Ordering::Acquire) }
    /// Mark this in-core dquot for backend writeback. # C: O(1)
    pub fn mark_dirty(&self) { self.dirty.store(true, Ordering::Release); }
    /// True when this dquot needs backend writeback. # C: O(1)
    pub fn is_dirty(&self) -> bool { self.dirty.load(Ordering::Acquire) }
    /// Clear the dirty bit after successful backend writeback. # C: O(1)
    pub fn clear_dirty(&self) { self.dirty.store(false, Ordering::Release); }
    /// Replace admission limits. Existing over-limit usage remains charged. # C: O(1)
    pub fn set_limits(&self, limits: DquotLimits) {
        let mut st = self.st.lock();
        st.dqblk.dqb_bhardlimit = limits.space.hard;
        st.dqblk.dqb_bsoftlimit = limits.space.soft;
        st.dqblk.dqb_ihardlimit = limits.inodes.hard;
        st.dqblk.dqb_isoftlimit = limits.inodes.soft;
        clear_grace_under_soft(&mut st.dqblk);
        st.fake = fake_dqblk(st.dqblk);
    }
    /// Replace usage from a filesystem quota-file load. # C: O(1)
    pub fn set_usage(&self, usage: DquotUsage) {
        let _acct = lock_accounting();
        self.set_usage_nogate(usage);
    }
    /// Replace the full Linux in-core quota record. # C: O(1)
    pub fn set_dqblk(&self, dqblk: MemDqblk) {
        let _acct = lock_accounting();
        *self.st.lock() = DquotState { dqblk, fake: fake_dqblk(dqblk) };
    }
    /// Apply Linux `dquot_set_dqblk` masked field updates. # C: O(1)
    pub fn set_dqblk_masked(&self, dqblk: MemDqblk, fieldmask: u32, info: MemDqinfo, now_sec: u64) -> KResult<()> {
        if fieldmask & !DQB_VFS_MASK != 0 { return Err(VfsError::Einval); }
        let _acct = lock_accounting();
        let mut st = self.st.lock();
        apply_masked_dqblk(&mut st.dqblk, dqblk, fieldmask, info, now_sec);
        st.fake = fake_dqblk(st.dqblk);
        Ok(())
    }
    /// Charge usage, failing with EDQUOT if hard/expired soft limits fail. # C: O(1)
    pub fn charge(&self, delta: DquotUsage) -> KResult<()> {
        let _acct = lock_accounting();
        self.charge_nogate(delta)
    }
    /// Charge usage without quota-limit enforcement. # C: O(1)
    pub fn charge_unchecked(&self, delta: DquotUsage) -> KResult<()> {
        let _acct = lock_accounting();
        self.charge_usage_nogate(delta)
    }
    /// Charge usage with quota-class grace settings. # C: O(1)
    pub fn charge_with_grace(&self, delta: DquotUsage, info: MemDqinfo, now_sec: u64) -> KResult<()> {
        self.charge_checked(delta, DQUOT_SPACE_WARN, grace_ctx(info, now_sec)).result
    }
    /// Charge usage through the full Linux limit ladder, reporting the warning
    /// class the attempt raised. # C: O(1)
    pub fn charge_checked(&self, delta: DquotUsage, flags: u32, ctx: ChargeCtx) -> ChargeResult {
        let _acct = lock_accounting();
        if delta.is_zero() { return ChargeResult { result: Ok(()), warn: QuotaWarnType::NoWarn }; }
        let mut st = self.st.lock();
        let (next, warn) = check_charge(st.dqblk, delta, flags, ctx);
        match next {
            Ok(dqblk) => { st.dqblk = dqblk; ChargeResult { result: Ok(()), warn } }
            Err(e) => ChargeResult { result: Err(e), warn },
        }
    }
    /// Release usage, reporting the below-limit warning class it raised. # C: O(1)
    pub fn release_checked(&self, delta: DquotUsage, enforced: bool) -> ChargeResult {
        let _acct = lock_accounting();
        if delta.is_zero() { return ChargeResult { result: Ok(()), warn: QuotaWarnType::NoWarn }; }
        let mut st = self.st.lock();
        let warn = worst_free_warn(st.dqblk, delta, enforced);
        let result = release_dqblk(&mut st.dqblk, delta);
        ChargeResult { result, warn }
    }
    /// `dquot_claim_space_nodirty`: reserved space becomes used space. # C: O(1)
    pub fn claim_reserved(&self, number: u64) {
        let _acct = lock_accounting();
        let mut st = self.st.lock();
        st.dqblk = charge::claim_space(st.dqblk, number);
    }
    /// `dquot_reclaim_space_nodirty`: used space becomes reserved space. # C: O(1)
    pub fn reclaim_reserved(&self, number: u64) {
        let _acct = lock_accounting();
        let mut st = self.st.lock();
        st.dqblk = charge::reclaim_space(st.dqblk, number);
    }
    /// Remove charged usage. Underflow means caller's inode accounting is stale. # C: O(1)
    pub fn release(&self, delta: DquotUsage) -> KResult<()> {
        let _acct = lock_accounting();
        self.release_nogate(delta)
    }
    pub(super) fn admits_nogate(&self, delta: DquotUsage) -> bool {
        let st = self.st.lock();
        hard_admits(st.dqblk, delta)
    }
    pub(super) fn admits_nogate_with_grace(&self, delta: DquotUsage, info: MemDqinfo, now_sec: u64) -> bool {
        let st = self.st.lock();
        check_charge(st.dqblk, delta, DQUOT_SPACE_WARN, grace_ctx(info, now_sec)).0.is_ok()
    }
    pub(super) fn can_release_nogate(&self, delta: DquotUsage) -> bool {
        self.st.lock().dqblk.usage().checked_sub(delta).is_some()
    }
    pub(super) fn charge_nogate(&self, delta: DquotUsage) -> KResult<()> {
        if delta.is_zero() { return Ok(()); }
        let mut st = self.st.lock();
        let next = st.dqblk.usage().checked_add(delta).ok_or(VfsError::Edquot)?;
        if !hard_admits(st.dqblk, delta) { return Err(VfsError::Edquot); }
        st.dqblk.dqb_curspace = next.space;
        st.dqblk.dqb_rsvspace = next.reserved_space;
        st.dqblk.dqb_curinodes = next.inodes;
        Ok(())
    }
    pub(super) fn charge_usage_nogate(&self, delta: DquotUsage) -> KResult<()> {
        if delta.is_zero() { return Ok(()); }
        let mut st = self.st.lock();
        let next = st.dqblk.usage().checked_add(delta).ok_or(VfsError::Edquot)?;
        st.dqblk.dqb_curspace = next.space;
        st.dqblk.dqb_rsvspace = next.reserved_space;
        st.dqblk.dqb_curinodes = next.inodes;
        Ok(())
    }
    pub(super) fn charge_nogate_with_grace(&self, delta: DquotUsage, info: MemDqinfo, now_sec: u64) -> KResult<()> {
        if delta.is_zero() { return Ok(()); }
        let mut st = self.st.lock();
        let (next, _warn) = check_charge(st.dqblk, delta, DQUOT_SPACE_WARN, grace_ctx(info, now_sec));
        st.dqblk = next?;
        Ok(())
    }
    pub(super) fn release_nogate(&self, delta: DquotUsage) -> KResult<()> {
        if delta.is_zero() { return Ok(()); }
        let mut st = self.st.lock();
        release_dqblk(&mut st.dqblk, delta)
    }
    pub(super) fn set_usage_nogate(&self, usage: DquotUsage) {
        let mut st = self.st.lock();
        st.dqblk.dqb_curspace = usage.space;
        st.dqblk.dqb_rsvspace = usage.reserved_space;
        st.dqblk.dqb_curinodes = usage.inodes;
        clear_grace_under_soft(&mut st.dqblk);
    }
}

fn hard_admits(dq: MemDqblk, delta: DquotUsage) -> bool {
    let tspace = dq.dqb_curspace.saturating_add(dq.dqb_rsvspace)
        .saturating_add(delta.space).saturating_add(delta.reserved_space);
    let space_ok = dq.dqb_bhardlimit == 0 || tspace <= dq.dqb_bhardlimit;
    let inode_ok = dq.dqb_ihardlimit == 0
        || dq.dqb_curinodes.saturating_add(delta.inodes) <= dq.dqb_ihardlimit;
    space_ok && inode_ok
}

const fn fake_dqblk(dq: MemDqblk) -> bool { charge::is_fake(dq) }

/// Run the block ladder then the inode ladder over one combined delta,
/// unwinding the block charge when the inode ladder refuses. # C: O(1)
fn check_charge(dq: MemDqblk, delta: DquotUsage, flags: u32, ctx: ChargeCtx) -> (KResult<MemDqblk>, QuotaWarnType) {
    let space = charge::add_space(dq, delta.space, delta.reserved_space, flags, ctx);
    if let Err(e) = space.result { return (Err(e), space.warn); }
    let inodes = charge::add_inodes(space.dqblk, delta.inodes, ctx);
    let warn = if space.warn.is_none() { inodes.warn } else { space.warn };
    // The block counters were already applied to `space.dqblk`; refusing the
    // inode half discards that record entirely, so no partial charge is left.
    match inodes.result {
        Err(e) => (Err(e), warn),
        Ok(()) => (Ok(inodes.dqblk), warn),
    }
}

fn apply_masked_dqblk(cur: &mut MemDqblk, new: MemDqblk, fieldmask: u32, info: MemDqinfo, now_sec: u64) {
    let mut check_blim = false;
    let mut check_ilim = false;
    if fieldmask & DQB_SPACE != 0 {
        cur.dqb_curspace = new.dqb_curspace.wrapping_sub(cur.dqb_rsvspace);
        check_blim = true;
    }
    if fieldmask & DQB_SPC_SOFT != 0 { cur.dqb_bsoftlimit = new.dqb_bsoftlimit; }
    if fieldmask & DQB_SPC_HARD != 0 { cur.dqb_bhardlimit = new.dqb_bhardlimit; }
    if fieldmask & (DQB_SPC_SOFT | DQB_SPC_HARD) != 0 { check_blim = true; }
    if fieldmask & DQB_INO_COUNT != 0 {
        cur.dqb_curinodes = new.dqb_curinodes;
        check_ilim = true;
    }
    if fieldmask & DQB_INO_SOFT != 0 { cur.dqb_isoftlimit = new.dqb_isoftlimit; }
    if fieldmask & DQB_INO_HARD != 0 { cur.dqb_ihardlimit = new.dqb_ihardlimit; }
    if fieldmask & (DQB_INO_SOFT | DQB_INO_HARD) != 0 { check_ilim = true; }
    if fieldmask & DQB_RTB_COUNT != 0 { cur.dqb_rtbcount = new.dqb_rtbcount; }
    if fieldmask & DQB_RTB_SOFT != 0 { cur.dqb_rtb_softlimit = new.dqb_rtb_softlimit; }
    if fieldmask & DQB_RTB_HARD != 0 { cur.dqb_rtb_hardlimit = new.dqb_rtb_hardlimit; }
    if fieldmask & DQB_RTB_TIMER != 0 { cur.dqb_rtbtimer = new.dqb_rtbtimer; }
    if fieldmask & DQB_SPC_TIMER != 0 {
        cur.dqb_btime = new.dqb_btime;
        check_blim = true;
    }
    if fieldmask & DQB_INO_TIMER != 0 {
        cur.dqb_itime = new.dqb_itime;
        check_ilim = true;
    }
    if check_blim {
        if cur.dqb_bsoftlimit == 0 || cur.dqb_curspace.saturating_add(cur.dqb_rsvspace) <= cur.dqb_bsoftlimit {
            cur.dqb_btime = 0;
        } else if fieldmask & DQB_SPC_TIMER == 0 {
            cur.dqb_btime = now_sec.saturating_add(info.dqi_bgrace).min(i64::MAX as u64) as i64;
        }
    }
    if check_ilim {
        if cur.dqb_isoftlimit == 0 || cur.dqb_curinodes <= cur.dqb_isoftlimit {
            cur.dqb_itime = 0;
        } else if fieldmask & DQB_INO_TIMER == 0 {
            cur.dqb_itime = now_sec.saturating_add(info.dqi_igrace).min(i64::MAX as u64) as i64;
        }
    }
    cur.dqb_valid = fieldmask;
}

fn grace_ctx(info: MemDqinfo, now_sec: u64) -> ChargeCtx {
    ChargeCtx { info, now_sec, enforced: true, ignore_hardlimit: false }
}

/// Apply a release delta, refusing an underflow that would mean the caller's
/// inode accounting has already drifted from the charged totals. # C: O(1)
fn release_dqblk(dqblk: &mut MemDqblk, delta: DquotUsage) -> KResult<()> {
    dqblk.usage().checked_sub(delta).ok_or(VfsError::Einval)?;
    *dqblk = charge::decr_space(*dqblk, delta.space);
    *dqblk = charge::free_reserved_space(*dqblk, delta.reserved_space);
    *dqblk = charge::decr_inodes(*dqblk, delta.inodes);
    Ok(())
}

/// Highest-severity below-limit warning raised by one combined release. # C: O(1)
fn worst_free_warn(dqblk: MemDqblk, delta: DquotUsage, enforced: bool) -> QuotaWarnType {
    let space = charge::bdq_free_warn(dqblk, delta.space.saturating_add(delta.reserved_space), enforced);
    if !space.is_none() { return space; }
    charge::idq_free_warn(dqblk, delta.inodes, enforced)
}

fn clear_grace_under_soft(dq: &mut MemDqblk) {
    if dq.dqb_curspace.saturating_add(dq.dqb_rsvspace) <= dq.dqb_bsoftlimit { dq.dqb_btime = 0; }
    if dq.dqb_curinodes <= dq.dqb_isoftlimit { dq.dqb_itime = 0; }
}

/// Per-filesystem dquot table keyed by [`QuotaId`]. Filesystems store this in
/// their own superblock-private state; no parallel file-specific side channel.
pub struct DquotSet {
    map: Spinlock<BTreeMap<QuotaId, DquotRef>, DquotSetLockClass>,
}

impl DquotSet {
    /// Empty dquot table. # C: O(1)
    pub fn new() -> Self { Self { map: Spinlock::new(BTreeMap::new()) } }
    /// Lookup an existing dquot. # C: O(log N)
    pub fn lookup(&self, id: QuotaId) -> Option<DquotRef> {
        self.map.lock().get(&id).cloned()
    }
    /// Lookup or create the canonical dquot for `id`. # C: O(log N)
    pub fn get_or_create(&self, id: QuotaId) -> DquotRef {
        self.get_or_insert_with(id, Dquot::new)
    }
    /// Lookup or create using the filesystem hook allocator. # C: O(log N)
    pub fn get_or_insert_with(&self, id: QuotaId, make: impl FnOnce(QuotaId) -> DquotRef) -> DquotRef {
        let mut map = self.map.lock();
        if let Some(dq) = map.get(&id) { return dq.clone(); }
        let dq = make(id);
        map.insert(id, dq.clone());
        dq
    }
    /// Install limits on the canonical dquot for `id`. # C: O(log N)
    pub fn set_limits(&self, id: QuotaId, limits: DquotLimits) -> DquotRef {
        let dq = self.get_or_create(id);
        dq.set_limits(limits);
        dq
    }
    /// Charge the canonical dquot for `id`. # C: O(log N)
    pub fn charge(&self, id: QuotaId, delta: DquotUsage) -> KResult<DquotRef> {
        let dq = self.get_or_create(id);
        dq.charge(delta)?;
        Ok(dq)
    }
    /// Release usage from the canonical dquot for `id`. # C: O(log N)
    pub fn release(&self, id: QuotaId, delta: DquotUsage) -> KResult<()> {
        let dq = self.get_or_create(id);
        dq.release(delta)
    }
    /// True when this exact dquot is still the canonical cache entry. # C: O(log N)
    pub fn contains_exact(&self, dq: &DquotRef) -> bool {
        let map = self.map.lock();
        let Some(cur) = map.get(&dq.id) else { return false; };
        Arc::ptr_eq(cur, dq)
    }
    /// True when every cached dquot in this class has no active Linux users. # C: O(N)
    pub fn kind_quiesced(&self, kind: QuotaType) -> bool {
        self.map.lock().iter().all(|(id, dq)| id.kind != kind || dq.active_refs() == 0)
    }
    /// Remove this exact dquot after successful final release. # C: O(log N)
    pub fn remove_exact(&self, dq: &DquotRef) {
        let mut map = self.map.lock();
        if map.get(&dq.id).is_some_and(|cur| Arc::ptr_eq(cur, dq)) { map.remove(&dq.id); }
    }
    /// Remove this exact dquot iff no Linux users remain. # C: O(log N)
    pub fn remove_inactive_exact(&self, dq: &DquotRef) -> bool {
        let mut map = self.map.lock();
        let Some(cur) = map.get(&dq.id) else { return false; };
        if !Arc::ptr_eq(cur, dq) || dq.active_refs() != 0 { return false; }
        map.remove(&dq.id);
        true
    }
    /// Reinstall an inactive dquot whose final backend drop failed. # C: O(log N)
    pub(super) fn reinsert_inactive(&self, dq: DquotRef) {
        if dq.active_refs() != 0 { return; }
        let mut map = self.map.lock();
        map.entry(dq.id).or_insert(dq);
    }
    /// Snapshot every dquot for one quota class. # C: O(N)
    pub fn by_kind(&self, kind: QuotaType) -> Vec<DquotRef> {
        self.map.lock().iter().filter_map(|(id, dq)| if id.kind == kind { Some(dq.clone()) } else { None }).collect()
    }
    /// True when any cached dquot remains for one quota class. # C: O(N)
    pub fn has_kind(&self, kind: QuotaType) -> bool {
        self.map.lock().keys().any(|id| id.kind == kind)
    }
    /// True when no dquots remain cached. # C: O(1)
    pub fn is_empty(&self) -> bool { self.map.lock().is_empty() }
    /// Lowest resident id for `kind` at or after `start`. # C: O(N)
    pub fn next_id(&self, kind: QuotaType, start: u32) -> Option<u32> {
        self.map.lock().keys().filter(|id| id.kind == kind && id.id >= start).map(|id| id.id).next()
    }
    /// Drop every cached dquot for one quota class. # C: O(N)
    pub fn remove_kind(&self, kind: QuotaType) {
        self.map.lock().retain(|id, _| id.kind != kind);
    }
}

impl Default for DquotSet {
    fn default() -> Self { Self::new() }
}
