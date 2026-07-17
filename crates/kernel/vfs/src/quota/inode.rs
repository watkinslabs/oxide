extern crate alloc;

use alloc::sync::Arc;
use sync::Spinlock;

use crate::inode::Inode;
use crate::superblock::SuperBlock;
use crate::types::{KResult, VfsError};

use super::dquot::{Dquot, DquotRef};
use super::ids::{Kqid, QuotaType, MAXQUOTAS};
use super::limits::MemDqinfo;
use super::transfer::{DquotTransferSlot, dquot_transfer_with_grace_mask, rollback_transferred_usage};
use super::usage::DquotUsage;

struct InodeDquotLockClass;
impl sync::LockClass for InodeDquotLockClass { fn rank() -> u16 { 32 } }

/// Inode-attached dquot slots (`inode.i_dquot[MAXQUOTAS]`). # C: O(1)
pub struct InodeDquots {
    slots: Spinlock<[Option<DquotRef>; MAXQUOTAS], InodeDquotLockClass>,
}

impl InodeDquots {
    /// Empty inode quota attachment table. # C: O(1)
    pub fn new() -> Self { Self { slots: Spinlock::new(core::array::from_fn(|_| None)) } }
    /// Snapshot one attached dquot slot. # C: O(1)
    pub fn get(&self, kind: QuotaType) -> Option<DquotRef> { self.slots.lock()[kind.slot()].clone() }
    /// Replace one attached dquot slot. # C: O(1)
    pub fn set(&self, kind: QuotaType, dq: Option<DquotRef>) { self.slots.lock()[kind.slot()] = dq; }
    /// Take one attached dquot slot. # C: O(1)
    pub fn take(&self, kind: QuotaType) -> Option<DquotRef> { self.slots.lock()[kind.slot()].take() }
    /// Snapshot all attached dquot slots. # C: O(1)
    pub fn snapshot(&self) -> [Option<DquotRef>; MAXQUOTAS] { self.slots.lock().clone() }
    /// Replace all attached dquot slots after successful transfer. # C: O(1)
    pub fn replace(&self, slots: [Option<DquotRef>; MAXQUOTAS]) { *self.slots.lock() = slots; }
}

impl Default for InodeDquots {
    fn default() -> Self { Self::new() }
}

/// `dqget` against an inode's owning superblock. # C: O(log N)+FS
pub fn dqget(inode: &Inode, qid: Kqid) -> KResult<DquotRef> {
    inode.i_sb().ok_or(VfsError::Einval)?.s_dquot.dqget(qid)
}

/// `dqput`: dropping the counted reference releases the in-core dquot. # C: O(log N)+FS
pub fn dqput(dq: DquotRef) {
    if let Some(sb) = dq.owner_super() { sb.s_dquot.dqput(dq); }
}

/// Snapshot one inode-attached dquot. # C: O(1)
pub fn inode_dquot(inode: &Inode, kind: QuotaType) -> Option<DquotRef> {
    inode.i_dquot.get(kind)
}

/// Drop one inode-attached dquot slot during quota-off/shutdown. # C: O(1)
pub fn dquot_drop_type(inode: &Inode, kind: QuotaType) {
    if let Some(dq) = inode.i_dquot.take(kind) { dqput(dq); }
}

/// Drop every inode-attached dquot slot during final quota teardown. # C: O(MAXQUOTAS)
pub fn dquot_drop(inode: &Inode) {
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] { dquot_drop_type(inode, kind); }
}

/// Attach active user/group/project dquots to an inode. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_initialize(inode: &Inode) -> KResult<()> {
    let sb = inode.i_sb().ok_or(VfsError::Einval)?;
    let mut initialized: [Option<Arc<dyn super::ops::DquotOperations>>; MAXQUOTAS] = core::array::from_fn(|_| None);
    for ops in sb.s_dquot.enabled_operations().into_iter().flatten() {
        if initialized.iter().flatten().any(|old| Arc::ptr_eq(old, &ops)) { continue; }
        ops.initialize(inode)?;
        for slot in &mut initialized {
            if slot.is_none() { *slot = Some(ops); break; }
        }
    }
    let old = inode.i_dquot.snapshot();
    let mut new = old.clone();
    let mut acquired: [Option<DquotRef>; MAXQUOTAS] = core::array::from_fn(|_| None);
    if sb.s_dquot.is_enabled(QuotaType::User) {
        attach_initialized_slot(&sb, &old, &mut new, &mut acquired, QuotaType::User, Kqid::user(inode.uid().unwrap_or(0)))?;
    }
    if sb.s_dquot.is_enabled(QuotaType::Group) {
        attach_initialized_slot(&sb, &old, &mut new, &mut acquired, QuotaType::Group, Kqid::group(inode.gid().unwrap_or(0)))?;
    }
    if sb.s_dquot.is_enabled(QuotaType::Project) {
        attach_initialized_slot(&sb, &old, &mut new, &mut acquired, QuotaType::Project, Kqid::project(inode.projid()))?;
    }
    inode.i_dquot.replace(new);
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        let idx = kind.slot();
        if !same_slot(&old[idx], &inode.i_dquot.get(kind)) {
            if let Some(dq) = old[idx].clone() { sb.s_dquot.dqput(dq); }
        }
    }
    Ok(())
}

fn attach_initialized_slot(
    sb: &SuperBlock,
    old: &[Option<DquotRef>; MAXQUOTAS],
    new: &mut [Option<DquotRef>; MAXQUOTAS],
    acquired: &mut [Option<DquotRef>; MAXQUOTAS],
    kind: QuotaType,
    qid: Kqid,
) -> KResult<()> {
    let idx = kind.slot();
    if old[idx].as_ref().is_some_and(|dq| dq.id() == qid) { return Ok(()); }
    match sb.s_dquot.dqget(qid) {
        Ok(dq) => {
            acquired[idx] = Some(dq.clone());
            new[idx] = Some(dq);
            Ok(())
        }
        Err(e) => {
            for dq in acquired.iter_mut().filter_map(Option::take) { sb.s_dquot.dqput(dq); }
            Err(e)
        }
    }
}

/// New quota ids for inode-owner/project transfer. `None` leaves a class alone.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DquotTransferIds {
    pub uid:    Option<u32>,
    pub gid:    Option<u32>,
    pub projid: Option<u32>,
}

/// Linux-shaped inode transfer wrapper around `__dquot_transfer`. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_transfer_inode(inode: &Inode, usage: DquotUsage, ids: DquotTransferIds) -> KResult<()> {
    // Pseudo and hosted synthetic inodes have no owning superblock and
    // therefore no quota domain to transfer between. Linux's quota hooks are
    // skipped for such inodes; returning success preserves the setattr owner
    // mutation instead of manufacturing EINVAL from a missing i_sb.
    if inode.i_sb().is_none() { return Ok(()); }
    dquot_initialize(inode)?;
    let sb = inode.i_sb().ok_or(VfsError::Einval)?;
    let old = inode.i_dquot.snapshot();
    let mut new = old.clone();
    let mut acquired: [Option<DquotRef>; MAXQUOTAS] = core::array::from_fn(|_| None);
    if let Some(uid) = ids.uid {
        acquire_transfer_slot(&sb, &old, &mut new, &mut acquired, QuotaType::User, Kqid::user(uid))?;
    }
    if let Some(gid) = ids.gid {
        acquire_transfer_slot(&sb, &old, &mut new, &mut acquired, QuotaType::Group, Kqid::group(gid))?;
    }
    if let Some(projid) = ids.projid {
        acquire_transfer_slot(&sb, &old, &mut new, &mut acquired, QuotaType::Project, Kqid::project(projid))?;
    }
    let slots = [
        slot_ref(&old, &new, QuotaType::User),
        slot_ref(&old, &new, QuotaType::Group),
        slot_ref(&old, &new, QuotaType::Project),
    ];
    if let Err(e) = dquot_transfer_with_grace_mask(usage, &slots, grace_info(&sb), quota_now_sec(), enforce_mask(&sb)) {
        for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
            let idx = kind.slot();
            if !same_slot(&old[idx], &new[idx]) {
                if let Some(dq) = new[idx].clone() { sb.s_dquot.dqput(dq); }
            }
        }
        return Err(e);
    }
    for slot in &slots {
        if slot.unchanged() { continue; }
        if let Err(e) = dirty_transfer_slot(&sb, *slot) {
            let rollback = rollback_transferred_usage(&slots, usage).and_then(|_| dirty_transfer_slots(&sb, &slots));
            for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
                let idx = kind.slot();
                if !same_slot(&old[idx], &new[idx]) {
                    if let Some(dq) = new[idx].clone() { sb.s_dquot.dqput(dq); }
                }
            }
            if let Err(rb) = rollback { return Err(rb); }
            return Err(e);
        }
    }
    for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
        let idx = kind.slot();
        if !same_slot(&old[idx], &new[idx]) {
            if let Some(dq) = old[idx].clone() { sb.s_dquot.dqput(dq); }
        }
    }
    inode.i_dquot.replace(new);
    Ok(())
}

fn acquire_transfer_slot(
    sb: &SuperBlock,
    old: &[Option<DquotRef>; MAXQUOTAS],
    new: &mut [Option<DquotRef>; MAXQUOTAS],
    acquired: &mut [Option<DquotRef>; MAXQUOTAS],
    kind: QuotaType,
    qid: Kqid,
) -> KResult<()> {
    if !sb.s_dquot.is_enabled(kind) { return Ok(()); }
    let idx = kind.slot();
    if old[idx].as_ref().is_some_and(|dq| dq.id() == qid) { return Ok(()); }
    match sb.s_dquot.dqget(qid) {
        Ok(dq) => {
            acquired[idx] = Some(dq.clone());
            new[idx] = Some(dq);
            Ok(())
        }
        Err(e) => {
            for dq in acquired.iter_mut().filter_map(Option::take) { sb.s_dquot.dqput(dq); }
            Err(e)
        }
    }
}

fn dirty_transfer_slot(sb: &SuperBlock, slot: DquotTransferSlot<'_>) -> KResult<()> {
    if let Some(dq) = slot.old { mark_dirty(sb, dq)?; }
    if let Some(dq) = slot.new { mark_dirty(sb, dq)?; }
    Ok(())
}

fn dirty_transfer_slots(sb: &SuperBlock, slots: &[DquotTransferSlot<'_>]) -> KResult<()> {
    for slot in slots {
        if slot.unchanged() { continue; }
        dirty_transfer_slot(sb, *slot)?;
    }
    Ok(())
}

/// Transfer quota charges for a chown uid/gid change. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_transfer_owner(inode: &Inode, uid: u32, gid: u32) -> KResult<()> {
    let usage = inode_quota_usage(inode);
    dquot_transfer_inode(inode, usage, DquotTransferIds { uid: Some(uid), gid: Some(gid), projid: None })
}

/// Charge a new inode to the active quota classes on `sb`. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_alloc_inode(sb: &SuperBlock, uid: u32, gid: u32, projid: u32, usage: DquotUsage) -> KResult<()> {
    dquot_charge_usage(sb, uid, gid, projid, usage)
}

/// Charge arbitrary inode-owned usage to active quota classes on `sb`. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_charge_usage(sb: &SuperBlock, uid: u32, gid: u32, projid: u32, usage: DquotUsage) -> KResult<()> {
    let ids = [Kqid::user(uid), Kqid::group(gid), Kqid::project(projid)];
    let mut snap: [Option<(DquotRef, DquotUsage)>; MAXQUOTAS] = core::array::from_fn(|_| None);
    for qid in ids {
        if !sb.s_dquot.is_enabled(qid.kind) { continue; }
        let dq = sb.s_dquot.dqget(qid)?;
        let before = dq.usage();
        let info = sb.s_dquot.info(qid.kind);
        let charge = if sb.s_dquot.is_enforced(qid.kind) {
            dq.charge_with_grace(usage, info, quota_now_sec())
        } else {
            dq.charge_unchecked(usage)
        };
        if let Err(e) = charge {
            let rb = restore_snapshots(sb, &snap);
            dqput_snapshots(sb, &snap);
            sb.s_dquot.dqput(dq);
            if let Err(rb) = rb { return Err(rb); }
            return Err(e);
        }
        if let Err(e) = mark_dirty(sb, dq.as_ref()) {
            snap[qid.slot()] = Some((dq, before));
            let rb = restore_snapshots(sb, &snap);
            dqput_snapshots(sb, &snap);
            if let Err(rb) = rb { return Err(rb); }
            return Err(e);
        }
        snap[qid.slot()] = Some((dq, before));
    }
    dqput_snapshots(sb, &snap);
    Ok(())
}

/// Release a removed inode from the active quota classes on `sb`. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_free_inode(sb: &SuperBlock, uid: u32, gid: u32, projid: u32, usage: DquotUsage) -> KResult<()> {
    dquot_release_usage(sb, uid, gid, projid, usage)
}

/// Release arbitrary inode-owned usage from active quota classes on `sb`. # C: O(MAXQUOTAS log N)+FS
pub fn dquot_release_usage(sb: &SuperBlock, uid: u32, gid: u32, projid: u32, usage: DquotUsage) -> KResult<()> {
    let mut snap: [Option<(DquotRef, DquotUsage)>; MAXQUOTAS] = core::array::from_fn(|_| None);
    for qid in [Kqid::user(uid), Kqid::group(gid), Kqid::project(projid)] {
        if !sb.s_dquot.is_enabled(qid.kind) { continue; }
        let dq = sb.s_dquot.dqget(qid)?;
        let before = dq.usage();
        if let Err(e) = dq.release(usage) {
            let rb = restore_snapshots(sb, &snap);
            dqput_snapshots(sb, &snap);
            sb.s_dquot.dqput(dq);
            if let Err(rb) = rb { return Err(rb); }
            return Err(e);
        }
        if let Err(e) = mark_dirty(sb, dq.as_ref()) {
            snap[qid.slot()] = Some((dq, before));
            let rb = restore_snapshots(sb, &snap);
            dqput_snapshots(sb, &snap);
            if let Err(rb) = rb { return Err(rb); }
            return Err(e);
        }
        snap[qid.slot()] = Some((dq, before));
    }
    dqput_snapshots(sb, &snap);
    Ok(())
}

fn restore_snapshots(sb: &SuperBlock, snap: &[Option<(DquotRef, DquotUsage)>; MAXQUOTAS]) -> KResult<()> {
    for (dq, usage) in snap.iter().filter_map(|s| s.as_ref()) { dq.set_usage(*usage); }
    let mut first = Ok(());
    for (dq, _) in snap.iter().filter_map(|s| s.as_ref()) {
        if let Err(e) = mark_dirty(sb, dq.as_ref()) {
            if first.is_ok() { first = Err(e); }
        }
    }
    first
}

fn dqput_snapshots(sb: &SuperBlock, snap: &[Option<(DquotRef, DquotUsage)>; MAXQUOTAS]) {
    for (dq, _) in snap.iter().filter_map(|s| s.as_ref()) { sb.s_dquot.dqput(dq.clone()); }
}

fn inode_quota_usage(inode: &Inode) -> DquotUsage {
    DquotUsage { space: inode.blocks().saturating_mul(512), reserved_space: 0, inodes: 1 }
}

fn mark_dirty(sb: &SuperBlock, dq: &Dquot) -> KResult<()> {
    dq.mark_dirty();
    if let Some(ops) = sb.s_dquot.operations(dq.id().kind) { ops.mark_dirty(dq)?; }
    Ok(())
}

fn grace_info(sb: &SuperBlock) -> [MemDqinfo; MAXQUOTAS] {
    [sb.s_dquot.info(QuotaType::User), sb.s_dquot.info(QuotaType::Group), sb.s_dquot.info(QuotaType::Project)]
}

fn enforce_mask(sb: &SuperBlock) -> [bool; MAXQUOTAS] {
    [sb.s_dquot.is_enforced(QuotaType::User), sb.s_dquot.is_enforced(QuotaType::Group), sb.s_dquot.is_enforced(QuotaType::Project)]
}

fn quota_now_sec() -> u64 {
    crate::inode_times::realtime_now_ns() / crate::superblock::NSEC_PER_SEC
}

fn slot_ref<'a>(old: &'a [Option<Arc<Dquot>>; MAXQUOTAS],
                new: &'a [Option<Arc<Dquot>>; MAXQUOTAS],
                kind: QuotaType) -> DquotTransferSlot<'a> {
    DquotTransferSlot { old: old[kind.slot()].as_deref(), new: new[kind.slot()].as_deref() }
}

fn same_slot(old: &Option<Arc<Dquot>>, new: &Option<Arc<Dquot>>) -> bool {
    match (old, new) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}
