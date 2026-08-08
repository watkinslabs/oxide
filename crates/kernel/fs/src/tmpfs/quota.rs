// tmpfs disk quota: the mount's `quota`/`usrquota`/`grpquota` classes and the
// four `*_hardlimit=` ceilings, enforced through the generic dquot layer with
// an in-memory dquot as the record.
//
// Where the charges happen mirrors the reference exactly: the mount-wide
// block/inode ceilings are consulted FIRST (their refusal is ENOSPC), the
// per-owner quota SECOND (its refusal is EDQUOT), and a quota refusal returns
// the mount-wide reservation before it propagates. Both happen at allocation
// time — a page is charged when it is allocated, not when a write completes.
//
// The owner a charge lands on is the owner recorded on the charged object, not
// the calling task: a chown moves the outstanding charge between owners through
// the generic transfer, and the object's recorded owner moves with it.

use alloc::sync::{Arc, Weak};

use vfs::superblock::SuperBlock;
use vfs::{DquotLimits, DquotRef, DquotUsage, KResult, Kqid, MemDqinfo, QuotaLimit, QuotaType, VfsError};

use super::accounting::TmpfsSb;
use super::limits::PG;
use super::mount_opts::{QTYPE_MASK_GRP, QTYPE_MASK_USR, QuotaLimits, TmpfsOpts};

/// Grace period a class is given after crossing a soft limit, for both the
/// block and the inode counter. An in-memory filesystem has no place to record
/// a per-class grace override across a mount, so both start at one week.
const QUOTA_GRACE_SECS: u64 = 7 * 24 * 60 * 60;

/// Bookkeeping unit `i_blocks` is expressed in, so a charged page reports the
/// same size to `stat(2)` as it costs the owner's quota.
const BLOCK_UNIT: u64 = 512;

/// The owner one quota charge lands on. Carried alongside the charge rather
/// than re-read from the calling task, so the release finds the same owner the
/// allocation charged even when the object outlives its last name.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct QuotaOwner {
    pub uid: u32,
    pub gid: u32,
}

impl QuotaOwner {
    /// # C: O(1)
    pub(super) const fn new(uid: u32, gid: u32) -> Self { Self { uid, gid } }
    /// The owner recorded on an inode. # C: O(1)
    pub(super) fn of(inode: &vfs::Inode) -> Self {
        Self::new(inode.uid().unwrap_or(0), inode.gid().unwrap_or(0))
    }
}

/// One mount's quota configuration: the classes it turns on and the hard
/// ceilings every id in each class starts with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct TmpfsQuota {
    types:  u32,
    limits: QuotaLimits,
}

impl TmpfsQuota {
    /// No class on: the accounting a mount without quota options keeps. # C: O(1)
    pub(super) const fn off() -> Self { Self { types: 0, limits: QuotaLimits { usr_block: 0, usr_inode: 0, grp_block: 0, grp_inode: 0 } } }
    /// The classes and ceilings one parsed option string asks for. # C: O(1)
    pub(super) const fn from_opts(o: &TmpfsOpts) -> Self { Self { types: o.quota_types, limits: o.qlimits } }
    /// True when any class is on. # C: O(1)
    pub(super) const fn is_on(&self) -> bool { self.types != 0 }
    /// True when this class is one the mount asked for. # C: O(1)
    pub(super) const fn has(&self, kind: QuotaType) -> bool { self.types & mask_of(kind) != 0 }
    /// The ceilings a freshly seen id in `kind` starts with. Zero in a slot is
    /// the absence of a ceiling, not a ceiling of zero. # C: O(1)
    pub(super) const fn limits_for(&self, kind: QuotaType) -> DquotLimits {
        let (block, inode) = match kind {
            QuotaType::User  => (self.limits.usr_block, self.limits.usr_inode),
            QuotaType::Group => (self.limits.grp_block, self.limits.grp_inode),
            QuotaType::Project => (0, 0),
        };
        DquotLimits { space: QuotaLimit::hard(block), reserved_space: QuotaLimit::unlimited(), inodes: QuotaLimit::hard(inode) }
    }
}

const fn mask_of(kind: QuotaType) -> u32 {
    match kind {
        QuotaType::User  => QTYPE_MASK_USR,
        QuotaType::Group => QTYPE_MASK_GRP,
        QuotaType::Project => 0,
    }
}

/// The classes a tmpfs mount can carry. Project quota needs an id the inode
/// carries independently of its owner, which this filesystem has no mount
/// option to set, so it is never one of them.
const TMPFS_QUOTA_TYPES: [QuotaType; 2] = [QuotaType::User, QuotaType::Group];

/// The in-memory quota record: the dquot itself. A newly seen id is born with
/// the mount's hard ceilings, and nothing writes it anywhere else, because
/// there is nowhere else. # C: O(1)
struct ShmemDquotOps {
    q:  TmpfsQuota,
    sb: Weak<SuperBlock>,
}

impl vfs::DquotOperations for ShmemDquotOps {
    /// # C: O(1)
    fn as_any(&self) -> &dyn core::any::Any { self }
    /// # C: O(1)
    fn alloc_dquot(&self, qid: Kqid) -> DquotRef { vfs::Dquot::with_limits(qid, self.q.limits_for(qid.kind)) }
    /// Nothing to write back: the record and the in-core dquot are one object.
    /// # C: O(1)
    fn mark_dirty(&self, _dq: &vfs::Dquot) -> KResult<()> { Ok(()) }
    /// # C: O(1)
    fn write_dquot(&self, _dq: &vfs::Dquot) -> KResult<()> { Ok(()) }
    /// # C: O(1)
    fn write_info(&self, _kind: QuotaType, _info: MemDqinfo) -> KResult<()> { Ok(()) }
    /// Lowest id at or after `qid` this mount holds a record for. # C: O(N)
    fn get_next_id(&self, qid: Kqid) -> KResult<Option<Kqid>> {
        let sb = self.sb.upgrade().ok_or(VfsError::Esrch)?;
        if !sb.s_dquot.is_enabled(qid.kind) { return Err(VfsError::Esrch); }
        Ok(sb.s_dquot.dquots().next_id(qid.kind, qid.id).map(|id| Kqid { kind: qid.kind, id }))
    }
}

/// Turn on every class this mount asked for, with the grace periods an
/// in-memory quota carries and the mount's ceilings as each class's defaults.
/// A class that fails to come up leaves the ones before it off too, so the
/// mount never runs with a partial quota. # C: O(MAXQUOTAS)
pub(super) fn enable(sb: &Arc<SuperBlock>, q: &TmpfsQuota) -> KResult<()> {
    if !q.is_on() { return Ok(()); }
    let ops: Arc<dyn vfs::DquotOperations> = Arc::new(ShmemDquotOps { q: *q, sb: Arc::downgrade(sb) });
    for kind in TMPFS_QUOTA_TYPES {
        if !q.has(kind) { continue; }
        if let Err(e) = vfs::quota_on(sb, kind, vfs::QFMT_SHMEM, ops.clone()) {
            for done in TMPFS_QUOTA_TYPES {
                if done == kind { break; }
                if q.has(done) { let _ = vfs::quota_off(sb, done); }
            }
            return Err(e);
        }
        sb.s_dquot.load_info(kind, MemDqinfo {
            dqi_bgrace: QUOTA_GRACE_SECS,
            dqi_igrace: QUOTA_GRACE_SECS,
            dqi_valid:  vfs::IIF_BGRACE | vfs::IIF_IGRACE,
            ..Default::default()
        });
    }
    Ok(())
}

/// Turn off every class this mount has on (last-umount teardown). # C: O(N_dq)
pub(super) fn disable(sb: &SuperBlock) {
    for kind in TMPFS_QUOTA_TYPES {
        if sb.s_dquot.is_enabled(kind) { let _ = vfs::quota_off(sb, kind); }
    }
}

/// Bytes `pages` data pages cost an owner's block quota. # C: O(1)
pub(super) const fn quota_space(pages: u64) -> u64 { pages.saturating_mul(PG as u64) }

/// `i_blocks` value `pages` data pages report. # C: O(1)
pub(super) const fn blocks_of(pages: u64) -> u64 { pages.saturating_mul(PG as u64 / BLOCK_UNIT) }

/// Reserve `pages` data pages for `owner`: the mount ceiling first (`ENOSPC`),
/// then the owner's block quota (`EDQUOT`), returning the mount reservation if
/// the quota refuses. # C: O(pages + MAXQUOTAS log N)
pub(super) fn acct_blocks(acct: &TmpfsSb, owner: QuotaOwner, pages: u64) -> KResult<()> {
    if pages == 0 { return Ok(()); }
    if !acct.charge_blocks(pages) { return Err(VfsError::Enospc); }
    if let Err(e) = charge(acct, owner, DquotUsage { space: quota_space(pages), reserved_space: 0, inodes: 0 }) {
        acct.free_blocks(pages);
        return Err(e);
    }
    Ok(())
}

/// Release `pages` data pages charged to `owner`. # C: O(MAXQUOTAS log N)
pub(super) fn unacct_blocks(acct: &TmpfsSb, owner: QuotaOwner, pages: u64) {
    if pages == 0 { return; }
    release(acct, owner, DquotUsage { space: quota_space(pages), reserved_space: 0, inodes: 0 });
    acct.free_blocks(pages);
}

/// Reserve one inode for `owner`: the mount ceiling first (`ENOSPC`), then the
/// owner's inode quota (`EDQUOT`). # C: O(MAXQUOTAS log N)
pub(super) fn alloc_inode(acct: &TmpfsSb, owner: QuotaOwner) -> KResult<()> {
    if !acct.charge_inode() { return Err(VfsError::Enospc); }
    if let Err(e) = charge(acct, owner, DquotUsage::inode(0, 0)) {
        acct.free_inode();
        return Err(e);
    }
    Ok(())
}

/// Charge the owner's inode quota for an inode that already holds its
/// mount-wide reservation (the root inode, built before the mount had a quota
/// domain to charge against). # C: O(MAXQUOTAS log N)
pub(super) fn charge_existing_inode(acct: &TmpfsSb, inode: &vfs::InodeRef) {
    let _ = charge(acct, QuotaOwner::of(inode), DquotUsage::inode(0, 0));
}

/// Release one inode charged to `owner`. # C: O(MAXQUOTAS log N)
pub(super) fn free_inode(acct: &TmpfsSb, owner: QuotaOwner) {
    release(acct, owner, DquotUsage::inode(0, 0));
    acct.free_inode();
}

fn charge(acct: &TmpfsSb, owner: QuotaOwner, usage: DquotUsage) -> KResult<()> {
    let Some(sb) = acct.quota_sb() else { return Ok(()); };
    vfs::dquot_charge_usage(&sb, owner.uid, owner.gid, 0, usage)
}

fn release(acct: &TmpfsSb, owner: QuotaOwner, usage: DquotUsage) {
    let Some(sb) = acct.quota_sb() else { return; };
    // A release that cannot find its charge means the charge was never made
    // (an instance whose quota came on after the object did). Nothing is owed,
    // so there is nothing to report and nothing to undo.
    let _ = vfs::dquot_release_usage(&sb, owner.uid, owner.gid, 0, usage);
}
