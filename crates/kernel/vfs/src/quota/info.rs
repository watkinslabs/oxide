extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::Spinlock;

use crate::superblock::SuperBlock;
use crate::types::{KResult, VfsError};

use super::dquot::{DquotRef, DquotSet};
use super::ids::{Kqid, QuotaType};
use super::limits::{DQF_GETINFO_MASK, DQF_SETINFO_MASK, IIF_ALL, IIF_BGRACE, IIF_BWARN, IIF_FLAGS, IIF_IGRACE, IIF_IWARN, IIF_RT_BGRACE, IIF_RTBWARN, MemDqinfo};
use super::ops::DquotOperations;

struct QuotaOpsLockClass;
impl sync::LockClass for QuotaOpsLockClass { fn rank() -> u16 { 32 } fn name() -> &'static str { "QuotaOpsLockClass" } }

struct QuotaWaitLockClass;
impl sync::LockClass for QuotaWaitLockClass { fn rank() -> u16 { 31 } fn name() -> &'static str { "QuotaWaitLockClass" } }

type QuotaParkHook = fn(usize);
type QuotaScheduleHook = fn();
type QuotaWakeHook = fn(usize);

#[derive(Clone, Copy)]
struct QuotaWaitHooks {
    park:     Option<QuotaParkHook>,
    schedule: Option<QuotaScheduleHook>,
    wake:     Option<QuotaWakeHook>,
}

static QUOTA_WAIT_LOCK: Spinlock<(), QuotaWaitLockClass> = Spinlock::new(());
static QUOTA_WAIT_HOOKS: Spinlock<QuotaWaitHooks, QuotaWaitLockClass> = Spinlock::new(QuotaWaitHooks {
    park: None, schedule: None, wake: None,
});

/// Superblock quota state (`super_block.s_dquot`). # C: O(1)
pub struct QuotaInfo {
    enabled:          AtomicU32,
    limits:           AtomicU32,
    suspended_limits: AtomicU32,
    closing:          AtomicU32,
    dquots:           DquotSet,
    info:             [QuotaClassInfo; 3],
    owner:            Spinlock<Weak<SuperBlock>, QuotaOwnerLockClass>,
}

struct QuotaOwnerLockClass;
impl sync::LockClass for QuotaOwnerLockClass { fn rank() -> u16 { 31 } fn name() -> &'static str { "QuotaOwnerLockClass" } }

struct QuotaClassInfo {
    bgrace:    AtomicU64,
    igrace:    AtomicU64,
    rt_bgrace: AtomicU64,
    bwarn:     AtomicU32,
    iwarn:     AtomicU32,
    rtbwarn:   AtomicU32,
    flags:     AtomicU32,
    fmt:       AtomicU32,
    ops:       Spinlock<Option<Arc<dyn DquotOperations>>, QuotaOpsLockClass>,
}

impl QuotaInfo {
    /// Empty quota state: no types enabled, no filesystem hooks. # C: O(1)
    pub fn new() -> Self {
        Self { enabled: AtomicU32::new(0), limits: AtomicU32::new(0), suspended_limits: AtomicU32::new(0), closing: AtomicU32::new(0), dquots: DquotSet::new(),
            info: core::array::from_fn(|_| QuotaClassInfo::new()), owner: Spinlock::new(Weak::new()) }
    }
    /// Bind this `s_dquot` to its containing superblock. # C: O(1)
    pub fn bind_super(&self, sb: &Arc<SuperBlock>) { *self.owner.lock() = Arc::downgrade(sb); }
    /// Owning superblock snapshot. # C: O(1)
    pub fn owner_super(&self) -> Option<Arc<SuperBlock>> { self.owner.lock().upgrade() }
    /// Install quota-file hooks for one quota class. # C: O(1)
    pub fn set_operations(&self, kind: QuotaType, ops: Arc<dyn DquotOperations>) { *self.info[kind.slot()].ops.lock() = Some(ops); }
    /// Remove quota-file hooks for one quota class. # C: O(1)
    pub fn clear_operations(&self, kind: QuotaType) { *self.info[kind.slot()].ops.lock() = None; }
    /// Enable one quota class on this superblock. # C: O(1)
    pub fn enable(&self, kind: QuotaType, fmt: u32) {
        self.info[kind.slot()].fmt.store(fmt, Ordering::Release);
        self.closing.fetch_and(!kind_bit(kind), Ordering::AcqRel);
        self.enabled.fetch_or(kind_bit(kind), Ordering::AcqRel);
        self.limits.fetch_or(kind_bit(kind), Ordering::AcqRel);
    }
    /// Disable one quota class on this superblock. # C: O(1)
    pub fn disable(&self, kind: QuotaType) {
        let bit = kind_bit(kind);
        self.enabled.fetch_and(!bit, Ordering::AcqRel);
        self.limits.fetch_and(!bit, Ordering::AcqRel);
        self.suspended_limits.fetch_and(!bit, Ordering::AcqRel);
        self.closing.fetch_and(!bit, Ordering::AcqRel);
    }
    /// Start Linux quota-off: block new users while teardown drains old refs. # C: O(1)
    pub fn begin_disable(&self, kind: QuotaType) -> bool {
        let bit = kind_bit(kind);
        if self.enabled.fetch_and(!bit, Ordering::AcqRel) & bit == 0 { return false; }
        self.limits.fetch_and(!bit, Ordering::AcqRel);
        self.closing.fetch_or(bit, Ordering::AcqRel);
        true
    }
    /// Suspend one sysfile quota class for RW→RO remount. # C: O(1)
    pub fn suspend(&self, kind: QuotaType) -> KResult<()> {
        let bit = kind_bit(kind);
        if self.enabled.fetch_and(!bit, Ordering::AcqRel) & bit == 0 { return Err(VfsError::Esrch); }
        if self.limits.fetch_and(!bit, Ordering::AcqRel) & bit != 0 {
            self.suspended_limits.fetch_or(bit, Ordering::AcqRel);
        } else {
            self.suspended_limits.fetch_and(!bit, Ordering::AcqRel);
        }
        Ok(())
    }
    /// Consume the suspended enforcement snapshot for one quota class. # C: O(1)
    pub fn take_suspended_limits(&self, kind: QuotaType) -> bool {
        let bit = kind_bit(kind);
        self.suspended_limits.fetch_and(!bit, Ordering::AcqRel) & bit != 0
    }
    /// True if a suspended quota class had enforcement active before suspend. # C: O(1)
    pub fn has_suspended_limits(&self, kind: QuotaType) -> bool {
        self.suspended_limits.load(Ordering::Acquire) & kind_bit(kind) != 0
    }
    /// True while quota-off teardown is draining one class. # C: O(1)
    pub fn is_closing(&self, kind: QuotaType) -> bool {
        self.closing.load(Ordering::Acquire) & kind_bit(kind) != 0
    }
    /// True when a quota class is active on this superblock. # C: O(1)
    pub fn is_enabled(&self, kind: QuotaType) -> bool {
        self.enabled.load(Ordering::Acquire) & kind_bit(kind) != 0
    }
    /// True when quota limit enforcement is active for this class. # C: O(1)
    pub fn is_enforced(&self, kind: QuotaType) -> bool {
        self.limits.load(Ordering::Acquire) & kind_bit(kind) != 0
    }
    /// Enable quota limit enforcement while accounting is already active. # C: O(1)
    pub fn enable_limits(&self, kind: QuotaType) -> KResult<()> {
        let bit = kind_bit(kind);
        if self.enabled.load(Ordering::Acquire) & bit == 0 { return Err(VfsError::Einval); }
        if self.limits.fetch_or(bit, Ordering::AcqRel) & bit != 0 { return Err(VfsError::Eexist); }
        Ok(())
    }
    /// Disable quota limit enforcement while keeping accounting active. # C: O(1)
    pub fn disable_limits(&self, kind: QuotaType) -> KResult<()> {
        let bit = kind_bit(kind);
        if self.limits.fetch_and(!bit, Ordering::AcqRel) & bit == 0 { return Err(VfsError::Eexist); }
        Ok(())
    }
    /// Snapshot the active class mask. # C: O(1)
    pub fn enabled_mask(&self) -> u32 { self.enabled.load(Ordering::Acquire) }
    /// Snapshot the enforced class mask. # C: O(1)
    pub fn enforced_mask(&self) -> u32 { self.limits.load(Ordering::Acquire) }
    /// Active quota-file format for one class. # C: O(1)
    pub fn format(&self, kind: QuotaType) -> u32 { self.info[kind.slot()].fmt.load(Ordering::Acquire) }
    /// Backing dquot cache. # C: O(1)
    pub fn dquots(&self) -> &DquotSet { &self.dquots }
    /// Hosted tests inspect leaked active references without parking quota-off. # C: O(log N)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn active_refs_for_tests(&self, qid: Kqid) -> usize {
        self.dquots.lookup(qid).map(|dq| dq.active_refs()).unwrap_or(0)
    }
    /// Quota-file hook snapshot for one class. # C: O(1)
    pub fn operations(&self, kind: QuotaType) -> Option<Arc<dyn DquotOperations>> { self.info[kind.slot()].ops.lock().clone() }
    /// Any installed quota-file hook, used by filesystems with shared hook objects. # C: O(MAXQUOTAS)
    pub fn any_operations(&self) -> Option<Arc<dyn DquotOperations>> {
        for kind in [QuotaType::User, QuotaType::Group, QuotaType::Project] {
            if let Some(ops) = self.operations(kind) { return Some(ops); }
        }
        None
    }
    /// Snapshot enabled quota-file hooks. # C: O(MAXQUOTAS)
    pub fn enabled_operations(&self) -> [Option<Arc<dyn DquotOperations>>; 3] {
        core::array::from_fn(|idx| {
            let kind = quota_type_from_slot(idx);
            if self.is_enabled(kind) { self.operations(kind) } else { None }
        })
    }
    /// Snapshot quota-file info for one class. # C: O(1)
    pub fn info(&self, kind: QuotaType) -> MemDqinfo { self.info[kind.slot()].get() }
    /// Apply a Linux Q_SETINFO masked update. # C: O(1)
    pub fn set_info(&self, kind: QuotaType, info: MemDqinfo) { self.info[kind.slot()].set(info); }
    /// Load filesystem-owned quota info, including read-only kernel flags. # C: O(1)
    pub fn load_info(&self, kind: QuotaType, info: MemDqinfo) { self.info[kind.slot()].load(info); }
    /// Clear per-type quota-file info after quota-off. # C: O(1)
    pub fn clear_info(&self, kind: QuotaType) { self.info[kind.slot()].clear(); }
    /// Wait until quota-off can invalidate every cached dquot for one class. # C: O(N) or sleeps
    pub fn wait_for_kind_quiesced(&self, kind: QuotaType) {
        loop {
            let _g = QUOTA_WAIT_LOCK.lock();
            if self.dquots.kind_quiesced(kind) { return; }
            let hooks = quota_wait_hooks();
            match (hooks.park, hooks.schedule) {
                (Some(park), Some(schedule)) => {
                    park(self.wait_key(kind));
                    drop(_g);
                    schedule();
                }
                _ => {
                    drop(_g);
                    core::hint::spin_loop();
                }
            }
        }
    }
    /// Linux `dqget`: lookup/create canonical dquot, then acquire it. # C: O(log N)+FS
    pub fn dqget(&self, qid: Kqid) -> KResult<DquotRef> {
        if !self.is_enabled(qid.kind) { return Err(VfsError::Esrch); }
        let ops = self.operations(qid.kind);
        let dq = match &ops {
            Some(o) => self.dquots.get_or_insert_with(qid, |id| o.alloc_dquot(id)),
            None => self.dquots.get_or_create(qid),
        };
        if let Some(sb) = self.owner_super() { dq.bind_owner(&sb)?; }
        if let Some(o) = ops { o.acquire_dquot(dq.as_ref())?; }
        dq.acquire_ref();
        Ok(dq)
    }
    /// Linux `dqput`: release one active dquot user and wake quota-off waiters. # C: O(log N)+FS
    pub fn dqput(&self, dq: DquotRef) {
        let kind = dq.id().kind;
        if !self.dquots.contains_exact(&dq) { return; }
        if !dq.release_ref() { return; }
        if self.is_closing(kind) { let _ = self.drop_inactive_dquot(dq); }
        self.wake_kind(kind);
    }
    /// Final quota-off invalidation for an inactive cached dquot. # C: O(log N)+FS
    pub fn drop_inactive_dquot(&self, dq: DquotRef) -> KResult<()> {
        let kind = dq.id().kind;
        if !self.dquots.remove_inactive_exact(&dq) { return Ok(()); }
        if let Err(e) = self.drop_removed_dquot(kind, dq.as_ref()) {
            self.dquots.reinsert_inactive(dq);
            self.wake_kind(kind);
            return Err(e);
        }
        self.wake_kind(kind);
        Ok(())
    }
    fn drop_removed_dquot(&self, kind: QuotaType, dq: &super::dquot::Dquot) -> KResult<()> {
        if let Some(ops) = self.operations(kind) {
            if dq.is_dirty() {
                ops.write_dquot(dq)?;
                dq.clear_dirty();
            }
            ops.release_dquot(dq)?;
        }
        Ok(())
    }
    fn wait_key(&self, kind: QuotaType) -> usize {
        (self as *const QuotaInfo as usize) ^ kind.slot()
    }
    // B1427: the wake call MUST be gated by QUOTA_WAIT_LOCK — the same lock
    // `wait_for_kind_quiesced` holds across its condition check + park. The
    // dquot refcount mutation (release_ref) that flips the condition happens
    // lock-free via atomics, so without this gate a waiter's check (sees
    // non-quiesced) can race a concurrent release_ref+wake_kind: the wake
    // fires into an empty wait list (waiter hasn't parked yet) and is lost,
    // then the waiter parks forever. Gating the wake under QUOTA_WAIT_LOCK
    // forces it to happen either before the waiter's check (harmless, waiter
    // then sees quiesced) or after the waiter has already registered on the
    // wait list under the same lock (wake finds it) — never in the gap.
    fn wake_kind(&self, kind: QuotaType) {
        let _g = QUOTA_WAIT_LOCK.lock();
        if let Some(wake) = quota_wait_hooks().wake { wake(self.wait_key(kind)); }
    }
}

/// Install quota-off wait hooks. VFS owns dquot state; sched owns task parking. # C: O(1)
pub fn set_quota_wait_hooks(park: QuotaParkHook, schedule: QuotaScheduleHook, wake: QuotaWakeHook) {
    *QUOTA_WAIT_HOOKS.lock() = QuotaWaitHooks { park: Some(park), schedule: Some(schedule), wake: Some(wake) };
}

/// Clear quota-off wait hooks for hosted tests that install process-global hooks. # C: O(1)
pub fn clear_quota_wait_hooks() {
    *QUOTA_WAIT_HOOKS.lock() = QuotaWaitHooks { park: None, schedule: None, wake: None };
}

fn quota_wait_hooks() -> QuotaWaitHooks { *QUOTA_WAIT_HOOKS.lock() }

impl QuotaClassInfo {
    fn new() -> Self {
        Self {
            bgrace: AtomicU64::new(0), igrace: AtomicU64::new(0), rt_bgrace: AtomicU64::new(0),
            bwarn: AtomicU32::new(0), iwarn: AtomicU32::new(0), rtbwarn: AtomicU32::new(0),
            flags: AtomicU32::new(0), fmt: AtomicU32::new(0), ops: Spinlock::new(None),
        }
    }
    fn get(&self) -> MemDqinfo {
        MemDqinfo {
            dqi_bgrace: self.bgrace.load(Ordering::Acquire),
            dqi_igrace: self.igrace.load(Ordering::Acquire),
            dqi_rt_bgrace: self.rt_bgrace.load(Ordering::Acquire),
            dqi_bwarnlimit: self.bwarn.load(Ordering::Acquire) as u16,
            dqi_iwarnlimit: self.iwarn.load(Ordering::Acquire) as u16,
            dqi_rtbwarnlimit: self.rtbwarn.load(Ordering::Acquire) as u16,
            dqi_flags: self.flags.load(Ordering::Acquire) & DQF_GETINFO_MASK,
            dqi_valid: IIF_ALL,
        }
    }
    fn set(&self, info: MemDqinfo) {
        if info.dqi_valid & IIF_BGRACE != 0 { self.bgrace.store(info.dqi_bgrace, Ordering::Release); }
        if info.dqi_valid & IIF_IGRACE != 0 { self.igrace.store(info.dqi_igrace, Ordering::Release); }
        if info.dqi_valid & IIF_RT_BGRACE != 0 { self.rt_bgrace.store(info.dqi_rt_bgrace, Ordering::Release); }
        if info.dqi_valid & IIF_BWARN != 0 { self.bwarn.store(info.dqi_bwarnlimit as u32, Ordering::Release); }
        if info.dqi_valid & IIF_IWARN != 0 { self.iwarn.store(info.dqi_iwarnlimit as u32, Ordering::Release); }
        if info.dqi_valid & IIF_RTBWARN != 0 { self.rtbwarn.store(info.dqi_rtbwarnlimit as u32, Ordering::Release); }
        if info.dqi_valid & IIF_FLAGS != 0 { self.flags.store(info.dqi_flags & DQF_SETINFO_MASK, Ordering::Release); }
    }
    fn load(&self, info: MemDqinfo) {
        if info.dqi_valid & IIF_BGRACE != 0 { self.bgrace.store(info.dqi_bgrace, Ordering::Release); }
        if info.dqi_valid & IIF_IGRACE != 0 { self.igrace.store(info.dqi_igrace, Ordering::Release); }
        if info.dqi_valid & IIF_RT_BGRACE != 0 { self.rt_bgrace.store(info.dqi_rt_bgrace, Ordering::Release); }
        if info.dqi_valid & IIF_BWARN != 0 { self.bwarn.store(info.dqi_bwarnlimit as u32, Ordering::Release); }
        if info.dqi_valid & IIF_IWARN != 0 { self.iwarn.store(info.dqi_iwarnlimit as u32, Ordering::Release); }
        if info.dqi_valid & IIF_RTBWARN != 0 { self.rtbwarn.store(info.dqi_rtbwarnlimit as u32, Ordering::Release); }
        if info.dqi_valid & IIF_FLAGS != 0 { self.flags.store(info.dqi_flags & DQF_GETINFO_MASK, Ordering::Release); }
    }
    fn clear(&self) {
        self.bgrace.store(0, Ordering::Release);
        self.igrace.store(0, Ordering::Release);
        self.rt_bgrace.store(0, Ordering::Release);
        self.bwarn.store(0, Ordering::Release);
        self.iwarn.store(0, Ordering::Release);
        self.rtbwarn.store(0, Ordering::Release);
        self.flags.store(0, Ordering::Release);
        self.fmt.store(0, Ordering::Release);
    }
}

impl Default for QuotaInfo {
    fn default() -> Self { Self::new() }
}

fn kind_bit(kind: QuotaType) -> u32 { 1u32 << kind.slot() }

fn quota_type_from_slot(slot: usize) -> QuotaType {
    match slot {
        0 => QuotaType::User,
        1 => QuotaType::Group,
        _ => QuotaType::Project,
    }
}
