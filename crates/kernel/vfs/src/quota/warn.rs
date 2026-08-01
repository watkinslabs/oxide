extern crate alloc;

#[cfg(not(target_os = "oxide-kernel"))]
use alloc::vec::Vec;
use sync::Spinlock;

use super::ids::{Kqid, MAXQUOTAS};

struct QuotaWarnLockClass;
impl sync::LockClass for QuotaWarnLockClass { fn rank() -> u16 { 30 } fn name() -> &'static str { "QuotaWarnLockClass" } }

/// Linux `QUOTA_NL_*` warning class carried by `struct dquot_warn.w_type`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u32)]
pub enum QuotaWarnType {
    #[default]
    NoWarn        = 0,
    IHardWarn     = 1,
    ISoftLongWarn = 2,
    ISoftWarn     = 3,
    BHardWarn     = 4,
    BSoftLongWarn = 5,
    BSoftWarn     = 6,
    IHardBelow    = 7,
    ISoftBelow    = 8,
    BHardBelow    = 9,
    BSoftBelow    = 10,
}

impl QuotaWarnType {
    /// Wire value carried in the `QUOTA_NL_A_WARNING` attribute. # C: O(1)
    pub const fn as_u32(self) -> u32 { self as u32 }
    /// True when this slot carries no pending warning. # C: O(1)
    pub const fn is_none(self) -> bool { matches!(self, QuotaWarnType::NoWarn) }
    /// Human-readable cause, matching the console warning text classes. # C: O(1)
    pub const fn message(self) -> &'static str {
        match self {
            QuotaWarnType::NoWarn        => "",
            QuotaWarnType::IHardWarn     => "file limit reached",
            QuotaWarnType::ISoftLongWarn => "file quota exceeded too long",
            QuotaWarnType::ISoftWarn     => "file quota exceeded",
            QuotaWarnType::BHardWarn     => "block limit reached",
            QuotaWarnType::BSoftLongWarn => "block quota exceeded too long",
            QuotaWarnType::BSoftWarn     => "block quota exceeded",
            QuotaWarnType::IHardBelow    => "file usage back below hard limit",
            QuotaWarnType::ISoftBelow    => "file usage back below soft limit",
            QuotaWarnType::BHardBelow    => "block usage back below hard limit",
            QuotaWarnType::BSoftBelow    => "block usage back below soft limit",
        }
    }
}

/// One pending warning (`struct dquot_warn`): class plus the exceeding id and
/// the device the quota domain belongs to.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DquotWarn {
    pub warn_type: QuotaWarnType,
    pub qid:       Option<Kqid>,
    pub dev:       u32,
}

impl DquotWarn {
    /// Empty warning slot. # C: O(1)
    pub const fn none() -> Self { Self { warn_type: QuotaWarnType::NoWarn, qid: None, dev: 0 } }
    /// `prepare_warning`: record the first warning raised for one dquot slot. # C: O(1)
    pub fn prepare(&mut self, warn_type: QuotaWarnType, qid: Kqid, dev: u32) {
        if warn_type.is_none() || !self.warn_type.is_none() { return; }
        self.warn_type = warn_type;
        self.qid = Some(qid);
        self.dev = dev;
    }
}

/// A full `dquot_warn[MAXQUOTAS]` batch accumulated across one quota operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DquotWarns {
    slots: [DquotWarn; MAXQUOTAS],
}

impl Default for DquotWarns {
    fn default() -> Self { Self::new() }
}

impl DquotWarns {
    /// Empty warning batch. # C: O(1)
    pub const fn new() -> Self { Self { slots: [DquotWarn::none(); MAXQUOTAS] } }
    /// Record a warning into one quota-class slot. # C: O(1)
    pub fn prepare(&mut self, qid: Kqid, warn_type: QuotaWarnType, dev: u32) {
        self.slots[qid.slot()].prepare(warn_type, qid, dev);
    }
    /// Snapshot one quota-class slot. # C: O(1)
    pub fn slot(&self, idx: usize) -> DquotWarn { self.slots[idx] }
    /// True when no class raised a warning. # C: O(MAXQUOTAS)
    pub fn is_empty(&self) -> bool { self.slots.iter().all(|w| w.warn_type.is_none()) }
    /// `flush_warnings`: deliver every pending warning and clear the batch. # C: O(MAXQUOTAS)
    pub fn flush(&mut self, caused_by_uid: u32) {
        for slot in &mut self.slots {
            let (warn_type, Some(qid)) = (slot.warn_type, slot.qid) else { continue; };
            if warn_type.is_none() { continue; }
            deliver_warning(QuotaWarning { qid, dev: slot.dev, warn_type, caused_by_uid });
            *slot = DquotWarn::none();
        }
    }
}

/// One delivered quota warning, matching the `VFS_DQUOT`/`QUOTA_NL_C_WARNING`
/// attribute set: quota class, exceeding id, warning class, device, and the
/// uid of the task whose allocation crossed the limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaWarning {
    pub qid:           Kqid,
    pub dev:           u32,
    pub warn_type:     QuotaWarnType,
    pub caused_by_uid: u32,
}

type QuotaWarnHook = fn(QuotaWarning);

static QUOTA_WARN_HOOK: Spinlock<Option<QuotaWarnHook>, QuotaWarnLockClass> = Spinlock::new(None);

/// Install the quota-warning delivery hook. VFS owns warning generation; the
/// broadcast transport lives in the layer that owns sockets. # C: O(1)
pub fn set_quota_warn_hook(hook: QuotaWarnHook) { *QUOTA_WARN_HOOK.lock() = Some(hook); }

/// Remove the quota-warning delivery hook. # C: O(1)
pub fn clear_quota_warn_hook() { *QUOTA_WARN_HOOK.lock() = None; }

/// Deliver one warning to the installed transport, logging it either way. # C: O(1)+transport
pub fn deliver_warning(warning: QuotaWarning) {
    record_warning(warning);
    let hook = *QUOTA_WARN_HOOK.lock();
    if let Some(hook) = hook { hook(warning); }
}

#[cfg(not(target_os = "oxide-kernel"))]
static WARN_LOG: Spinlock<Vec<QuotaWarning>, QuotaWarnLockClass> = Spinlock::new(Vec::new());

#[cfg(not(target_os = "oxide-kernel"))]
fn record_warning(warning: QuotaWarning) { WARN_LOG.lock().push(warning); }

/// Drain warnings observed by hosted tests. # C: O(N)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn take_logged_warnings() -> Vec<QuotaWarning> { core::mem::take(&mut *WARN_LOG.lock()) }

#[cfg(target_os = "oxide-kernel")]
fn record_warning(warning: QuotaWarning) {
    klog::write_primary_raw(b"[QUOTA] ");
    klog::write_primary_raw(warning.warn_type.message().as_bytes());
    klog::write_primary_raw(b" type=");
    klog::write_primary_hex_u64(warning.qid.kind.slot() as u64);
    klog::write_primary_raw(b" id=");
    klog::write_primary_hex_u64(warning.qid.id as u64);
    klog::write_primary_raw(b" dev=");
    klog::write_primary_hex_u64(warning.dev as u64);
    klog::write_primary_raw(b"\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ids::QuotaType;

    #[test]
    fn prepare_keeps_first_warning_per_slot() {
        let mut w = DquotWarn::none();
        w.prepare(QuotaWarnType::BSoftWarn, Kqid::user(7), 0x0801);
        w.prepare(QuotaWarnType::BHardWarn, Kqid::user(7), 0x0801);
        assert_eq!(w.warn_type, QuotaWarnType::BSoftWarn);
        assert_eq!(w.qid, Some(Kqid::user(7)));
        assert_eq!(w.dev, 0x0801);
    }

    #[test]
    fn prepare_ignores_nowarn() {
        let mut w = DquotWarn::none();
        w.prepare(QuotaWarnType::NoWarn, Kqid::group(1), 5);
        assert_eq!(w, DquotWarn::none());
    }

    #[test]
    fn warn_wire_values_match_uapi() {
        assert_eq!(QuotaWarnType::NoWarn.as_u32(), 0);
        assert_eq!(QuotaWarnType::IHardWarn.as_u32(), 1);
        assert_eq!(QuotaWarnType::ISoftLongWarn.as_u32(), 2);
        assert_eq!(QuotaWarnType::ISoftWarn.as_u32(), 3);
        assert_eq!(QuotaWarnType::BHardWarn.as_u32(), 4);
        assert_eq!(QuotaWarnType::BSoftLongWarn.as_u32(), 5);
        assert_eq!(QuotaWarnType::BSoftWarn.as_u32(), 6);
        assert_eq!(QuotaWarnType::IHardBelow.as_u32(), 7);
        assert_eq!(QuotaWarnType::ISoftBelow.as_u32(), 8);
        assert_eq!(QuotaWarnType::BHardBelow.as_u32(), 9);
        assert_eq!(QuotaWarnType::BSoftBelow.as_u32(), 10);
    }

    #[test]
    fn batch_slots_are_indexed_by_quota_class() {
        let mut warns = DquotWarns::new();
        warns.prepare(Kqid::group(3), QuotaWarnType::IHardWarn, 9);
        assert!(warns.slot(QuotaType::User.slot()).warn_type.is_none());
        assert_eq!(warns.slot(QuotaType::Group.slot()).warn_type, QuotaWarnType::IHardWarn);
        assert!(!warns.is_empty());
    }
}
