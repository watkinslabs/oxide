// Audit configuration: the values a control client reads back in
// `struct audit_status`, and the admission ladder that guards changing them.
//
// Pure — no locks, no clock, no allocation. `state` owns the single live
// instance; everything here is a decision the hosted suite drives directly.
//
// Validity and permission are separate steps on purpose. A control client's
// change is itself an audited event, and the record must be written BEFORE the
// change lands and must carry whether it was allowed — so the caller needs to
// know "this value is legal" and "this client may set it" as two answers.

use syscall::errno::Errno;

use crate::uapi::*;

/// The configurable half of the audit system.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// `AUDIT_OFF` / `AUDIT_ON` / `AUDIT_LOCKED`.
    pub enabled: u32,
    /// What to do when a record cannot be emitted.
    pub failure: u32,
    /// Records per second, or zero for no limit.
    pub rate_limit: u32,
    /// Outstanding records allowed, or zero for no limit.
    pub backlog_limit: u32,
    /// How long a producer may wait for backlog room, in ticks.
    pub backlog_wait_time: u32,
    /// Records dropped since the counter was last reset.
    pub lost: u32,
    /// Accumulated time producers spent waiting on a full backlog, in ticks.
    pub backlog_wait_time_actual: u32,
    /// Optional features currently on.
    pub features: u32,
    /// Optional features that can no longer be changed.
    pub feature_lock: u32,
}

impl Config {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            enabled: AUDIT_OFF, failure: AUDIT_FAIL_PRINTK, rate_limit: 0,
            backlog_limit: AUDIT_BACKLOG_LIMIT_DEFAULT,
            backlog_wait_time: AUDIT_BACKLOG_WAIT_TIME,
            lost: 0, backlog_wait_time_actual: 0, features: 0, feature_lock: 0,
        }
    }

    /// Whether configuration is frozen. Locking is one-way: it is the point of
    /// the state, so nothing but a reboot clears it.
    /// # C: O(1)
    pub fn locked(&self) -> bool { self.enabled == AUDIT_LOCKED }

    /// Read and clear the lost counter. The read is destructive because the
    /// client is claiming the hole it describes.
    /// # C: O(1)
    pub fn take_lost(&mut self) -> u32 { core::mem::replace(&mut self.lost, 0) }

    /// # C: O(1)
    pub fn take_backlog_wait_time_actual(&mut self) -> u32 {
        core::mem::replace(&mut self.backlog_wait_time_actual, 0)
    }

    /// Count one dropped record. Saturating: an overflowed counter that wrapped
    /// to a small number would understate the hole.
    /// # C: O(1)
    pub fn count_lost(&mut self) { self.lost = self.lost.saturating_add(1); }
}

impl Default for Config {
    /// # C: O(1)
    fn default() -> Self { Self::new() }
}

/// A settable configuration value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Field {
    Enabled,
    Failure,
    RateLimit,
    BacklogLimit,
    BacklogWaitTime,
}

impl Field {
    /// The name this field carries in a configuration-change record.
    /// # C: O(1)
    pub fn name(self) -> &'static [u8] {
        match self {
            Field::Enabled => b"audit_enabled",
            Field::Failure => b"audit_failure",
            Field::RateLimit => b"audit_rate_limit",
            Field::BacklogLimit => b"audit_backlog_limit",
            Field::BacklogWaitTime => b"audit_backlog_wait_time",
        }
    }

    /// # C: O(1)
    pub fn get(self, c: &Config) -> u32 {
        match self {
            Field::Enabled => c.enabled,
            Field::Failure => c.failure,
            Field::RateLimit => c.rate_limit,
            Field::BacklogLimit => c.backlog_limit,
            Field::BacklogWaitTime => c.backlog_wait_time,
        }
    }

    /// Whether `v` is a value this field can hold at all. Independent of who
    /// is asking: an illegal value is illegal even for a caller that would
    /// have been allowed to set a legal one.
    /// # C: O(1)
    pub fn validate(self, v: u32) -> Result<(), Errno> {
        match self {
            Field::Enabled if v > AUDIT_LOCKED => Err(Errno::Einval),
            Field::Failure if v != AUDIT_FAIL_SILENT && v != AUDIT_FAIL_PRINTK
                && v != AUDIT_FAIL_PANIC => Err(Errno::Einval),
            // A producer parked on a full backlog is a producer not making
            // progress, so the wait is bounded well above the default but not
            // unbounded.
            Field::BacklogWaitTime if v > AUDIT_BACKLOG_WAIT_TIME_MAX => Err(Errno::Einval),
            _ => Ok(()),
        }
    }

    /// # C: O(1)
    fn store(self, c: &mut Config, v: u32) {
        match self {
            Field::Enabled => c.enabled = v,
            Field::Failure => c.failure = v,
            Field::RateLimit => c.rate_limit = v,
            Field::BacklogLimit => c.backlog_limit = v,
            Field::BacklogWaitTime => c.backlog_wait_time = v,
        }
    }
}

/// Apply one configuration change: legal value first, then permission.
///
/// The two steps are ordered so that a locked configuration still reports an
/// illegal value as illegal — a client learns its request was malformed rather
/// than being told it lacked a permission it would not have needed.
/// # C: O(1)
pub fn set(c: &mut Config, f: Field, v: u32) -> Result<(), Errno> {
    f.validate(v)?;
    if c.locked() { return Err(Errno::Eperm); }
    f.store(c, v);
    Ok(())
}

/// One requested feature change, decoded from `struct audit_features`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FeatureRequest {
    pub vers: u32,
    pub mask: u32,
    pub features: u32,
    pub lock: u32,
}

/// Apply a feature request.
///
/// Validated in full before anything is committed: a request naming two
/// features, one of them locked, must change neither. A locked feature may be
/// re-requested at its current value — that is not a change — but any attempt
/// to move it is EPERM. Locking is applied along with the values, and is
/// cumulative.
/// # C: O(N_features)
pub fn apply_features(cfg: &mut Config, req: FeatureRequest) -> Result<(), Errno> {
    for i in 0..=AUDIT_LAST_FEATURE {
        let bit = feature_to_mask(i);
        if bit & req.mask == 0 { continue; }
        if (cfg.feature_lock & bit) != 0 && (req.features & bit) != (cfg.features & bit) {
            return Err(Errno::Eperm);
        }
    }
    for i in 0..=AUDIT_LAST_FEATURE {
        let bit = feature_to_mask(i);
        if bit & req.mask == 0 { continue; }
        if req.features & bit != 0 { cfg.features |= bit; } else { cfg.features &= !bit; }
        cfg.feature_lock |= req.lock & bit;
    }
    let _ = req.vers;
    Ok(())
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
