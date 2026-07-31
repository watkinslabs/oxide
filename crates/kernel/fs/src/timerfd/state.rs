//! Canonical lock-protected timerfd transaction state.

use vfs::VfsError;

use super::uapi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TimerfdState {
    /// Next expiry in realtime ns when `realtime_absolute`, otherwise in the
    /// host monotonic deadline domain.
    pub expiry_ns:           u64,
    pub interval_ns:         u64,
    pub ticks:               u64,
    pub clock_generation_seen: u64,
    pub cancel_enabled:      bool,
    pub cancel_pending:      bool,
    pub realtime_absolute:   bool,
    /// `TFD_SETTIME_FLAGS` retained from the last arm, for `fdinfo` only.
    pub settime_flags:       u16,
    /// Derived host-monotonic deadline retained across a wall-clock step so
    /// an already-crossed expiration cannot be lost by backward reprojection.
    pub realtime_projection_ns: u64,
}

impl TimerfdState {
    /// Build a disarmed test state at clock generation zero. # C: O(1)
    #[cfg(test)]
    pub const fn disarmed() -> Self {
        Self::new(0)
    }

    /// Build a disarmed state at the observed clock generation. # C: O(1)
    pub const fn new(clock_generation_seen: u64) -> Self {
        Self {
            expiry_ns: 0,
            interval_ns: 0,
            ticks: 0,
            clock_generation_seen,
            cancel_enabled: false,
            cancel_pending: false,
            realtime_absolute: false,
            settime_flags: 0,
            realtime_projection_ns: 0,
        }
    }

    /// Linux `TFD_IOC_SET_TICKS`: inject an expiration count without touching
    /// the armed deadline. A pending clock-step cancellation is consumed and
    /// reported instead — the count would be meaningless across a step.
    /// # C: O(1)
    pub fn set_ticks(&mut self, ticks: u64) -> Result<(), VfsError> {
        if self.cancel_pending {
            self.cancel_pending = false;
            return Err(VfsError::Ecanceled);
        }
        self.ticks = ticks;
        Ok(())
    }

    /// Materialize through the exact old-domain step boundary, then reproject
    /// at the current post-step clock sample.
    /// # C: O(1)
    pub fn note_clock_was_set(
        &mut self,
        generation: u64,
        step_mono_ns: u64,
        now_mono: u64,
        now_real: u64,
    ) -> bool {
        if self.clock_generation_seen == generation { return false; }
        self.materialize_realtime_projection(step_mono_ns);
        self.clock_generation_seen = generation;
        if self.realtime_absolute {
            self.realtime_projection_ns = self.project_realtime(now_mono, now_real);
            self.refresh_expirations(now_mono, now_real);
            self.realtime_projection_ns = self.project_realtime(now_mono, now_real);
        }
        if !self.cancel_enabled { return false; }
        self.cancel_pending = true;
        true
    }

    fn clock_now(&self, now_mono: u64, now_real: u64) -> u64 {
        if self.realtime_absolute { now_real } else { now_mono }
    }

    fn project_realtime(&self, now_mono: u64, now_real: u64) -> u64 {
        if self.expiry_ns == 0 {
            0
        } else {
            super::model::realtime_deadline(self.expiry_ns, now_mono, now_real)
        }
    }

    fn materialize_realtime_projection(&mut self, now_mono: u64) {
        let projection = self.realtime_projection_ns;
        if !self.realtime_absolute || projection == 0 || now_mono < projection {
            return;
        }
        let count = if self.interval_ns == 0 { 1 } else {
            ((now_mono - projection) / self.interval_ns) + 1
        };
        self.ticks = self.ticks.saturating_add(count);
        if self.interval_ns == 0 {
            self.expiry_ns = 0;
            self.realtime_projection_ns = 0;
        } else {
            let advance = self.interval_ns.saturating_mul(count);
            self.expiry_ns = self.expiry_ns.saturating_add(advance)
                .min(syscall::time::KTIME_MAX_NS);
            self.realtime_projection_ns = projection.saturating_add(advance)
                .min(syscall::time::KTIME_MAX_NS);
        }
    }

    /// Return the host-monotonic deadline used by wait and poll. # C: O(1)
    pub fn projected_expiry(&self, now_mono: u64, now_real: u64) -> u64 {
        if self.expiry_ns == 0 {
            0
        } else if self.realtime_absolute {
            if self.realtime_projection_ns != 0 {
                self.realtime_projection_ns
            } else {
                self.project_realtime(now_mono, now_real)
            }
        } else {
            self.expiry_ns
        }
    }

    /// Accumulate every expiration reached in the active clock domain. # C: O(1)
    pub fn refresh_expirations(&mut self, now_mono: u64, now_real: u64) {
        self.materialize_realtime_projection(now_mono);
        let expiry = self.expiry_ns;
        let now = self.clock_now(now_mono, now_real);
        if expiry == 0 {
            self.realtime_projection_ns = 0;
            return;
        }
        if now < expiry { return; }
        let count = if self.interval_ns == 0 { 1 } else {
            ((now - expiry) / self.interval_ns) + 1
        };
        self.ticks = self.ticks.saturating_add(count);
        self.expiry_ns = if self.interval_ns == 0 { 0 } else {
            expiry.saturating_add(self.interval_ns.saturating_mul(count))
                .min(syscall::time::KTIME_MAX_NS)
        };
        if self.realtime_absolute {
            self.realtime_projection_ns = self.project_realtime(now_mono, now_real);
        }
    }

    /// Snapshot remaining time while preserving accumulated ticks. # C: O(1)
    pub fn snapshot(&mut self, now_mono: u64, now_real: u64) -> uapi::Itimerspec {
        self.refresh_expirations(now_mono, now_real);
        uapi::Itimerspec {
            interval_ns: self.interval_ns,
            value_ns: self.expiry_ns.saturating_sub(self.clock_now(now_mono, now_real)),
        }
    }

    /// Replace all timer state and report the forwarded old value. # C: O(1)
    pub fn replace(
        &mut self,
        now_mono: u64,
        now_real: u64,
        mut replacement: Self,
    ) -> uapi::Itimerspec {
        let old = self.snapshot(now_mono, now_real);
        if replacement.realtime_absolute && replacement.expiry_ns != 0
            && replacement.realtime_projection_ns == 0 {
            replacement.realtime_projection_ns =
                replacement.project_realtime(now_mono, now_real);
        }
        *self = replacement;
        old
    }

    /// Install an armed or disarmed state as one transaction. # C: O(1)
    pub fn install(
        &mut self,
        now_mono: u64,
        now_real: u64,
        expiry_ns: u64,
        interval_ns: u64,
        cancel_enabled: bool,
        realtime_absolute: bool,
        settime_flags: u16,
    ) -> (uapi::Itimerspec, bool) {
        let pending_cancel = self.cancel_pending;
        let replacement = Self {
            expiry_ns,
            interval_ns,
            ticks: 0,
            clock_generation_seen: self.clock_generation_seen,
            cancel_enabled,
            cancel_pending: cancel_enabled && pending_cancel && expiry_ns == 0,
            realtime_absolute,
            settime_flags,
            realtime_projection_ns: if realtime_absolute && expiry_ns != 0 {
                super::model::realtime_deadline(expiry_ns, now_mono, now_real)
            } else { 0 },
        };
        let old = self.replace(now_mono, now_real, replacement);
        let canceled = cancel_enabled && expiry_ns != 0 && pending_cancel;
        (old, canceled)
    }

    /// Consume cancellation or the complete accumulated tick count. # C: O(1)
    pub fn take_expirations(
        &mut self,
        now_mono: u64,
        now_real: u64,
    ) -> Result<Option<u64>, VfsError> {
        if self.cancel_pending {
            let had_expirations = self.ticks != 0;
            self.cancel_pending = false;
            self.ticks = 0;
            if had_expirations || (self.expiry_ns != 0
                && self.clock_now(now_mono, now_real) >= self.expiry_ns) {
                self.expiry_ns = 0;
                self.realtime_projection_ns = 0;
            }
            return Err(VfsError::Ecanceled);
        }
        self.refresh_expirations(now_mono, now_real);
        if self.ticks == 0 { return Ok(None); }
        let ticks = self.ticks;
        self.ticks = 0;
        Ok(Some(ticks))
    }
}
