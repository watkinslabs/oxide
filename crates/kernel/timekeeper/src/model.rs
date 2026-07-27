pub(crate) const NSEC_PER_SEC: i128 = 1_000_000_000;
pub const MAX_TAI_OFFSET: i32 = 100_000;
/// `KTIME_SEC_MAX` — the largest wall second representable as a `ktime_t`.
/// A proposed time at or past it is rejected rather than clamped, matching
/// `timespec64_valid_settod()`.
pub(crate) const KTIME_SEC_MAX: i128 = (i64::MAX / 1_000_000_000) as i128;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TimeError { Range }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ClockSnapshot {
    pub wall_offset_ns: i128,
    pub suspend_ns: u64,
    pub tai_offset_sec: i32,
    pub realtime_generation: u64,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ClockState {
    pub wall_offset_ns: i128,
    pub suspend_ns: u64,
    pub tai_offset_sec: i32,
    pub realtime_generation: u64,
}

fn clamp_ns(value: i128) -> u64 { value.clamp(0, u64::MAX as i128) as u64 }

impl ClockState {
    pub const ZERO: Self = Self {
        wall_offset_ns: 0, suspend_ns: 0, tai_offset_sec: 0, realtime_generation: 0,
    };

    pub fn snapshot(self) -> ClockSnapshot {
        ClockSnapshot { wall_offset_ns: self.wall_offset_ns, suspend_ns: self.suspend_ns,
            tai_offset_sec: self.tai_offset_sec,
            realtime_generation: self.realtime_generation }
    }

    pub fn realtime(self, mono_ns: u64) -> u64 {
        clamp_ns(i128::from(mono_ns) + self.wall_offset_ns)
    }

    pub fn boottime(self, mono_ns: u64) -> u64 { mono_ns.saturating_add(self.suspend_ns) }

    pub fn tai(self, mono_ns: u64) -> u64 {
        clamp_ns(i128::from(self.realtime(mono_ns))
            + i128::from(self.tai_offset_sec) * NSEC_PER_SEC)
    }

    pub fn set_realtime(&mut self, mono_ns: u64, target_ns: u64) {
        self.wall_offset_ns = i128::from(target_ns) - i128::from(mono_ns);
        self.realtime_generation = self.realtime_generation.wrapping_add(1);
    }

    /// `__timekeeping_inject_offset()` — shift the wall clock by a signed
    /// delta, rejecting a result that is not a valid settable time. Counts as
    /// a STEP, so the generation advances and absolute deadlines reproject.
    pub fn inject_offset(&mut self, mono_ns: u64, delta_ns: i128) -> Result<(), TimeError> {
        let target = i128::from(mono_ns) + self.wall_offset_ns + delta_ns;
        if target < 0 || target >= KTIME_SEC_MAX * NSEC_PER_SEC { return Err(TimeError::Range); }
        self.wall_offset_ns += delta_ns;
        self.realtime_generation = self.realtime_generation.wrapping_add(1);
        Ok(())
    }

    /// Continuous NTP discipline: nudge the wall clock without declaring a
    /// step. The generation is deliberately NOT bumped — a slew is what NTP
    /// does instead of a step precisely so absolute CLOCK_REALTIME deadlines
    /// and `TFD_TIMER_CANCEL_ON_SET` consumers are not disturbed.
    pub fn slew(&mut self, delta_ns: i64) {
        self.wall_offset_ns += i128::from(delta_ns);
    }

    pub fn set_tai_offset(&mut self, seconds: i32) -> Result<(), TimeError> {
        if !(0..=MAX_TAI_OFFSET).contains(&seconds) { return Err(TimeError::Range); }
        self.tai_offset_sec = seconds;
        Ok(())
    }

    pub fn account_suspend(&mut self, elapsed_ns: u64) {
        self.suspend_ns = self.suspend_ns.saturating_add(elapsed_ns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_are_distinct_and_realtime_step_preserves_monotonic_boottime() {
        let mut state = ClockState::ZERO;
        state.account_suspend(40);
        state.set_realtime(100, 1_000);
        state.set_tai_offset(37).unwrap();
        assert_eq!(state.realtime(125), 1_025);
        assert_eq!(state.boottime(125), 165);
        assert_eq!(state.tai(125), 37_000_001_025);
        state.set_realtime(125, 500);
        assert_eq!(state.realtime(125), 500);
        assert_eq!(state.boottime(125), 165);
        assert_eq!(state.tai(125), 37_000_000_500);
    }

    #[test]
    fn tai_adjustment_is_validated_and_changes_only_tai() {
        let mut state = ClockState::ZERO;
        state.set_realtime(10, 100);
        let real = state.realtime(20);
        let boot = state.boottime(20);
        assert_eq!(state.set_tai_offset(-1), Err(TimeError::Range));
        assert_eq!(state.set_tai_offset(MAX_TAI_OFFSET + 1), Err(TimeError::Range));
        let generation = state.realtime_generation;
        state.set_tai_offset(12).unwrap();
        assert_eq!(state.realtime(20), real);
        assert_eq!(state.boottime(20), boot);
        assert_eq!(state.tai(20), real + 12_000_000_000);
        assert_eq!(state.realtime_generation, generation);
    }

    #[test]
    fn suspend_accounting_saturates_without_advancing_realtime() {
        let mut state = ClockState::ZERO;
        state.account_suspend(u64::MAX - 5);
        state.account_suspend(10);
        assert_eq!(state.boottime(7), u64::MAX);
        assert_eq!(state.realtime(7), 7);
    }
}
