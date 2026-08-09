// Sampling-period accounting — `perf_swevent_set_period`, `perf_swevent_event`
// and `perf_swevent_overflow`'s overflow count.
//
// Pure over `HwPeriod`: the sign-trick arithmetic (`period_left` is kept in
// `[-sample_period, 0]` so the sign is the trigger) is exactly the part a
// wrong reimplementation gets subtly wrong, and it is hosted-testable here.

use super::uapi::sample;

/// The period half of Linux's `struct hw_perf_event` for a software counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HwPeriod {
    pub sample_period: u64,
    pub last_period:   u64,
    /// Signed remaining budget; negative means "not yet due".
    pub period_left:   i64,
}

impl HwPeriod {
    /// `perf_event_alloc`'s initialisation followed by `perf_swevent_add`'s
    /// normalisation — the state a freshly scheduled-in sampling event has.
    /// # C: O(1)
    pub fn new(sample_period: u64) -> HwPeriod {
        let mut hw = HwPeriod { sample_period, last_period: sample_period,
                                period_left: sample_period as i64 };
        let _ = set_period(&mut hw);
        hw
    }
}

/// `perf_swevent_set_period` — fold the accumulated surplus back into
/// `[-period, 0)` and report how many whole periods it covered. # C: O(1)
pub fn set_period(hw: &mut HwPeriod) -> u64 {
    let period = hw.last_period;
    hw.last_period = hw.sample_period;
    if period == 0 { return 0; }
    let val = hw.period_left;
    if val < 0 { return 0; }
    let nr = (period + val as u64) / period;
    hw.period_left = val - (nr * period) as i64;
    nr
}

/// What one software-counter advance produced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Overflow {
    /// How many `PERF_RECORD_SAMPLE`s to emit (`perf_swevent_overflow`'s loop
    /// bound). Zero means the period is not yet exhausted.
    pub count:  u64,
    /// The value `PERF_SAMPLE_PERIOD` reports for those samples.
    pub period: u64,
}

/// `perf_swevent_event`'s decision, after the counter itself has been advanced
/// by `nr`. A non-sampling event never overflows, which is why a counting-only
/// `perf_event_open` produces no records at all. # C: O(1)
pub fn account(hw: &mut HwPeriod, sample_type: u64, freq: bool, nr: u64) -> Overflow {
    if hw.sample_period == 0 { return Overflow::default(); }
    // With `PERF_SAMPLE_PERIOD` on a period-driven event the record reports
    // the raw advance and fires immediately, rather than the configured period.
    if sample_type & sample::PERIOD != 0 && !freq {
        return Overflow { count: 1, period: nr };
    }
    let period = hw.last_period;
    if nr == 1 && hw.sample_period == 1 && !freq {
        return Overflow { count: 1, period };
    }
    hw.period_left = hw.period_left.wrapping_add(nr as i64);
    if hw.period_left < 0 { return Overflow { count: 0, period }; }
    Overflow { count: set_period(hw), period }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_normalises_the_budget_to_one_full_period_below_zero() {
        let hw = HwPeriod::new(100);
        assert_eq!(hw.period_left, -100);
        assert_eq!(hw.last_period, 100);
    }

    #[test]
    fn a_non_sampling_event_never_overflows() {
        let mut hw = HwPeriod::new(0);
        assert_eq!(account(&mut hw, 0, false, 1_000_000), Overflow::default());
    }

    #[test]
    fn one_sample_lands_every_period_events() {
        let mut hw = HwPeriod::new(4);
        let mut fired = 0;
        for _ in 0..16 { fired += account(&mut hw, 0, false, 1).count; }
        assert_eq!(fired, 4, "16 events at period 4");
        assert!(hw.period_left < 0);
    }

    #[test]
    fn a_burst_larger_than_the_period_reports_every_period_it_covered() {
        let mut hw = HwPeriod::new(10);
        // 35 events across a period of 10, from a budget of -10.
        let o = account(&mut hw, 0, false, 35);
        assert_eq!(o.count, 3);
        assert_eq!(o.period, 10);
        assert_eq!(hw.period_left, -5);
    }

    #[test]
    fn period_one_fires_on_every_single_event() {
        let mut hw = HwPeriod::new(1);
        for _ in 0..5 { assert_eq!(account(&mut hw, 0, false, 1).count, 1); }
    }

    #[test]
    fn sample_period_field_reports_the_raw_advance_and_fires_at_once() {
        let mut hw = HwPeriod::new(1000);
        let o = account(&mut hw, sample::PERIOD, false, 7);
        assert_eq!(o, Overflow { count: 1, period: 7 });
        assert_eq!(hw.period_left, -1000, "the budget is untouched on this path");
        // `attr.freq` takes the ordinary budget path instead.
        let o = account(&mut hw, sample::PERIOD, true, 7);
        assert_eq!(o.count, 0);
        assert_eq!(hw.period_left, -993);
    }

    /// Positive control for the sign trick: a budget that never goes
    /// non-negative must never fire.
    #[test]
    fn budget_short_of_the_period_produces_nothing() {
        let mut hw = HwPeriod::new(1_000_000);
        for _ in 0..999 { assert_eq!(account(&mut hw, 0, false, 1).count, 0); }
        assert_eq!(hw.period_left, -999_001);
    }
}
