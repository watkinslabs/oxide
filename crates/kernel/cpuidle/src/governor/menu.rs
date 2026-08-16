// `menu`: predict how long this idle will last, then pick the deepest state
// that pays for itself over that long.
//
// Two predictors, combined by taking the shorter. The first scales the time to
// the next known timer by a correction factor learned per duration bucket —
// timers are an upper bound on the sleep, and the factor records how much
// shorter reality usually is. The second looks for a repeating interval in the
// recent history, which catches a periodic wakeup the timer subsystem knows
// nothing about, such as a device interrupt.

use crate::limits::{ns_to_us, us_to_ns, MAX_INTERESTING_NS, RESIDENCY_THRESHOLD_NS};

use super::input::{deepest_fitting, enabled, may_stop_tick, shallower_fitting,
                   shallowest_enabled, Reflection, SelectInput, Selection};

/// Duration buckets the correction factor is learned per. A prediction error
/// on a microsecond sleep says nothing about a millisecond one.
pub const BUCKETS: usize = 6;
/// Recent intervals kept for the repeat detector.
pub const INTERVALS: usize = 8;
/// Fixed-point scale of the correction factor.
pub const RESOLUTION: u64 = 1024;
/// How fast the correction factor forgets: one part in this per update.
pub const DECAY: u64 = 8;

/// Upper edge of each bucket, microseconds; the last bucket has none.
const BUCKET_EDGES_US: [u64; BUCKETS - 1] = [10, 100, 1_000, 10_000, 100_000];

/// Which bucket a duration falls in. # C: O(BUCKETS)
pub fn which_bucket(duration_ns: u64) -> usize {
    let us = ns_to_us(duration_ns);
    BUCKET_EDGES_US.iter().position(|edge| us < *edge).unwrap_or(BUCKETS - 1)
}

/// The learned per-CPU predictor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MenuState {
    /// Ratio of measured sleep to predicted sleep, scaled by
    /// `RESOLUTION * DECAY`, one per bucket.
    pub correction: [u64; BUCKETS],
    /// Recent measured intervals, nanoseconds; `u64::MAX` marks a slot that
    /// carries no usable sample.
    pub intervals: [u64; INTERVALS],
    pub interval_ptr: usize,
    pub bucket: usize,
    /// Time to the next timer at the last selection, nanoseconds.
    pub next_timer_ns: u64,
    /// Whether a completed sleep is waiting to be learned from.
    pub needs_update: bool,
    pub tick_wakeup: bool,
    pub last_state: Option<usize>,
}

impl Default for MenuState {
    /// A fresh predictor assumes it predicts perfectly, and learns otherwise.
    /// # C: O(1)
    fn default() -> MenuState {
        MenuState {
            correction: [RESOLUTION * DECAY; BUCKETS],
            intervals: [u64::MAX; INTERVALS],
            interval_ptr: 0,
            bucket: 0,
            next_timer_ns: u64::MAX,
            needs_update: false,
            tick_wakeup: false,
            last_state: None,
        }
    }
}

impl MenuState {
    /// Record one measured interval. # C: O(1)
    fn push_interval(&mut self, interval_ns: u64) {
        self.intervals[self.interval_ptr] = interval_ns;
        self.interval_ptr = (self.interval_ptr + 1) % INTERVALS;
    }

    /// A repeating interval in the recent history, or `None` when the samples
    /// are too scattered to be one.
    ///
    /// The rule: keep discarding whichever extreme sits furthest from the mean
    /// until what remains is tight — either its standard deviation is small
    /// outright, or the mean is at least six deviations above zero. Give up
    /// once a quarter of the samples have been discarded, because a series
    /// that needs that much trimming has no repeat in it. # C: O(INTERVALS²)
    pub fn typical_interval(&self) -> Option<u64> {
        let mut min_thresh = 0u64;
        let mut max_thresh = u64::MAX;
        loop {
            let mut sum = 0u64;
            let mut count = 0u64;
            let mut max = 0u64;
            for value in self.intervals.iter().copied() {
                if value == u64::MAX || value <= min_thresh || value >= max_thresh { continue; }
                sum += value;
                count += 1;
                if value > max { max = value; }
            }
            if count == 0 { return None; }
            let avg = sum / count;
            let variance = self.intervals.iter().copied()
                .filter(|v| *v != u64::MAX && *v > min_thresh && *v < max_thresh)
                .map(|v| { let d = v.abs_diff(avg); d.saturating_mul(d) })
                .fold(0u64, |acc, d| acc.saturating_add(d)) / count;
            let tight = variance <= us_to_ns(20).saturating_mul(us_to_ns(20))
                || avg.saturating_mul(avg) > variance.saturating_mul(36);
            if tight && count * 4 >= INTERVALS as u64 * 3 { return Some(avg); }
            if count * 4 <= INTERVALS as u64 * 3 { return None; }
            // Trim from whichever side is further from the mean.
            let min = self.intervals.iter().copied()
                .filter(|v| *v != u64::MAX && *v > min_thresh && *v < max_thresh)
                .min().unwrap_or(avg);
            if avg - min > max - avg { min_thresh = min; } else { max_thresh = max; }
            if min_thresh >= max_thresh { return None; }
        }
    }

    /// Learn from the sleep that just ended. # C: O(1)
    pub fn update(&mut self, states: &[crate::state::IdleState], reflection: &Reflection) {
        let Some(entered) = reflection.entered else { return; };
        let Some(state) = states.get(entered) else { return; };
        let mut measured = if reflection.tick_wakeup && self.next_timer_ns > MAX_INTERESTING_NS {
            // A tick wakeup on a CPU whose next timer was far away says only
            // that the sleep was long; taking the tick period as the length
            // would train the predictor to be far too pessimistic.
            MAX_INTERESTING_NS / 10 * 9
        } else if state.polling() && reflection.poll_time_limit {
            self.next_timer_ns
        } else {
            let raw = reflection.measured_ns;
            if raw > state.exit_latency_ns.saturating_mul(2) { raw - state.exit_latency_ns }
            else { raw / 2 }
        };
        if measured > self.next_timer_ns { measured = self.next_timer_ns; }

        let factor = &mut self.correction[self.bucket];
        *factor -= *factor / DECAY;
        if self.next_timer_ns > 0 && self.next_timer_ns != u64::MAX
            && measured < MAX_INTERESTING_NS
        {
            *factor += RESOLUTION.saturating_mul(measured) / self.next_timer_ns;
        } else {
            *factor += RESOLUTION;
        }
        self.push_interval(measured);
    }
}

/// Choose a state. # C: O(N_states + INTERVALS²)
pub fn select(state: &mut MenuState, input: &SelectInput, states_len: usize) -> Selection {
    let _ = states_len;
    if state.needs_update { state.needs_update = false; }

    let repeat = state.typical_interval();
    let mut predicted_ns = repeat.unwrap_or(u64::MAX);

    if predicted_ns > RESIDENCY_THRESHOLD_NS || input.tick_stopped {
        let delta = input.sleep_length_ns;
        state.next_timer_ns = delta;
        state.bucket = which_bucket(delta);
        if delta != u64::MAX {
            let scaled = mul_div_round(delta, state.correction[state.bucket],
                                       RESOLUTION * DECAY);
            predicted_ns = predicted_ns.min(scaled);
        }
    } else {
        state.next_timer_ns = u64::MAX;
        state.bucket = BUCKETS - 1;
    }

    let shallowest = shallowest_enabled(input);
    if input.latency_req_ns == 0 { return Selection { index: shallowest, stop_tick: false }; }
    if input.states.len() > 1 && enabled(input, 0) {
        let second = &input.states[1];
        if state.next_timer_ns < second.target_residency_ns
            || input.latency_req_ns < second.exit_latency_ns
        {
            return Selection { index: 0, stop_tick: !input.states[0].polling() };
        }
    }

    let index = deepest_fitting(input, predicted_ns).unwrap_or(shallowest);
    finish(input, index, predicted_ns)
}

/// Apply the tick constraint to a chosen state. With the tick running, a state
/// that needs longer than the tick period to pay for itself will be cut short
/// by the tick, so the choice is corrected down to one that fits. # C: O(N)
fn finish(input: &SelectInput, index: usize, predicted_ns: u64) -> Selection {
    let stop_tick = may_stop_tick(input, index, predicted_ns);
    if stop_tick { return Selection { index, stop_tick }; }
    if index > 0 && input.states[index].target_residency_ns > input.tick_ns {
        let corrected = shallower_fitting(input, index, input.tick_ns);
        return Selection { index: corrected, stop_tick: false };
    }
    Selection { index, stop_tick: false }
}

/// `value * numerator / denominator`, rounded to nearest, without overflowing
/// on a `u64::MAX` sleep length. # C: O(1)
fn mul_div_round(value: u64, numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 { return value; }
    match value.checked_mul(numerator) {
        Some(product) => (product + denominator / 2) / denominator,
        None => (value / denominator).saturating_mul(numerator),
    }
}

/// Take the outcome of the sleep that just ended. # C: O(1)
pub fn reflect(state: &mut MenuState, states: &[crate::state::IdleState],
               reflection: &Reflection)
{
    state.last_state = reflection.entered;
    state.tick_wakeup = reflection.tick_wakeup;
    match reflection.entered {
        Some(_) => { state.update(states, reflection); state.needs_update = true; }
        // A refused entry taught the predictor nothing about how long the CPU
        // would have slept, so the slot records "no usable sample" rather than
        // a zero that would drag the average down.
        None => state.push_interval(u64::MAX),
    }
}

#[cfg(test)]
#[path = "../tests/menu.rs"]
mod tests;
