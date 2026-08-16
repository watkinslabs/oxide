// `teo`: timer-event oriented. Rather than predicting a duration, it counts
// how the last several sleeps ended and picks the state those counts point at.
//
// One bin per state, each holding two counters. A `hit` means the sleep ran to
// the timer the kernel knew about; an `intercept` means something else woke the
// CPU first. A CPU whose sleeps are mostly intercepted should not be trusting
// the timer, so the selection is pulled shallower by exactly as much as the
// intercept counts outweigh the hits.

use crate::limits::{LATENCY_THRESHOLD_NS, RESIDENCY_THRESHOLD_NS};
use crate::state::IdleState;

use super::input::{deepest_within_latency, enabled, may_stop_tick, shallower_fitting,
                   shallowest_enabled, Reflection, SelectInput, Selection};

/// One count, in the fixed-point scale the counters decay in.
pub const PULSE: u64 = 1024;
/// How fast a count is forgotten: one part in eight per update.
pub const DECAY_SHIFT: u32 = 3;

/// The two counters of one state's bin.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Bin { pub hits: u64, pub intercepts: u64 }

/// The learned per-CPU predictor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeoState {
    pub bins: [Bin; crate::limits::MAX_STATES],
    /// Total of every bin's counters, plus one pulse per update.
    pub total: u64,
    /// Sleeps ending within the short-idle threshold.
    pub short_idles: u64,
    /// Intercepts that happened inside one tick period.
    pub tick_intercepts: u64,
    /// Sleeps ended by the tick itself.
    pub total_tick: u64,
    pub tick_wakeup: bool,
    /// Sleep length at the last selection, nanoseconds.
    pub sleep_length_ns: u64,
    pub last_state: Option<usize>,
}

impl Default for TeoState {
    /// # C: O(1)
    fn default() -> TeoState {
        TeoState {
            bins: [Bin::default(); crate::limits::MAX_STATES],
            total: 0,
            short_idles: 0,
            tick_intercepts: 0,
            total_tick: 0,
            tick_wakeup: false,
            sleep_length_ns: u64::MAX,
            last_state: None,
        }
    }
}

/// Forget one eighth of a count, and the last of it once the eighth is zero.
/// # C: O(1)
pub fn decay(metric: u64) -> u64 {
    let delta = metric >> DECAY_SHIFT;
    if delta != 0 { metric - delta } else { 0 }
}

impl TeoState {
    /// Fold one completed sleep into the counters. # C: O(N_states)
    pub fn update(&mut self, states: &[IdleState], reflection: &Reflection, tick_ns: u64) {
        let Some(entered) = reflection.entered else { return; };
        let Some(state) = states.get(entered) else { return; };
        let latency = state.exit_latency_ns;
        self.short_idles = decay(self.short_idles);

        let measured = if reflection.poll_time_limit {
            i64::MAX as u64
        } else if reflection.measured_ns >= latency {
            let net = reflection.measured_ns - latency / 2;
            if net < RESIDENCY_THRESHOLD_NS { self.short_idles += PULSE; }
            net
        } else {
            self.short_idles += PULSE;
            reflection.measured_ns / 2
        };

        let mut total = 0;
        let mut idx_timer = 0;
        let mut idx_duration = 0;
        for (index, state) in states.iter().enumerate() {
            let bin = &mut self.bins[index];
            bin.hits = decay(bin.hits);
            bin.intercepts = decay(bin.intercepts);
            total += bin.hits + bin.intercepts;
            if state.target_residency_ns <= self.sleep_length_ns { idx_timer = index; }
            if state.target_residency_ns <= measured { idx_duration = index; }
        }
        self.total = total + PULSE;
        self.tick_intercepts = decay(self.tick_intercepts);
        self.total_tick = decay(self.total_tick);

        if reflection.tick_wakeup {
            self.total_tick += PULSE;
            if 3 * self.total_tick > 2 * self.total {
                let deepest = states.len().saturating_sub(1);
                self.bins[deepest].hits += PULSE;
                return;
            }
            if 3 * self.tick_intercepts < 2 * self.total {
                self.bins[idx_timer].hits += PULSE;
                return;
            }
        }

        let close = self.sleep_length_ns.saturating_sub(measured) < latency / 2;
        if idx_timer == idx_duration && close {
            self.bins[idx_timer].hits += PULSE;
        } else {
            self.bins[idx_duration].intercepts += PULSE;
            if measured <= tick_ns { self.tick_intercepts += PULSE; }
        }
    }
}

/// Choose a state. # C: O(N_states)
pub fn select(state: &mut TeoState, input: &SelectInput) -> Selection {
    state.sleep_length_ns = input.sleep_length_ns;
    let first = shallowest_enabled(input);
    let constraint = deepest_within_latency(input);
    let Some(constraint) = constraint else {
        return Selection { index: first, stop_tick: false };
    };

    // Deepest enabled state, and the intercept weight of everything shallower.
    let mut index = first;
    let mut idx_intercepts = 0;
    let mut idx_hits = 0;
    let mut running_intercepts = 0;
    let mut running_hits = 0;
    let mut intercept_max = 0;
    let mut intercept_max_idx = first;
    for candidate in 1..input.states.len() {
        let bin = state.bins[candidate - 1];
        running_intercepts += bin.intercepts;
        running_hits += bin.hits;
        if bin.intercepts >= intercept_max {
            intercept_max = bin.intercepts;
            intercept_max_idx = candidate - 1;
        }
        if !enabled(input, candidate) { continue; }
        index = candidate;
        idx_intercepts = running_intercepts;
        idx_hits = running_hits;
    }

    if index == first {
        let duration = input.states.get(index)
            .map_or(0, |state| state.target_residency_ns);
        return finish(input, index, duration);
    }

    // Intercepts among the shallower states outweighing this candidate's own
    // evidence means the CPU is not sleeping as long as the timer says.
    if 2 * idx_intercepts > state.total.saturating_sub(idx_hits) {
        let mut accumulated = 0;
        for candidate in (first..index).rev() {
            accumulated += state.bins[candidate].intercepts;
            if !enabled(input, candidate) { continue; }
            index = candidate;
            if 2 * accumulated > idx_intercepts && candidate <= intercept_max_idx { break; }
        }
    }
    if index > constraint { index = constraint; }

    let short = index == first
        || input.states[index].target_residency_ns < RESIDENCY_THRESHOLD_NS;
    if !input.tick_stopped && short
        && (2 * state.short_idles >= state.total
            || input.latency_req_ns < LATENCY_THRESHOLD_NS)
    {
        return Selection { index, stop_tick: false };
    }

    let mut duration = input.sleep_length_ns;
    if index > 0 && input.states[index].target_residency_ns > duration {
        index = shallower_fitting(input, index, duration);
    }
    if state.total > 0 && input.states[index].target_residency_ns < input.tick_ns
        && 3 * state.tick_intercepts >= 2 * state.total
    {
        duration = input.tick_ns / 2;
    }
    finish(input, index, duration)
}

/// Apply the tick constraint. # C: O(N_states)
fn finish(input: &SelectInput, index: usize, duration_ns: u64) -> Selection {
    if may_stop_tick(input, index, duration_ns) {
        return Selection { index, stop_tick: true };
    }
    let first = shallowest_enabled(input);
    if index > first && input.states[index].target_residency_ns > input.tick_ns {
        return Selection { index: shallower_fitting(input, index, input.tick_ns),
                           stop_tick: false };
    }
    Selection { index, stop_tick: false }
}

/// Take the outcome of the sleep that just ended. # C: O(N_states)
pub fn reflect(state: &mut TeoState, states: &[IdleState], reflection: &Reflection,
               tick_ns: u64)
{
    state.tick_wakeup = reflection.tick_wakeup;
    state.last_state = reflection.entered;
    state.update(states, reflection, tick_ns);
}

#[cfg(test)]
#[path = "../tests/teo.rs"]
mod tests;
