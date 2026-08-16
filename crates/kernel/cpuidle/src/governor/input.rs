// What a governor decides from, what it returns, and the state-table scan
// every governor shares.

use crate::state::IdleState;
use crate::usage::StateUsage;

/// Everything a governor may look at when the CPU goes idle.
#[derive(Copy, Clone)]
pub struct SelectInput<'a> {
    pub states: &'a [IdleState],
    pub usage: &'a [StateUsage],
    /// Time until the next event the kernel already knows about,
    /// nanoseconds. `u64::MAX` where nothing is scheduled.
    pub sleep_length_ns: u64,
    /// Period of the periodic tick, nanoseconds. A state whose residency
    /// exceeds it cannot pay for itself while the tick keeps firing.
    pub tick_ns: u64,
    /// Deepest wakeup latency anything on this CPU will tolerate,
    /// nanoseconds.
    pub latency_req_ns: u64,
    /// Whether the periodic tick is currently suppressed.
    pub tick_stopped: bool,
}

/// A governor's answer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    /// Index into the state table.
    pub index: usize,
    /// Whether the periodic tick may be suppressed for this sleep.
    pub stop_tick: bool,
}

/// What actually happened, handed back after the CPU wakes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Reflection {
    /// State the driver actually entered, or `None` when it refused.
    pub entered: Option<usize>,
    /// Measured residency, nanoseconds.
    pub measured_ns: u64,
    /// Whether the periodic tick is what woke the CPU.
    pub tick_wakeup: bool,
    /// Whether a polling state gave up on its own time limit rather than
    /// being woken.
    pub poll_time_limit: bool,
}

/// Whether state `index` may be selected. # C: O(1)
pub fn enabled(input: &SelectInput, index: usize) -> bool {
    input.usage.get(index).is_some_and(StateUsage::enabled)
}

/// Shallowest enabled state, which is where a governor with no better answer
/// lands. # C: O(N_states)
pub fn shallowest_enabled(input: &SelectInput) -> usize {
    (0..input.states.len()).find(|index| enabled(input, *index)).unwrap_or(0)
}

/// Deepest enabled state whose wakeup cost the latency requirement allows.
/// # C: O(N_states)
pub fn deepest_within_latency(input: &SelectInput) -> Option<usize> {
    (0..input.states.len()).rev()
        .find(|index| enabled(input, *index)
            && input.states[*index].exit_latency_ns <= input.latency_req_ns)
}

/// Deepest enabled state worth entering for a sleep of `duration_ns` that also
/// meets the latency requirement. The scan stops at the first state too costly
/// to leave, because the table is ordered and everything past it is worse on
/// both counts. # C: O(N_states)
pub fn deepest_fitting(input: &SelectInput, duration_ns: u64) -> Option<usize> {
    let mut best = None;
    for index in 0..input.states.len() {
        let state = &input.states[index];
        if state.exit_latency_ns > input.latency_req_ns { break; }
        if !enabled(input, index) { continue; }
        if state.target_residency_ns > duration_ns {
            if best.is_none() { best = Some(index); }
            break;
        }
        best = Some(index);
    }
    best
}

/// Nearest enabled state at or below `from` that fits inside `duration_ns`.
/// # C: O(N_states)
pub fn shallower_fitting(input: &SelectInput, from: usize, duration_ns: u64) -> usize {
    let mut chosen = from;
    for index in (0..from).rev() {
        if !enabled(input, index) { continue; }
        chosen = index;
        if input.states[index].target_residency_ns <= duration_ns { break; }
    }
    chosen
}

/// Whether the tick may be suppressed for a sleep of `duration_ns` entering
/// `index`. A spin state never justifies it — the CPU is not asleep — and
/// neither does a sleep shorter than the tick period, because the tick would
/// have fired inside it anyway. # C: O(1)
pub fn may_stop_tick(input: &SelectInput, index: usize, duration_ns: u64) -> bool {
    if input.tick_stopped { return true; }
    let Some(state) = input.states.get(index) else { return false; };
    !state.polling() && duration_ns >= input.tick_ns
}

#[cfg(test)]
#[path = "../tests/scan.rs"]
mod tests;
