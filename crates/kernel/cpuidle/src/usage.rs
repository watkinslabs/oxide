// Per-state accounting, and the two mispredict counters that make it useful.
//
// `above` and `below` are how a reader tells a governor that guesses well from
// one that does not: `above` counts sleeps that ended sooner than the state
// was worth, `below` counts sleeps long enough that a deeper state would have
// paid. Both are decisions, not measurements, and both are wrong in a way that
// looks plausible if the comparison uses the wrong duration.

use alloc::vec::Vec;

use crate::state::IdleState;
use crate::uapi::{DISABLED_BY_DRIVER, DISABLED_BY_USER};

/// Counters for one state on one CPU.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct StateUsage {
    /// Entries the driver accepted.
    pub usage: u64,
    /// Total measured residency, nanoseconds.
    pub time_ns: u64,
    /// Entries that ended before the state was worth entering.
    pub above: u64,
    /// Entries long enough that a deeper state would have fitted.
    pub below: u64,
    /// Entries the driver refused.
    pub rejected: u64,
    /// Why this state is unavailable, if it is.
    pub disable: u32,
}

impl StateUsage {
    /// Whether the state may be selected. # C: O(1)
    pub fn enabled(&self) -> bool { self.disable == 0 }

    /// Apply a write to `disable`. Only the user bit moves; a state the driver
    /// declared unusable stays unusable however hard userspace asks.
    /// # C: O(1)
    pub fn set_user_disable(&mut self, disable: bool) {
        if disable { self.disable |= DISABLED_BY_USER; }
        else { self.disable &= !DISABLED_BY_USER; }
    }

    /// What `disable` reads back: the user's own bit, not the driver's.
    /// # C: O(1)
    pub fn user_disabled(&self) -> bool { self.disable & DISABLED_BY_USER != 0 }

    /// Whether the driver pinned the state off. # C: O(1)
    pub fn driver_disabled(&self) -> bool { self.disable & DISABLED_BY_DRIVER != 0 }
}

/// Which mispredict, if either, one completed sleep was.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mispredict { None, Above, Below }

/// Classify one completed sleep.
///
/// Too deep (`Above`): the sleep ended short of the entered state's own target
/// residency, and a shallower state was available to have been chosen instead.
/// A state with nothing shallower enabled is not a mispredict — there was no
/// better answer.
///
/// Too shallow (`Below`): the sleep outlasted the entered state's exit
/// latency, and what remained after paying that latency would itself have
/// covered the next enabled deeper state's target residency. Only the nearest
/// enabled deeper state is consulted, because that is the one the governor
/// would have picked.
/// # C: O(N_states)
pub fn classify(states: &[IdleState], usage: &[StateUsage], entered: usize, measured_ns: u64)
    -> Mispredict
{
    let Some(state) = states.get(entered) else { return Mispredict::None; };
    if measured_ns < state.target_residency_ns {
        let shallower_available = usage[..entered].iter().rev().any(StateUsage::enabled);
        return if shallower_available { Mispredict::Above } else { Mispredict::None };
    }
    let latency = state.exit_latency_ns;
    if measured_ns <= latency { return Mispredict::None; }
    let resident = measured_ns - latency;
    let deeper = states.iter().enumerate().skip(entered + 1)
        .find(|(index, _)| usage.get(*index).is_some_and(|u| u.enabled()));
    match deeper {
        Some((_, deeper)) if resident >= deeper.target_residency_ns => Mispredict::Below,
        _ => Mispredict::None,
    }
}

/// Record one accepted entry. # C: O(N_states)
pub fn record_entry(states: &[IdleState], usage: &mut [StateUsage], entered: usize,
                    measured_ns: u64)
{
    let verdict = classify(states, usage, entered, measured_ns);
    let Some(slot) = usage.get_mut(entered) else { return; };
    slot.usage += 1;
    slot.time_ns = slot.time_ns.saturating_add(measured_ns);
    match verdict {
        Mispredict::Above => slot.above += 1,
        Mispredict::Below => slot.below += 1,
        Mispredict::None => {}
    }
}

/// Record one entry the driver refused. The refusal is attributed to the state
/// that was asked for, not to whatever ran instead: a governor picking a state
/// the hardware keeps declining is the thing worth seeing. # C: O(1)
pub fn record_rejection(usage: &mut [StateUsage], requested: usize) {
    if let Some(slot) = usage.get_mut(requested) { slot.rejected += 1; }
}

/// Fresh counters for a state table. # C: O(N_states)
pub fn new_usage(states: &[IdleState]) -> Vec<StateUsage> {
    states.iter().map(|state| StateUsage {
        disable: state.initial_disable(), ..StateUsage::default()
    }).collect()
}

#[cfg(test)]
#[path = "tests/usage.rs"]
mod tests;
