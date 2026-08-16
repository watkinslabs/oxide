// One policy: the set of CPUs that share a clock, the limits in force on it,
// and the frequency it is currently at.
//
// Limits come from several places at once — the platform's own ceiling, a
// thermal cap, and whatever userspace wrote. They are aggregated into one pair
// rather than each writer setting the pair directly, because a second writer
// clearing the first one's constraint is how a machine ends up running at full
// speed with a thermal limit that was supposed to be active.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};

use crate::table::FreqTable;
use crate::uapi::Relation;

/// Who asked for a limit. Each source holds one, and the effective limit is
/// the tightest of them.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LimitSource {
    /// What userspace wrote to `scaling_min_freq` / `scaling_max_freq`.
    User,
    /// The platform's own ceiling, as firmware currently reports it.
    Platform,
    /// A thermal cooling device throttling this policy.
    Thermal,
}

/// Every limit source, in the order they are aggregated.
pub const LIMIT_SOURCES: [LimitSource; 3] =
    [LimitSource::User, LimitSource::Platform, LimitSource::Thermal];

/// One source's request, kilohertz. `None` means it is not constraining.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Request { pub min: Option<u32>, pub max: Option<u32> }

/// The aggregated limits of a policy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Limits { pub min: u32, pub max: u32 }

/// Fold every request into one pair, then hold it inside the hardware's own
/// range.
///
/// The ceiling is resolved first and the floor is then held at or below it, so
/// a floor written above the current ceiling cannot invert the pair. Inverted
/// limits are the shape that makes a resolution ambiguous, and the ceiling is
/// the half that must win: exceeding a thermal or platform cap is a hardware
/// problem, running slower than asked is a performance one. # C: O(N_sources)
pub fn aggregate(hw: Limits, requests: &[(LimitSource, Request)]) -> Limits {
    let mut min = hw.min;
    let mut max = hw.max;
    for (_, request) in requests {
        if let Some(request_max) = request.max { max = max.min(request_max); }
        if let Some(request_min) = request.min { min = min.max(request_min); }
    }
    let max = max.clamp(hw.min, hw.max);
    let min = min.clamp(hw.min, max);
    Limits { min, max }
}

/// One registered policy.
pub struct Policy {
    /// CPUs sharing this clock and currently online.
    pub cpus: Vec<usize>,
    /// Every CPU in the clock domain, online or not.
    pub related_cpus: Vec<usize>,
    pub table: FreqTable,
    /// The hardware's own range, kilohertz.
    pub hw: Limits,
    /// Time one transition costs, nanoseconds.
    pub transition_latency_ns: u64,
    state: Spinlock<PolicyState, Devices>,
}

/// The mutable half of a policy.
pub struct PolicyState {
    pub limits: Limits,
    /// Frequency the policy is at, kilohertz.
    pub cur: u32,
    pub requests: Vec<(LimitSource, Request)>,
    pub governor: &'static str,
    pub boost: bool,
    /// What a write to `scaling_setspeed` asked for, kilohertz.
    pub setspeed: Option<u32>,
    pub stats: crate::stats::Stats,
}

impl Policy {
    /// Build a policy around a validated table. # C: O(N_entries)
    pub fn new(cpus: Vec<usize>, table: FreqTable, transition_latency_ns: u64, cur: u32,
               governor: &'static str) -> Option<Arc<Policy>>
    {
        let (min, max) = table.cpuinfo(false)?;
        let hw = Limits { min, max };
        let stats = crate::stats::Stats::new(&table.available(true), cur);
        Some(Arc::new(Policy {
            related_cpus: cpus.clone(),
            cpus,
            table,
            hw,
            transition_latency_ns,
            state: Spinlock::new(PolicyState {
                limits: hw,
                cur,
                requests: LIMIT_SOURCES.iter().map(|src| (*src, Request::default())).collect(),
                governor,
                boost: false,
                setspeed: None,
                stats,
            }),
        }))
    }

    /// The limits in force. # C: O(1)
    pub fn limits(&self) -> Limits { self.state.lock().limits }
    /// Frequency the policy is at, kilohertz. # C: O(1)
    pub fn cur(&self) -> u32 { self.state.lock().cur }
    /// Governor in force. # C: O(1)
    pub fn governor(&self) -> &'static str { self.state.lock().governor }
    /// Whether boost points are reachable. # C: O(1)
    pub fn boost(&self) -> bool { self.state.lock().boost }
    /// What `scaling_setspeed` last asked for. # C: O(1)
    pub fn setspeed(&self) -> Option<u32> { self.state.lock().setspeed }

    /// Run a closure against the mutable half. # C: O(closure)
    pub fn with_state<R>(&self, f: impl FnOnce(&mut PolicyState) -> R) -> R {
        f(&mut self.state.lock())
    }

    /// Record one source's request and re-aggregate. # C: O(N_sources)
    pub fn set_request(&self, source: LimitSource, request: Request) -> Limits {
        let mut state = self.state.lock();
        if let Some(slot) = state.requests.iter_mut().find(|(src, _)| *src == source) {
            slot.1 = request;
        }
        let limits = aggregate(self.hw, &state.requests);
        state.limits = limits;
        limits
    }

    /// One source's current request. # C: O(N_sources)
    pub fn request(&self, source: LimitSource) -> Request {
        self.state.lock().requests.iter().find(|(src, _)| *src == source)
            .map(|(_, request)| *request).unwrap_or_default()
    }

    /// Resolve a target against the limits in force. # C: O(N_entries)
    pub fn resolve(&self, target_khz: u32, relation: Relation) -> Option<u32> {
        let (limits, boost) = { let state = self.state.lock(); (state.limits, state.boost) };
        let index = self.table.resolve(target_khz, limits.min, limits.max, relation, boost)?;
        Some(self.table.entries[index].frequency)
    }

    /// Human-readable CPU list, as `affected_cpus` and `related_cpus` render
    /// it: space-separated, one trailing newline, no trailing space.
    /// # C: O(N_cpus)
    pub fn cpu_list(cpus: &[usize]) -> String {
        let mut body = String::new();
        for (index, cpu) in cpus.iter().enumerate() {
            if index > 0 { body.push(' '); }
            let _ = core::fmt::Write::write_fmt(&mut body, format_args!("{cpu}"));
        }
        body.push('\n');
        body
    }
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;
