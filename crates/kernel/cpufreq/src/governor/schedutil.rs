// `schedutil`: take the frequency from the scheduler's own utilisation signal
// rather than from a sampled busy fraction.
//
// The scheduler already tracks how much of each CPU is being used, updated
// every time a task's load average moves. Reading that instead of sampling
// removes the sampling window entirely: the frequency can move on the same
// wakeup that made the CPU busy, rather than up to one window later.
//
// The wait-for-IO boost exists because that signal is blind to a specific
// case: a task that spends most of its time waiting on a device shows almost
// no utilisation, yet the device is idle whenever the task is not running, so
// running the task slowly makes the whole pipeline slower. A CPU woken from an
// IO wait therefore gets a utilisation floor that doubles on each consecutive
// such wakeup and halves on every pass without one.

use super::input::{util_to_freq, with_headroom, Demand, Snapshot, Target, CAPACITY_SCALE};

/// Smallest boost that has any effect; below it the boost is dropped.
pub const IOWAIT_BOOST_MIN: u64 = CAPACITY_SCALE / 8;

/// The wait-for-IO boost of one CPU.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IowaitBoost {
    /// Current floor, out of `CAPACITY_SCALE`.
    pub value: u64,
    /// Whether this cycle's increase has already been taken.
    pub pending: bool,
    /// Monotonic time of the last update, nanoseconds.
    pub last_update_ns: u64,
}

impl IowaitBoost {
    /// Note a wakeup. `iowait` says whether the task woke from a device wait;
    /// `idle_gap_ns` is how long since the last update, and a gap of a whole
    /// tick means the boost has gone cold. # C: O(1)
    pub fn wakeup(&mut self, iowait: bool, gap_ns: u64, tick_ns: u64) {
        if gap_ns > tick_ns {
            self.value = if iowait { IOWAIT_BOOST_MIN } else { 0 };
            self.pending = iowait;
            return;
        }
        if !iowait || self.pending { return; }
        self.pending = true;
        self.value = if self.value == 0 { IOWAIT_BOOST_MIN }
                     else { (self.value * 2).min(CAPACITY_SCALE) };
    }

    /// Take the boost for one selection, decaying it if this pass brought no
    /// fresh wakeup. Returns the utilisation floor it contributes. # C: O(1)
    pub fn apply(&mut self, capacity: u64) -> u64 {
        if self.value == 0 { return 0; }
        if !self.pending {
            self.value >>= 1;
            if self.value < IOWAIT_BOOST_MIN { self.value = 0; return 0; }
        }
        self.pending = false;
        (self.value.saturating_mul(capacity)) / CAPACITY_SCALE
    }
}

/// The rate limit one policy runs with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Tunables { pub rate_limit_us: u64 }

impl Tunables {
    /// Rate limit derived from the driver's declared transition latency.
    /// # C: O(1)
    pub fn from_latency(transition_latency_ns: u64) -> Tunables {
        Tunables { rate_limit_us: crate::limits::transition_delay_us(transition_latency_ns) }
    }

    /// The limit in nanoseconds. # C: O(1)
    pub fn delay_ns(&self) -> u64 {
        self.rate_limit_us.saturating_mul(crate::limits::NSEC_PER_USEC)
    }
}

/// Whether a fresh selection is allowed yet. A limits change bypasses the
/// limit entirely: a thermal cap that has to wait out a rate limit is a cap
/// that is not in force. # C: O(1)
pub fn may_update(tunables: &Tunables, now_ns: u64, last_update_ns: u64, limits_changed: bool)
    -> bool
{
    limits_changed || now_ns.saturating_sub(last_update_ns) >= tunables.delay_ns()
}

/// Choose a target from the scheduler's utilisation signal.
///
/// The reference frequency is the hardware ceiling: utilisation is expressed
/// as a fraction of a fully busy CPU, so the frequency it maps to has to be
/// scaled against the full range and then held inside the policy limits by the
/// resolution. Scaling against a narrowed ceiling instead would make the same
/// utilisation ask for a different absolute frequency every time a cap moved.
/// # C: O(1)
pub fn schedutil(snapshot: &Snapshot, demand: &Demand) -> Option<Target> {
    let capacity = if demand.capacity == 0 { CAPACITY_SCALE } else { demand.capacity };
    let boosted = demand.util.max(demand.iowait_boost);
    let util = with_headroom(boosted).min(capacity);
    let freq = util_to_freq(util, capacity, u64::from(snapshot.hw.max));
    Some(Target::at_least(freq))
}

#[cfg(test)]
#[path = "../tests/schedutil.rs"]
mod tests;
