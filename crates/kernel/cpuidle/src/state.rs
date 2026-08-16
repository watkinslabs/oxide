// One idle state, as a driver declares it.
//
// A driver may declare its durations in either unit. Whichever it filled in
// wins and the other is derived, so a state carries one truth: every decision
// is made on the nanosecond fields, and the microsecond ones exist because
// that is what firmware and the sysfs attributes speak.

use alloc::string::String;

use crate::limits::{ns_to_us, us_to_ns};
use crate::uapi::{DISABLED_BY_DRIVER, DISABLED_BY_USER, FLAG_OFF, FLAG_POLLING, FLAG_UNUSABLE};

/// How the CPU is put into the state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Entry {
    /// Spin without sleeping.
    Poll,
    /// The architecture's plain halt.
    Halt,
    /// A monitor-wait hint the firmware supplied.
    Mwait { hint: u32 },
    /// A read from a port the firmware named.
    SystemIo { port: u64, width: u8 },
    /// The platform's own suspend call, at the firmware-named depth.
    PlatformSuspend { param: u32 },
}

/// One declared idle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdleState {
    pub name: String,
    pub desc: String,
    /// Cost of waking from the state, nanoseconds.
    pub exit_latency_ns: u64,
    /// Sleep short of this leaves the state a net loss, nanoseconds.
    pub target_residency_ns: u64,
    /// Draw while resident, microwatts. Zero where the platform reports none.
    pub power_uw: u32,
    pub flags: u32,
    pub entry: Entry,
}

impl IdleState {
    /// Declare a state from microsecond figures, which is what firmware and
    /// device trees report. # C: O(1)
    pub fn from_us(name: &str, desc: &str, exit_latency_us: u64, target_residency_us: u64,
                   entry: Entry) -> IdleState
    {
        IdleState {
            name: String::from(name),
            desc: String::from(desc),
            exit_latency_ns: us_to_ns(exit_latency_us),
            target_residency_ns: us_to_ns(target_residency_us),
            power_uw: 0,
            flags: 0,
            entry,
        }
    }

    /// Exit latency in the microseconds the attribute reports. # C: O(1)
    pub fn exit_latency_us(&self) -> u64 { ns_to_us(self.exit_latency_ns) }
    /// Target residency in the microseconds the attribute reports. # C: O(1)
    pub fn target_residency_us(&self) -> u64 { ns_to_us(self.target_residency_ns) }

    /// Whether the state spins instead of sleeping. # C: O(1)
    pub fn polling(&self) -> bool { self.flags & FLAG_POLLING != 0 }

    /// The disable bits a state starts life with. A driver that declared the
    /// state unusable pins it off; one that declared it merely off leaves
    /// userspace able to turn it back on. # C: O(1)
    pub fn initial_disable(&self) -> u32 {
        let mut disable = 0;
        if self.flags & FLAG_UNUSABLE != 0 { disable |= DISABLED_BY_DRIVER; }
        if self.flags & FLAG_OFF != 0 { disable |= DISABLED_BY_USER; }
        disable
    }
}

/// Reconcile a state table declared with either unit, then reject a table that
/// cannot be a ladder. Ordering is not cosmetic: every governor walks the
/// table assuming index order is depth order, so an unsorted table would have
/// it pick a shallow state believing it deep. # C: O(N_states)
pub fn validate(states: &[IdleState]) -> Result<(), TableError> {
    if states.is_empty() { return Err(TableError::Empty); }
    if states.len() > crate::limits::MAX_STATES { return Err(TableError::TooMany); }
    for pair in states.windows(2) {
        if pair[1].target_residency_ns < pair[0].target_residency_ns {
            return Err(TableError::ResidencyOutOfOrder);
        }
        if pair[1].exit_latency_ns < pair[0].exit_latency_ns {
            return Err(TableError::LatencyOutOfOrder);
        }
    }
    if states.iter().skip(1).any(IdleState::polling) {
        return Err(TableError::PollingNotFirst);
    }
    Ok(())
}

/// Why a declared state table was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TableError {
    Empty,
    TooMany,
    /// A deeper state claims to be worth entering for a shorter sleep.
    ResidencyOutOfOrder,
    /// A deeper state claims to be cheaper to leave.
    LatencyOutOfOrder,
    /// The spin state is not the shallowest.
    PollingNotFirst,
    /// A driver is already registered; there is only ever one state table.
    AlreadyRegistered,
}

#[cfg(test)]
#[path = "tests/state.rs"]
mod tests;
