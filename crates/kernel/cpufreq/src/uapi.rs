// Frequency-table ABI constants and the relation a caller resolves a target
// frequency with.

/// Marks a table entry the driver declared but the platform cannot use.
pub const ENTRY_INVALID: u32 = u32::MAX;

/// Table-entry flag: only reachable while boost is enabled.
pub const FLAG_BOOST: u32 = 1 << 0;
/// Table-entry flag: reachable, but another entry does the same work for less.
pub const FLAG_INEFFICIENT: u32 = 1 << 1;

/// How a requested frequency is turned into one the hardware has.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Relation {
    /// The lowest frequency at or above the target: never run slower than
    /// asked. What a minimum-frequency constraint resolves with.
    Lowest,
    /// The highest frequency at or below the target: never run faster than
    /// asked. What a maximum-frequency constraint resolves with.
    Highest,
    /// Whichever is nearest, in either direction.
    Closest,
}

impl Relation {
    /// Whether a resolution with this relation should prefer an entry the
    /// platform marked efficient where one is equally good. # C: O(1)
    pub fn prefers_efficient(self) -> bool { self != Relation::Highest }
}

/// What a driver that sets its own policy is being asked for. Only meaningful
/// for hardware that picks its own operating point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum PolicyKind { Unknown = 0, Powersave = 1, Performance = 2 }

/// Text `cpuinfo_cur_freq` returns when the driver cannot read the hardware.
pub const UNKNOWN_TEXT: &str = "<unknown>";

/// Longest driver or governor name.
pub const NAME_LEN: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_kinds_keep_their_abi_values() {
        assert_eq!(PolicyKind::Unknown as u32, 0);
        assert_eq!(PolicyKind::Powersave as u32, 1);
        assert_eq!(PolicyKind::Performance as u32, 2);
    }

    #[test]
    fn only_a_ceiling_resolution_ignores_the_efficiency_preference() {
        assert!(Relation::Lowest.prefers_efficient());
        assert!(Relation::Closest.prefers_efficient());
        assert!(!Relation::Highest.prefers_efficient());
    }

    #[test]
    fn the_invalid_entry_marker_cannot_be_a_real_frequency() {
        assert_eq!(ENTRY_INVALID, u32::MAX);
    }
}
