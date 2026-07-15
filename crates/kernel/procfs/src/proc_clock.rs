// TIME-namespace projection for proc clock outputs.

use namespace_identity::{NamespaceKind, NamespaceRef};
use nscg::time_ns::TimeNsClock;

pub(crate) struct ReaderClock {
    owner: Option<NamespaceRef>,
}

impl ReaderClock {
    /// Retain the current reader's TIME namespace for one proc render. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub(crate) fn current() -> Self {
        Self { owner: sched::current().and_then(|task| task.namespace_owner(NamespaceKind::Time)) }
    }

    #[cfg(test)]
    fn for_owner(owner: NamespaceRef) -> Self { Self { owner: Some(owner) } }

    /// Add the reader's boottime offset to host uptime. # C: O(log N)
    pub(crate) fn uptime_ns(&self, host_ns: u64) -> u64 {
        let Some(owner) = self.owner.as_ref() else { return host_ns };
        nscg::time_ns::apply_display_offset(owner, TimeNsClock::Boottime, host_ns)
            .unwrap_or(host_ns)
    }

    /// Project uptime while preserving Linux's global idle duration. # C: O(log N)
    pub(crate) fn uptime(&self, host_ns: u64, idle_ns: u64) -> (u64, u64) {
        (self.uptime_ns(host_ns), idle_ns)
    }

    /// Subtract the reader's boottime offset from the global boot epoch. # C: O(log N)
    pub(crate) fn btime_seconds(&self, host_seconds: u64) -> u64 {
        let Some(owner) = self.owner.as_ref() else { return host_seconds };
        let host_ns = host_seconds.saturating_mul(nscg::time_ns::NSEC_PER_SEC as u64);
        nscg::time_ns::absolute_to_host(owner, TimeNsClock::Boottime, host_ns)
            .unwrap_or(host_ns) / nscg::time_ns::NSEC_PER_SEC as u64
    }

    /// Add the reader's boottime offset to a target's host start and convert to ticks. # C: O(log N)
    pub(crate) fn starttime_ticks(&self, host_start_ns: u64) -> u64 {
        sched::clock::ns_to_clk_tck(self.uptime_ns(host_start_ns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use namespace_identity::{allocate, initial};
    use nscg::time_ns::{TimeNsUpdate, TimeOffset};

    fn reader(seconds: i64, nanoseconds: i32) -> ReaderClock {
        let owner = allocate(NamespaceKind::Time, initial(NamespaceKind::User), None).unwrap();
        nscg::time_ns::clone_from(&owner, &initial(NamespaceKind::Time)).unwrap();
        nscg::time_ns::set_offsets(&owner, &[TimeNsUpdate {
            clock: TimeNsClock::Boottime,
            offset: TimeOffset::new(seconds, nanoseconds).unwrap(),
            host_ns: 20_000_000_000,
        }]).unwrap();
        ReaderClock::for_owner(owner)
    }

    #[test]
    fn uptime_adds_reader_offset_without_changing_global_idle() {
        let clock = reader(3, 250_000_000);
        let idle_ns = 91_000_000_000;
        assert_eq!(clock.uptime(10_000_000_000, idle_ns),
            (13_250_000_000, 91_000_000_000));
    }

    #[test]
    fn btime_subtracts_fractional_reader_offset_as_linux_timespec() {
        let clock = reader(3, 250_000_000);
        assert_eq!(clock.btime_seconds(1_700_000_000), 1_699_999_996);

        let negative = reader(-2, 500_000_000);
        assert_eq!(negative.btime_seconds(1_700_000_000), 1_700_000_001);
    }

    #[test]
    fn target_starttime_uses_reader_offset_before_tick_conversion() {
        let reader = reader(-2, 500_000_000);
        let target_host_start_ns = 8_125_000_000;
        assert_eq!(reader.starttime_ticks(target_host_start_ns), 662);
    }

    #[test]
    fn missing_reader_namespace_leaves_host_values_unchanged() {
        let clock = ReaderClock { owner: None };
        assert_eq!(clock.uptime_ns(12_345_678_900), 12_345_678_900);
        assert_eq!(clock.btime_seconds(1_700_000_000), 1_700_000_000);
        assert_eq!(clock.starttime_ticks(12_345_678_900), 1_234);
    }
}
