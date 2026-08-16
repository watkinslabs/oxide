// The governor list. One table: `scaling_available_governors` renders it and a
// write to `scaling_governor` selects out of it.

use alloc::string::String;

use super::input::{Demand, Snapshot, Target};
use super::{ondemand, schedutil, simple};

/// Which governor a policy runs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Kind { Performance, Powersave, Userspace, Ondemand, Schedutil }

/// One selectable governor.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Governor {
    pub name: &'static str,
    pub kind: Kind,
    /// Whether the governor needs a periodic sample rather than acting from a
    /// scheduler callback or a limits change.
    pub sampled: bool,
}

/// Every governor, in listing order.
pub static GOVERNORS: &[Governor] = &[
    Governor { name: "conservative", kind: Kind::Ondemand, sampled: true },
    Governor { name: "ondemand", kind: Kind::Ondemand, sampled: true },
    Governor { name: "userspace", kind: Kind::Userspace, sampled: false },
    Governor { name: "powersave", kind: Kind::Powersave, sampled: false },
    Governor { name: "performance", kind: Kind::Performance, sampled: false },
    Governor { name: "schedutil", kind: Kind::Schedutil, sampled: false },
];

/// The governor a policy runs when nothing selected one. Utilisation-driven
/// scaling is what a modern distribution selects, and it is the only one that
/// can move the frequency on the wakeup that caused the demand.
/// # C: O(1)
pub fn default_governor() -> Governor {
    GOVERNORS[GOVERNORS.len() - 1]
}

/// Resolve a governor by name. # C: O(N_governors)
pub fn by_name(name: &str) -> Option<Governor> {
    let name = name.trim();
    GOVERNORS.iter().copied().find(|gov| gov.name == name)
}

/// Body of `scaling_available_governors`. # C: O(N_governors)
pub fn available_names() -> String {
    let mut body = String::new();
    for (index, gov) in GOVERNORS.iter().enumerate() {
        if index > 0 { body.push(' '); }
        body.push_str(gov.name);
    }
    body.push('\n');
    body
}

/// Run one governor. # C: O(1)
pub fn govern(kind: Kind, snapshot: &Snapshot, demand: &Demand,
              ondemand_tunables: &ondemand::Tunables) -> Option<Target>
{
    match kind {
        Kind::Performance => simple::performance(snapshot, demand),
        Kind::Powersave => simple::powersave(snapshot, demand),
        Kind::Userspace => simple::userspace(snapshot, demand),
        Kind::Ondemand => ondemand::ondemand(snapshot, demand, ondemand_tunables),
        Kind::Schedutil => schedutil::schedutil(snapshot, demand),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_governor_resolves_by_its_own_name() {
        for gov in GOVERNORS { assert_eq!(by_name(gov.name), Some(*gov)); }
        assert!(by_name("interactive").is_none());
        assert!(by_name("").is_none());
    }

    #[test]
    fn a_write_with_the_newline_a_shell_adds_still_resolves() {
        assert_eq!(by_name("performance\n").map(|g| g.kind), Some(Kind::Performance));
        assert_eq!(by_name(" schedutil ").map(|g| g.kind), Some(Kind::Schedutil));
    }

    #[test]
    fn the_available_list_is_space_separated_and_newline_terminated() {
        let body = available_names();
        assert!(body.contains("performance"));
        assert!(body.contains("schedutil"));
        assert!(body.ends_with('\n'));
        assert!(!body.contains("  "), "no double separators");
    }

    #[test]
    fn the_default_is_a_governor_that_is_actually_listed() {
        assert!(GOVERNORS.contains(&default_governor()));
        assert_eq!(default_governor().name, "schedutil");
    }

    #[test]
    fn only_the_load_sampling_governors_need_a_periodic_wakeup() {
        let sampled: alloc::vec::Vec<&str> =
            GOVERNORS.iter().filter(|g| g.sampled).map(|g| g.name).collect();
        assert_eq!(sampled, alloc::vec!["conservative", "ondemand"]);
    }
}
