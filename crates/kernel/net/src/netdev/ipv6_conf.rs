// Per-interface IPv6 configuration inherited from the namespace default.

use core::sync::atomic::{AtomicI64, Ordering};

/// One per-interface IPv6 policy selector.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv6ConfKey {
    DisableIpv6, OptimisticDad, UseOptimistic, UseTempaddr, TempValidLft, TempPreferredLft,
}

/// IPv6 policy copied from `conf/default` when an interface is created.
pub struct Ipv6DevConf {
    disable_ipv6: AtomicI64,
    optimistic_dad: AtomicI64,
    use_optimistic: AtomicI64,
    use_tempaddr: AtomicI64,
    temp_valid_lft: AtomicI64,
    temp_preferred_lft: AtomicI64,
}

impl Ipv6DevConf {
    pub(super) fn from_default(ns: u64) -> Self {
        let disable_ipv6 = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6DisableDefault).unwrap_or(0);
        let optimistic_dad = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6OptimisticDadDefault).unwrap_or(0);
        let use_optimistic = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6UseOptimisticDefault).unwrap_or(0);
        let use_tempaddr = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6UseTempaddrDefault).unwrap_or(0);
        let temp_valid_lft = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6TempValidLftDefault).unwrap_or(172_800);
        let temp_preferred_lft = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6TempPreferredLftDefault).unwrap_or(86_400);
        Self { disable_ipv6: AtomicI64::new(disable_ipv6),
            optimistic_dad: AtomicI64::new(optimistic_dad),
            use_optimistic: AtomicI64::new(use_optimistic),
            use_tempaddr: AtomicI64::new(use_tempaddr),
            temp_valid_lft: AtomicI64::new(temp_valid_lft),
            temp_preferred_lft: AtomicI64::new(temp_preferred_lft) }
    }

    /// Read one live per-interface IPv6 policy value. # C: O(1)
    pub fn value(&self, key: Ipv6ConfKey) -> i64 {
        match key {
            Ipv6ConfKey::DisableIpv6 => self.disable_ipv6.load(Ordering::Acquire),
            Ipv6ConfKey::OptimisticDad => self.optimistic_dad.load(Ordering::Acquire),
            Ipv6ConfKey::UseOptimistic => self.use_optimistic.load(Ordering::Acquire),
            Ipv6ConfKey::UseTempaddr => self.use_tempaddr.load(Ordering::Acquire),
            Ipv6ConfKey::TempValidLft => self.temp_valid_lft.load(Ordering::Acquire),
            Ipv6ConfKey::TempPreferredLft => self.temp_preferred_lft.load(Ordering::Acquire),
        }
    }

    /// Update one live per-interface IPv6 policy value. # C: O(1)
    pub fn set_value(&self, key: Ipv6ConfKey, value: i64) {
        match key {
            Ipv6ConfKey::DisableIpv6 => self.disable_ipv6.store(value, Ordering::Release),
            Ipv6ConfKey::OptimisticDad => self.optimistic_dad.store(value, Ordering::Release),
            Ipv6ConfKey::UseOptimistic => self.use_optimistic.store(value, Ordering::Release),
            Ipv6ConfKey::UseTempaddr => self.use_tempaddr.store(value, Ordering::Release),
            Ipv6ConfKey::TempValidLft => self.temp_valid_lft.store(value, Ordering::Release),
            Ipv6ConfKey::TempPreferredLft => self.temp_preferred_lft.store(value, Ordering::Release),
        }
    }
}
