// Per-interface IPv6 configuration inherited from the namespace default.

use core::sync::atomic::{AtomicI64, Ordering};

/// One per-interface IPv6 policy selector.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv6ConfKey { DisableIpv6, OptimisticDad, UseOptimistic }

/// IPv6 policy copied from `conf/default` when an interface is created.
pub struct Ipv6DevConf {
    disable_ipv6: AtomicI64,
    optimistic_dad: AtomicI64,
    use_optimistic: AtomicI64,
}

impl Ipv6DevConf {
    pub(super) fn from_default(ns: u64) -> Self {
        let disable_ipv6 = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6DisableDefault).unwrap_or(0);
        let optimistic_dad = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6OptimisticDadDefault).unwrap_or(0);
        let use_optimistic = crate::sysctl::value_in(ns,
            crate::net_ns::NetSysctlKey::Ipv6UseOptimisticDefault).unwrap_or(0);
        Self { disable_ipv6: AtomicI64::new(disable_ipv6),
            optimistic_dad: AtomicI64::new(optimistic_dad),
            use_optimistic: AtomicI64::new(use_optimistic) }
    }

    /// Read one live per-interface IPv6 policy value. # C: O(1)
    pub fn value(&self, key: Ipv6ConfKey) -> i64 {
        match key {
            Ipv6ConfKey::DisableIpv6 => self.disable_ipv6.load(Ordering::Acquire),
            Ipv6ConfKey::OptimisticDad => self.optimistic_dad.load(Ordering::Acquire),
            Ipv6ConfKey::UseOptimistic => self.use_optimistic.load(Ordering::Acquire),
        }
    }

    /// Update one live per-interface IPv6 policy value. # C: O(1)
    pub fn set_value(&self, key: Ipv6ConfKey, value: i64) {
        match key {
            Ipv6ConfKey::DisableIpv6 => self.disable_ipv6.store(value, Ordering::Release),
            Ipv6ConfKey::OptimisticDad => self.optimistic_dad.store(value, Ordering::Release),
            Ipv6ConfKey::UseOptimistic => self.use_optimistic.store(value, Ordering::Release),
        }
    }
}
