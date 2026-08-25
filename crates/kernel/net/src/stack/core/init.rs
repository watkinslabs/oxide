#![allow(unused_imports)]
use super::super::*;

impl NetStack {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            rtnl: crate::rtnl::Rtnl::new(),
            ifaces: IfaceRegistry::new(),
            routes: RouteTable::new(),
            routes6: Route6Table::new(),
            arp_proxy: crate::arp::proxy::ProxyTable::new(),
            bridges: crate::stack::bridge::BridgeTable::new(),
            bridge_pending: Spinlock::new(BTreeMap::new()),
            inet: super::super::inet_tables::InetTableLock::new(BTreeMap::new()),
            conntrack: Spinlock::new(BTreeMap::new()),
            flow_offload: Spinlock::new(BTreeMap::new()),
            flowtables: Spinlock::new(BTreeMap::new()),
            next_flowtable_handle: crate::fib_lock::FibLock::new(1),
            next_ip_id: crate::fib_lock::FibLock::new(1),
            ipv4_reasm: crate::ipv4_reasm::ReasmTable::new(),
            ipv6_reasm: crate::ipv6_reasm::ReasmTable::new(),
            v6_addrs:   super::super::types::StackBhLock::new(BTreeMap::new()),
            v6_anycast: super::super::types::StackBhLock::new(BTreeMap::new()),
            v6_ra_pending: super::super::types::StackBhLock::new(Vec::new()),
            softnet: [const { crate::fib_lock::FibLock::new(crate::backlog::queue::SoftnetData::new()) }; cpu::MAX_CPUS],
            rx_poll: crate::fib_lock::FibLock::new(Vec::new()),
            v6_mcast:   super::super::types::StackBhLock::new(BTreeMap::new()),
            v4_mcast:   super::super::types::StackBhLock::new(BTreeMap::new()),
            #[cfg(not(target_os = "oxide-kernel"))]
            ra_now_ns: ::core::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Acquire process-context serialization for RTNL control-plane mutations.
    /// # C: O(contention)
    /// # Ctx: schedulable process context
    /// # Lk: stack RTNL lock acquired
    /// # Sleeps: never
    pub fn rtnl_lock(&self) -> crate::RtnlGuard<'_> { self.rtnl.lock(self) }

    /// Linux `rtnl_trylock`. # C: O(1)
    pub fn rtnl_trylock(&self) -> Option<crate::RtnlGuard<'_>> { self.rtnl.try_lock(self) }

}

