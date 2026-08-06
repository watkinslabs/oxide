use super::*;

/// A transport-demux table shared by socket syscalls and NET_RX.
///
/// Linux takes the corresponding inet hash locks with `spin_lock_bh()` from
/// process context.  Keeping that rule at the type boundary prevents a task
/// holding a table lock from being interrupted by NET_RX on the same CPU and
/// deadlocking against itself.
pub(crate) struct InetTableLock<T>(Spinlock<T, StackLockClass>);

impl<T> InetTableLock<T> {
    /// Build one bottom-half-safe transport table. # C: O(1)
    pub(crate) const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    /// Exclude NET_RX while the transport registry is held. # C: O(1)
    pub(crate) fn lock(
        &self,
    ) -> sync::LockBhGuard<'_, T, StackLockClass, sched::bh::SchedBh> {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_table_lock_excludes_network_bottom_halves() {
        sched::preempt::_test_reset();
        let table = InetTableLock::new(BTreeMap::<u16, u16>::new());
        {
            let _guard = table.lock();
            assert_eq!(sched::preempt::softirq_count(),
                sched::preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(sched::preempt::softirq_count(), 0);
    }
}

/// Canonical AF_INET/AF_INET6 transport state owned by one network namespace.
pub(crate) struct InetTables {
    pub(crate) raw4: Arc<crate::raw4::Raw4Table>,
    pub(crate) raw6: Arc<crate::raw6::Raw6Table>,
    pub(crate) ping: Arc<crate::ping::PingTable>,
    pub(crate) udp: Arc<InetTableLock<BTreeMap<u16, Vec<Arc<UdpRxQueue>>>>>,
    pub(crate) udp6: Arc<InetTableLock<BTreeMap<u16, Vec<Arc<crate::stack_ipv6::Udp6RxQueue>>>>>,
    pub(crate) tcp_conns: Arc<InetTableLock<BTreeMap<TcpKey, Arc<TcpEntry>>>>,
    pub(crate) tcp_listens: Arc<InetTableLock<BTreeMap<TcpListenKey, Vec<Arc<TcpListenEntry>>>>>,
    pub(crate) tcp_binds: Arc<InetTableLock<BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>>>,
    pub(crate) pmtu: super::pmtu_cache::PmtuCache,
}

pub(crate) struct InetTablesRef {
    _owner: network_namespace::NetworkNamespaceRef,
    tables: Arc<InetTables>,
}

impl ::core::ops::Deref for InetTablesRef {
    type Target = InetTables;
    /// # C: O(1)
    fn deref(&self) -> &InetTables { &self.tables }
}

impl InetTables {
    /// Create empty transport state for one network namespace. # C: O(1)
    pub(crate) fn new() -> Self {
        Self {
            raw4: Arc::new(crate::raw4::Raw4Table::new()),
            raw6: Arc::new(crate::raw6::Raw6Table::new()),
            ping: Arc::new(crate::ping::PingTable::new()),
            udp: Arc::new(InetTableLock::new(BTreeMap::new())),
            udp6: Arc::new(InetTableLock::new(BTreeMap::new())),
            tcp_conns: Arc::new(InetTableLock::new(BTreeMap::new())),
            tcp_listens: Arc::new(InetTableLock::new(BTreeMap::new())),
            tcp_binds: Arc::new(InetTableLock::new(BTreeMap::new())),
            pmtu: super::pmtu_cache::PmtuCache::new(),
        }
    }

    /// Close every socket-owned transport object before namespace removal. # C: O(N)
    pub(crate) fn teardown(&self) {
        self.raw4.teardown();
        self.raw6.teardown();
        self.ping.teardown();
        for endpoints in ::core::mem::take(&mut *self.udp.lock()).into_values() {
            for endpoint in endpoints { endpoint.deactivate(); }
        }
        for endpoints in ::core::mem::take(&mut *self.udp6.lock()).into_values() {
            for endpoint in endpoints { endpoint.deactivate(); }
        }
        for listeners in ::core::mem::take(&mut *self.tcp_listens.lock()).into_values() {
            for listener in listeners {
                listener.closed.store(true, ::core::sync::atomic::Ordering::Release);
                for child in listener.close_accept_queue() { child.close_and_wake(); }
                #[cfg(target_os = "oxide-kernel")]
                listener.accept_waiters.wake_all();
            }
        }
        for entry in ::core::mem::take(&mut *self.tcp_conns.lock()).into_values() {
            super::tcp_timer::cancel(&entry);
            entry.close_and_wake();
        }
        self.tcp_binds.lock().clear();
    }
}

impl NetStack {
    /// Snapshot raw IPv6 endpoints from every live namespace-owned table.
    /// Router Alert is the sole cross-namespace raw delivery path. # C: O(N endpoints)
    pub(crate) fn raw6_endpoints_all_namespaces(&self) -> Vec<Arc<crate::raw6::Raw6Endpoint>> {
        let tables: Vec<Arc<InetTables>> = self.inet.lock().values().cloned().collect();
        let mut endpoints = Vec::new();
        for table in tables { endpoints.extend(table.raw6.all_endpoints()); }
        endpoints
    }

    /// Resolve the sole transport-table owner for `net_ns`. # C: O(log N)
    pub(crate) fn try_inet_tables(&self, net_ns: u64) -> Option<InetTablesRef> {
        let owner = network_namespace::lookup_u64(net_ns)?;
        let mut all = self.inet.lock();
        let tables = if let Some(tables) = all.get(&net_ns) { tables.clone() }
        else {
            let tables = Arc::new(InetTables::new());
            all.insert(net_ns, tables.clone());
            tables
        };
        Some(InetTablesRef { _owner: owner, tables })
    }

    /// Resolve tables for a numeric key whose live owner is retained elsewhere. # C: O(log N)
    pub(crate) fn inet_tables(&self, net_ns: u64) -> InetTablesRef {
        self.try_inet_tables(net_ns)
            .expect("network namespace transport owner must remain live")
    }

    /// Drop the stack's ownership of a destroyed namespace's transport state. # C: O(log N)
    pub fn remove_inet_namespace(&self, net_ns: u64) -> bool {
        if net_ns == 0 { return false; }
        let tables = self.inet.lock().remove(&net_ns);
        if let Some(tables) = &tables { tables.teardown(); }
        tables.is_some()
    }
}
