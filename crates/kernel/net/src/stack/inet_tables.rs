use super::*;

/// Canonical AF_INET/AF_INET6 transport state owned by one network namespace.
pub(crate) struct InetTables {
    pub(crate) raw4: Arc<crate::raw4::Raw4Table>,
    pub(crate) raw6: Arc<crate::raw6::Raw6Table>,
    pub(crate) udp: Arc<Spinlock<BTreeMap<u16, Vec<Arc<UdpRxQueue>>>, StackLockClass>>,
    pub(crate) udp6: Arc<Spinlock<BTreeMap<u16, Vec<Arc<crate::stack_ipv6::Udp6RxQueue>>>, StackLockClass>>,
    pub(crate) tcp_conns: Arc<Spinlock<BTreeMap<TcpKey, Arc<TcpEntry>>, StackLockClass>>,
    pub(crate) tcp_listens: Arc<Spinlock<BTreeMap<TcpListenKey, Vec<Arc<TcpListenEntry>>>, StackLockClass>>,
    pub(crate) tcp_binds: Arc<Spinlock<BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>, StackLockClass>>,
    pub(crate) next_tcp_ephemeral: ::core::sync::atomic::AtomicU32,
    pub(crate) next_udp_ephemeral: ::core::sync::atomic::AtomicU32,
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
            udp: Arc::new(Spinlock::new(BTreeMap::new())),
            udp6: Arc::new(Spinlock::new(BTreeMap::new())),
            tcp_conns: Arc::new(Spinlock::new(BTreeMap::new())),
            tcp_listens: Arc::new(Spinlock::new(BTreeMap::new())),
            tcp_binds: Arc::new(Spinlock::new(BTreeMap::new())),
            next_tcp_ephemeral: ::core::sync::atomic::AtomicU32::new(
                crate::ephemeral::DEFAULT_START as u32,
            ),
            next_udp_ephemeral: ::core::sync::atomic::AtomicU32::new(
                crate::ephemeral::DEFAULT_START as u32,
            ),
            pmtu: super::pmtu_cache::PmtuCache::new(),
        }
    }

    /// Close every socket-owned transport object before namespace removal. # C: O(N)
    pub(crate) fn teardown(&self) {
        self.raw4.teardown();
        self.raw6.teardown();
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
            entry.close_and_wake();
        }
        self.tcp_binds.lock().clear();
    }
}

impl NetStack {
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
