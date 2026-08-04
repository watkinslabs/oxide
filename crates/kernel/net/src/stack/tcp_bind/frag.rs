// IPv6 fragmentation-cap-aware TCP listener publication.

use super::*;

impl NetStack {
    /// Publish a listener sharing its IPv6 fragmentation request too. # C: O(N)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_listen_reserved_min_hop_frag(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>) -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_fastopen_frag(bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size, min_hop,
            Arc::new(crate::tcp_fastopen::FastOpenQueue::new()))
    }

    /// Publish a listener sharing its IPv6 fragmentation request and fast-open state. # C: O(N)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_listen_reserved_fastopen_frag(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>) -> NetResult<Arc<TcpListenEntry>>
    {
        let tables = self.inet_tables(bind.net_ns());
        let mut binds = tables.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        if bind.role.load(Ordering::Acquire) != TCP_BIND_BOUND { return Err(NetError::Einval); }
        let mut listeners = tables.tcp_listens.lock();
        for entries in listeners.values() {
            for old in entries {
                if old.bind.local.port == bind.local.port
                    && addr_overlap(&old.bind, bind)
                    && iface_overlap(old.bound_iface(), bind.bound_iface())
                    && !listener_may_share(&old.bind, bind)
                { return Err(NetError::Eaddrinuse); }
            }
        }
        if !bind.reuseaddr {
            let conns = tables.tcp_conns.lock();
            let conflict = conns.values().any(|entry| entry.conn.lock().state
                == crate::tcp_state::TcpState::TimeWait && entry.bind.as_ref().is_some_and(|old|
                    old.local.port == bind.local.port && addr_overlap(old, bind)
                        && iface_overlap(old.bound_iface(), bind.bound_iface())));
            if conflict { return Err(NetError::Eaddrinuse); }
        }
        let entry = Arc::new(TcpListenEntry::new_with_fastopen_frag(bind.clone(), bpf_filter,
            ip_mtu_discover, ipv6_mtu_discover, ipv6_frag_size, min_hop, fastopen));
        let key = TcpListenKey { local_ip: bind.local.ip, local_port: bind.local.port };
        listeners.entry(key).or_default().push(entry.clone());
        bind.role.store(TCP_BIND_LISTEN, Ordering::Release);
        Ok(entry)
    }
}
