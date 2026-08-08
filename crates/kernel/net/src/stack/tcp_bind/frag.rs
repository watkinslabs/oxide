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
        self.tcp_listen_reserved_fastopen_frag_pacing(bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size, min_hop, fastopen,
            Arc::new(::core::sync::atomic::AtomicU64::new(u64::MAX)))
    }

    /// Publish a listener sharing its IPv6 fragmentation, fast-open, and pacing state. # C: O(N)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_listen_reserved_fastopen_frag_pacing(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>) -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_fastopen_frag_pacing_ipv6(bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size,
            Arc::new(crate::sock_opts::sol_ipv6::Ipv6Opts::default()), min_hop, fastopen,
            max_pacing_rate)
    }

    /// Publish a listener retaining the socket's canonical IPv6 option state. # C: O(N)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_listen_reserved_fastopen_frag_pacing_ipv6(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_opts: Arc<crate::sock_opts::sol_ipv6::Ipv6Opts>,
        min_hop: Arc<crate::min_hop::MinHop>,
        fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>) -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_fastopen_frag_pacing_ipv6_mark(bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size, ipv6_opts, min_hop, fastopen, max_pacing_rate,
            Arc::new(::core::sync::atomic::AtomicI32::new(
                crate::stack::types::UNMARKED_OPTION)))
    }

    /// Publish a listener whose requests carry the listening socket's
    /// `SO_MARK` into every route lookup they make. # C: O(N)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_listen_reserved_fastopen_frag_pacing_ipv6_mark(&self,
        bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_opts: Arc<crate::sock_opts::sol_ipv6::Ipv6Opts>,
        min_hop: Arc<crate::min_hop::MinHop>,
        fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>,
        mark: Arc<::core::sync::atomic::AtomicI32>) -> NetResult<Arc<TcpListenEntry>>
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
        let entry = Arc::new(TcpListenEntry::new_with_fastopen_frag_pacing_ipv6_mark(bind.clone(),
            bpf_filter, ip_mtu_discover, ipv6_mtu_discover, ipv6_frag_size, ipv6_opts, min_hop,
            fastopen, max_pacing_rate, mark));
        let key = TcpListenKey { local_ip: bind.local.ip, local_port: bind.local.port };
        listeners.entry(key).or_default().push(entry.clone());
        bind.role.store(TCP_BIND_LISTEN, Ordering::Release);
        Ok(entry)
    }
}
