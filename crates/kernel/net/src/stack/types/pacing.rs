// TCP transport-entry construction carrying the canonical pacing option cell.

use super::*;

impl TcpEntry {
    /// Build a transport entry sharing its IPv6 fragmentation and pacing requests. # C: O(1)
    #[allow(clippy::too_many_arguments)]
    pub fn new_bound_full_frag_pacing(conn: TcpConn, error: Arc<crate::SocketError>,
        bind: Option<Arc<TcpBindReservation>>, bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        passive_listener: Option<alloc::sync::Weak<TcpListenEntry>>,
        min_hop: Arc<crate::min_hop::MinHop>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>) -> Self
    {
        Self::new_bound_ip_opts_pacing(conn, error, bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size, passive_listener, min_hop,
            Arc::new(crate::sock_opts::sol_ip::IpOpts::default()), max_pacing_rate)
    }

    /// Build a transport entry sharing every input and output socket option. # C: O(1)
    #[allow(clippy::too_many_arguments)]
    pub fn new_bound_ip_opts_pacing(conn: TcpConn, error: Arc<crate::SocketError>,
        bind: Option<Arc<TcpBindReservation>>, bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        passive_listener: Option<alloc::sync::Weak<TcpListenEntry>>,
        min_hop: Arc<crate::min_hop::MinHop>, ip_opts: Arc<crate::sock_opts::sol_ip::IpOpts>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>) -> Self
    {
        Self::new_bound_ip_opts_pacing_ipv6(conn, error, bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size, passive_listener, min_hop, ip_opts,
            Arc::new(crate::sock_opts::sol_ipv6::Ipv6Opts::default()), max_pacing_rate)
    }

    /// Build a transport entry retaining the socket's one canonical IPv6
    /// option object. # C: O(1)
    #[allow(clippy::too_many_arguments)]
    pub fn new_bound_ip_opts_pacing_ipv6(conn: TcpConn, error: Arc<crate::SocketError>,
        bind: Option<Arc<TcpBindReservation>>, bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        passive_listener: Option<alloc::sync::Weak<TcpListenEntry>>,
        min_hop: Arc<crate::min_hop::MinHop>, ip_opts: Arc<crate::sock_opts::sol_ip::IpOpts>,
        ipv6_opts: Arc<crate::sock_opts::sol_ipv6::Ipv6Opts>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>) -> Self
    {
        let syn_backlog_reserved = passive_listener.is_some();
        let owner = bind.as_ref().map(|bind| bind.owner.clone())
            .unwrap_or_else(|| crate::SocketOwner::root(network_namespace::initial(), 0));
        Self { owner, conn: Spinlock::new(conn), error, ip_mtu_discover, ipv6_mtu_discover,
            ipv6_frag_size, ipv6_opts, max_pacing_rate, ip_opts, min_hop, bind, bpf_filter, passive_listener,
            syn_backlog_reserved: ::core::sync::atomic::AtomicBool::new(syn_backlog_reserved),
            syn_backlog_young_reserved: ::core::sync::atomic::AtomicBool::new(syn_backlog_reserved),
            accept_backlog_reserved: ::core::sync::atomic::AtomicBool::new(false),
            accepted: ::core::sync::atomic::AtomicBool::new(false),
            fastopen_qlen: ::core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            rx_waiters: sched::live::WaitList::new(),
            poll_subs: alloc::boxed::Box::new(super::super::tcp_timer::TcpAsyncState::new()) }
    }
}
