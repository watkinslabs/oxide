use alloc::sync::Arc;

use super::{stack, InetSocket, SockKind, AF_INET6};

impl InetSocket {
    /// Create and publish one socket-owned raw IPv4 endpoint. # C: O(N)
    pub fn new_raw4(protocol: u8) -> Self {
        Self::new_raw4_in(protocol, crate::net_ns::current_namespace())
    }

    /// Build a raw IPv4 socket retaining an explicit owner. # C: O(N)
    pub fn new_raw4_in(protocol: u8, net_namespace: network_namespace::NetworkNamespaceRef) -> Self {
        let sock = Self::new_udp_in(net_namespace);
        let endpoint = crate::raw4::Raw4Endpoint::new_owned_with_pmtudisc(
            protocol, sock.owner.clone(),
            sock.bpf_filter.clone(), sock.mcast.clone(), sock.error.clone(),
            sock.opts.ip_mtu_discover.clone(),
        );
        endpoint.register_poll_subs(&sock.poll_subs);
        stack().register_raw4(&endpoint);
        *sock.kind.lock() = SockKind::Raw4(endpoint);
        sock.opts.so_type.store(3, core::sync::atomic::Ordering::Release);
        sock
    }

    /// Create and publish one socket-owned raw IPv6 endpoint. # C: O(N)
    pub fn new_raw6(protocol: u8) -> Self {
        Self::new_raw6_in(protocol, crate::net_ns::current_namespace())
    }

    /// Build a raw IPv6 socket retaining an explicit owner. # C: O(N)
    pub fn new_raw6_in(protocol: u8, net_namespace: network_namespace::NetworkNamespaceRef) -> Self {
        let sock = Self::new_udp_in(net_namespace);
        sock.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        let endpoint = Arc::new(crate::raw6::Raw6Endpoint::new_owned(
            sock.owner.clone(), protocol,
            sock.bpf_filter.clone(), sock.mcast.clone(), sock.error.clone(),
            Some(sock.opts.ipv6.router_alert()),
        ));
        endpoint.register_poll_subs(&sock.poll_subs);
        stack().register_raw6(&endpoint);
        *sock.kind.lock() = SockKind::Raw6(endpoint);
        sock.opts.so_type.store(3, core::sync::atomic::Ordering::Release);
        sock
    }
}

impl InetSocket {
    /// Build an IPv4 ICMP datagram socket. The endpoint stays out of the raw
    /// protocol table: replies reach it through its kernel-owned echo
    /// identifier, never through protocol fanout. # C: O(1)
    pub fn new_ping4_in(net_namespace: network_namespace::NetworkNamespaceRef) -> Self {
        let sock = Self::new_udp_in(net_namespace);
        let endpoint = crate::raw4::Raw4Endpoint::new_ping(
            sock.owner.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
            sock.error.clone(), sock.opts.reuseaddr.clone(),
            sock.opts.ip_mtu_discover.clone(),
        );
        endpoint.register_poll_subs(&sock.poll_subs);
        *sock.kind.lock() = SockKind::Raw4(endpoint);
        sock.opts.so_type.store(crate::socket_args::SOCK_DGRAM as u8,
            core::sync::atomic::Ordering::Release);
        sock
    }

    /// Build an IPv6 ICMP datagram socket. The address family is single-stack
    /// by construction, matching the endpoint class. # C: O(1)
    pub fn new_ping6_in(net_namespace: network_namespace::NetworkNamespaceRef) -> Self {
        let sock = Self::new_udp_in(net_namespace);
        sock.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        sock.opts.ipv6_v6only.store(1, core::sync::atomic::Ordering::Release);
        let endpoint = Arc::new(crate::raw6::Raw6Endpoint::new_ping(
            sock.owner.clone(), sock.bpf_filter.clone(), sock.mcast.clone(),
            sock.error.clone(), sock.opts.reuseaddr.clone(),
        ));
        endpoint.register_poll_subs(&sock.poll_subs);
        *sock.kind.lock() = SockKind::Raw6(endpoint);
        sock.opts.so_type.store(crate::socket_args::SOCK_DGRAM as u8,
            core::sync::atomic::Ordering::Release);
        sock
    }
}
