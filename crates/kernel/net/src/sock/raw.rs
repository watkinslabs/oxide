use alloc::sync::Arc;

use super::{stack, InetSocket, SockKind, AF_INET6};

impl InetSocket {
    /// Create and publish one socket-owned raw IPv4 endpoint. # C: O(N)
    pub fn new_raw4(protocol: u8) -> Self {
        let sock = Self::new_udp();
        let endpoint = crate::raw4::Raw4Endpoint::new(
            protocol, sock.net_ns.load(core::sync::atomic::Ordering::Acquire),
            sock.bpf_filter.clone(), sock.mcast.clone(),
        );
        endpoint.register_poll_subs(&sock.poll_subs);
        stack().register_raw4(&endpoint);
        *sock.kind.lock() = SockKind::Raw4(endpoint);
        sock.opts.so_type.store(3, core::sync::atomic::Ordering::Release);
        sock
    }

    /// Create and publish one socket-owned raw IPv6 endpoint. # C: O(N)
    pub fn new_raw6(protocol: u8) -> Self {
        let sock = Self::new_udp();
        sock.family.store(AF_INET6, core::sync::atomic::Ordering::Release);
        let endpoint = Arc::new(crate::raw6::Raw6Endpoint::new(
            sock.net_ns.load(core::sync::atomic::Ordering::Acquire), protocol,
            sock.bpf_filter.clone(), sock.mcast.clone(), sock.error.clone(),
        ));
        endpoint.register_poll_subs(&sock.poll_subs);
        stack().register_raw6(&endpoint);
        *sock.kind.lock() = SockKind::Raw6(endpoint);
        sock.opts.so_type.store(3, core::sync::atomic::Ordering::Release);
        sock
    }
}
