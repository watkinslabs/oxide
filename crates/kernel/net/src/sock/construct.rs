use alloc::sync::Arc;

use network_namespace::NetworkNamespaceRef;
use sync::Spinlock;

use super::{InetSocket, SockKind, SockOpts, AF_INET, AF_INET6, AF_PACKET, AF_UNIX};
use crate::Ipv4Addr;

#[cfg(target_os = "oxide-kernel")]
fn current_socket_uid() -> u32 {
    sched::live::current().map(|task| {
        task.creds.euid.load(core::sync::atomic::Ordering::Acquire)
    }).unwrap_or(0)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn current_socket_uid() -> u32 { 0 }

impl InetSocket {
    /// Derive the short-lived namespace table key. # C: O(1)
    pub fn net_ns(&self) -> u64 { crate::net_ns::namespace_id(&self.net_namespace) }

    /// # C: O(1)
    pub fn new_udp() -> Self { Self::new_udp_in(crate::net_ns::current_namespace()) }

    /// Build an IPv4 datagram socket retaining an explicit owner. # C: O(1)
    pub fn new_udp_in(net_namespace: NetworkNamespaceRef) -> Self {
        Self::new_in(net_namespace, Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::SocketError::new()), SockKind::Udp)
    }

    fn new_in(net_namespace: NetworkNamespaceRef,
              bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
              error: Arc<crate::SocketError>, kind: SockKind) -> Self {
        Self {
            family: core::sync::atomic::AtomicU16::new(AF_INET), local_port: Spinlock::new(None),
            local_ip: Spinlock::new(Ipv4Addr::ANY), peer: Arc::new(Spinlock::new(None)),
            udp4: Spinlock::new(None), udp6: Spinlock::new(None), tcp_bind: Spinlock::new(None),
            bpf_filter, mcast: Arc::new(crate::mcast_filter::SocketMcast::new()), kind: Spinlock::new(kind),
            opts: SockOpts::default(), error,
            read_shut: core::sync::atomic::AtomicBool::new(false),
            write_shut: core::sync::atomic::AtomicBool::new(false),
            released: core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            recv_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            connect_waiters: sched::live::WaitList::new(),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
            local_ip6: Spinlock::new(crate::Ipv6Addr([0; 16])), peer6: Arc::new(Spinlock::new(None)),
            peer6_scope: core::sync::atomic::AtomicU32::new(0),
            net_namespace,
            owner_uid: current_socket_uid(), unix_bound: Spinlock::new(None),
        }
    }

    /// # C: O(1)
    pub fn new_tcp() -> Self { Self::new_tcp_in(crate::net_ns::current_namespace()) }

    /// Build an IPv4 stream socket retaining an explicit owner. # C: O(1)
    pub fn new_tcp_in(net_namespace: NetworkNamespaceRef) -> Self {
        Self::new_tcp_with_state_in(Arc::new(crate::SocketError::new()),
            Arc::new(crate::bpf_filter::SocketFilter::new()), net_namespace)
    }

    /// Build a TCP socket around transport state allocated before accept. # C: O(1)
    pub fn new_tcp_with_error(error: Arc<crate::SocketError>) -> Self {
        Self::new_tcp_with_state_in(error, Arc::new(crate::bpf_filter::SocketFilter::new()),
            crate::net_ns::current_namespace())
    }

    /// Build a TCP socket sharing pre-existing transport state. # C: O(1)
    pub fn new_tcp_with_filter(error: Arc<crate::SocketError>,
                               bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        Self::new_tcp_with_state_in(error, bpf_filter, crate::net_ns::current_namespace())
    }

    /// Build a TCP socket retaining an explicit namespace owner. # C: O(1)
    pub(super) fn new_tcp_with_state_in(error: Arc<crate::SocketError>,
                                        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                                        net_namespace: NetworkNamespaceRef) -> Self {
        Self::new_in(net_namespace, bpf_filter, error, SockKind::TcpInit)
    }

    /// `socket(AF_INET6, SOCK_DGRAM, ...)`. # C: O(1)
    pub fn new_udp6() -> Self { Self::new_udp6_in(crate::net_ns::current_namespace()) }
    /// Build an IPv6 datagram socket retaining an explicit owner. # C: O(1)
    pub fn new_udp6_in(net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_udp_in(net_namespace); s.family.store(AF_INET6, core::sync::atomic::Ordering::Release); s
    }
    /// `socket(AF_INET6, SOCK_STREAM, ...)`. # C: O(1)
    pub fn new_tcp6() -> Self { Self::new_tcp6_in(crate::net_ns::current_namespace()) }
    /// Build an IPv6 stream socket retaining an explicit owner. # C: O(1)
    pub fn new_tcp6_in(net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_tcp_in(net_namespace); s.family.store(AF_INET6, core::sync::atomic::Ordering::Release); s
    }
    /// `socket(AF_UNIX, SOCK_STREAM, ...)`. # C: O(1)
    pub fn new_unix() -> Self { Self::new_unix_in(crate::net_ns::current_namespace()) }
    /// Build a UNIX stream socket retaining an explicit owner. # C: O(1)
    pub fn new_unix_in(net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_tcp_in(net_namespace); s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release); s
    }

    /// `socket(AF_UNIX, SOCK_DGRAM, ...)`. # C: O(1)
    pub fn new_unix_dgram() -> Self {
        Self::new_unix_dgram_in(crate::net_ns::current_namespace())
    }
    /// Build a UNIX datagram socket retaining an explicit owner. # C: O(1)
    pub fn new_unix_dgram_in(net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_tcp_in(net_namespace); s.family.store(AF_UNIX, core::sync::atomic::Ordering::Release);
        let q = crate::UnixDgramQueue::new(); q.register_subs(&s.poll_subs);
        *s.kind.lock() = SockKind::UnixDgram(q); s
    }

    /// `socket(AF_PACKET, type, protocol)`. # C: O(1)
    pub fn new_packet(proto: u16, sock_type: u8) -> Self {
        Self::new_packet_in(proto, sock_type, crate::net_ns::current_namespace())
    }
    /// Build a packet socket retaining an explicit owner. # C: O(1)
    pub fn new_packet_in(proto: u16, sock_type: u8, net_namespace: NetworkNamespaceRef) -> Self {
        let s = Self::new_tcp_in(net_namespace); s.family.store(AF_PACKET, core::sync::atomic::Ordering::Release);
        *s.kind.lock() = SockKind::Packet {
            ifindex: core::sync::atomic::AtomicU32::new(0),
            protocol: core::sync::atomic::AtomicU16::new(proto),
            sock_type: core::sync::atomic::AtomicU8::new(sock_type),
            rx: Spinlock::new(alloc::collections::VecDeque::new()),
        };
        s
    }
}

impl Default for InetSocket { fn default() -> Self { Self::new_udp() } }
