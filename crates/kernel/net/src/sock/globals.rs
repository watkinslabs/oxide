use super::*;
use crate::UdpRxQueue;

/// Cached lo iface id + Arc<LoopbackDev> after `init()`. None before.
static LO: Spinlock<Option<(NetIfaceId, Arc<LoopbackDev>)>, SockLockClass>
    = Spinlock::new(None);

/// Register the loopback netdev, install the 127.0.0.0/8 route.
/// Idempotent.
/// # SAFETY: caller is the boot path post-allocator-up; no other
/// CPU has yet executed AF_INET syscalls.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init() {
    let _ = crate::net_ns::install_final_drop_pending_notifier();
    let mut g = LO.lock();
    if g.is_some() { return; }
    // Linux creates the loopback device in the network namespace that owns
    // this socket stack; do not silently pin boot-time state to init ns.
    let owner = crate::net_ns::current_namespace();
    let (id, lo) = crate::global_stack().register_loopback_for(&owner);
    *g = Some((id, lo));
    crate::register_timers(); // net self-registers its periodic timers
}

/// `&'static` ref to the global stack; lookups miss until `init()`.
/// # C: O(1)
pub fn stack() -> &'static NetStack { crate::global_stack() }

/// Drain lo's xmit queue back through deliver_rx; synchronous on
/// every UDP send + after deliver_rx (so ICMP echo replies the
/// path itself xmit'd land). Replaces a real soft-IRQ NET_RX.
/// # C: O(N pending)
pub fn drain_loopback() {
    {
        let g = LO.lock();
        if let Some((id, lo)) = g.as_ref() {
            crate::global_stack().drain_loopback(*id, lo);
        }
    }
    for loopback in crate::net_ns::private_loopbacks(crate::global_stack()) {
        loopback.drain_into(crate::global_stack());
    }
}

/// Allocate an unused ephemeral src port + bind it under
/// `Ipv4Addr::ANY` so reply datagrams can be received.
/// # C: O(N tries)
pub fn alloc_ephemeral_port() -> Result<u16, NetError> {
    alloc_ephemeral_port_with_error(Arc::new(crate::SocketError::new()))
}

/// Allocate and bind an IPv4 ephemeral UDP port to one socket's canonical
/// error state. # C: O(N tries)
pub fn alloc_ephemeral_port_with_error(error: Arc<crate::SocketError>) -> Result<u16, NetError> {
    alloc_ephemeral_udp4(0, Ipv4Addr::ANY, error, None,
        Arc::new(core::sync::atomic::AtomicI32::new(0)),
        Arc::new(core::sync::atomic::AtomicI32::new(0)),
        Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 0,
        Arc::new(Spinlock::new(None)), Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()))
        .map(|(port, _)| port)
}

/// Allocate and bind one exact IPv4 UDP endpoint. # C: O(N tries * N_port)
pub fn alloc_ephemeral_udp4(net_ns: u64, bind_ip: Ipv4Addr,
                            error: Arc<crate::SocketError>, iface: Option<NetIfaceId>,
                            reuseaddr: Arc<core::sync::atomic::AtomicI32>,
                            reuseport: Arc<core::sync::atomic::AtomicI32>,
                            ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                            owner_uid: u32,
                            peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, SockLockClass>>,
                            bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                            mcast: Arc<crate::mcast_filter::SocketMcast>)
    -> Result<(u16, Arc<UdpRxQueue>), NetError>
{
    use core::sync::atomic::Ordering;
    let range = crate::ephemeral::range_in(net_ns).ok_or(NetError::Enodev)?;
    let tables = crate::global_stack().inet_tables(net_ns);
    for _ in 0..range.count() {
        let seq = tables.next_udp_ephemeral.fetch_add(1, Ordering::Relaxed);
        let p = range.port(seq);
        if let Ok(endpoint) = crate::global_stack().bind_udp_socket_in(
            net_ns, bind_ip, p, iface, error.clone(), reuseaddr.clone(), reuseport.clone(),
            ip_mtu_discover.clone(), owner_uid,
            peer.clone(), bpf_filter.clone(), mcast.clone(),
        ) {
            return Ok((p, endpoint));
        }
    }
    Err(NetError::Eaddrinuse)
}

/// AF_INET6 ephemeral-port allocator. Binds under `Ipv6Addr::ANY` in
/// the v6 UDP map so reply datagrams to a v6 client reach its recv
/// queue (the v4 `alloc_ephemeral_port` would bind in the wrong map
/// and replies via `deliver_rx_ipv6` would miss).
/// # C: O(N tries)
pub fn alloc_ephemeral_port6() -> Result<u16, NetError> {
    alloc_ephemeral_port6_with_error(Arc::new(crate::SocketError::new()))
}

/// Allocate and bind an IPv6 ephemeral UDP port to one socket's canonical
/// error state. # C: O(N tries)
pub fn alloc_ephemeral_port6_with_error(error: Arc<crate::SocketError>) -> Result<u16, NetError> {
    alloc_ephemeral_udp6(0, crate::Ipv6Addr::ANY, error, None,
        Arc::new(core::sync::atomic::AtomicI32::new(0)),
        Arc::new(core::sync::atomic::AtomicI32::new(0)), 0,
        Arc::new(core::sync::atomic::AtomicI32::new(0)), Arc::new(Spinlock::new(None)),
        Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
        Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
        Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(crate::mcast_filter::SocketMcast::new()))
        .map(|(port, _)| port)
}

/// Allocate and bind one exact IPv6 UDP endpoint. # C: O(N tries * N_port)
pub fn alloc_ephemeral_udp6(net_ns: u64, bind_ip: crate::Ipv6Addr,
                            error: Arc<crate::SocketError>, iface: Option<NetIfaceId>,
                            reuseaddr: Arc<core::sync::atomic::AtomicI32>,
                            reuseport: Arc<core::sync::atomic::AtomicI32>,
                            owner_uid: u32,
                            v6only: Arc<core::sync::atomic::AtomicI32>,
                            peer: Arc<Spinlock<Option<(crate::Ipv6Addr, u16)>, SockLockClass>>,
                            ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                            ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
                            bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                            mcast: Arc<crate::mcast_filter::SocketMcast>)
    -> Result<(u16, Arc<crate::stack_ipv6::Udp6RxQueue>), NetError>
{
    use core::sync::atomic::Ordering;
    let range = crate::ephemeral::range_in(net_ns).ok_or(NetError::Enodev)?;
    let tables = crate::global_stack().inet_tables(net_ns);
    for _ in 0..range.count() {
        let seq = tables.next_udp_ephemeral.fetch_add(1, Ordering::Relaxed);
        let p = range.port(seq);
        if let Ok(endpoint) = crate::global_stack().bind_udp6_socket_in(
            net_ns, bind_ip, p, iface, error.clone(), reuseaddr.clone(), reuseport.clone(), owner_uid,
            v6only.clone(),
            peer.clone(), ip_mtu_discover.clone(), ipv6_mtu_discover.clone(),
            bpf_filter.clone(), mcast.clone(),
        ) {
            return Ok((p, endpoint));
        }
    }
    Err(NetError::Eaddrinuse)
}
