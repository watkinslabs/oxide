use super::*;

impl NetStack {
    /// UDP bind. Eaddrinuse if taken. # C: O(log N)
    pub fn bind_udp(&self, bind_ip: Ipv4Addr, port: u16) -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_with_iface(bind_ip, port, None)
    }

    /// UDP bind with an optional SO_BINDTODEVICE filter. # C: O(log N)
    pub fn bind_udp_with_iface(&self, bind_ip: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>) -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_with_iface_error(bind_ip, port, iface, Arc::new(crate::SocketError::new()))
    }

    /// Bind an IPv4 UDP queue to one socket's canonical error state. # C: O(log N)
    pub fn bind_udp_with_iface_error(&self, bind_ip: Ipv4Addr, port: u16,
                               iface: Option<NetIfaceId>, error: Arc<crate::SocketError>)
        -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_socket(bind_ip, port, iface, error,
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
            0, Arc::new(Spinlock::new(None)),
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()))
    }

    /// Bind and return the exact socket-owned IPv4 UDP endpoint. # C: O(N_port)
    pub fn bind_udp_socket(&self, bind_ip: Ipv4Addr, port: u16,
                           iface: Option<NetIfaceId>, error: Arc<crate::SocketError>,
                           reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
                           reuseport: Arc<::core::sync::atomic::AtomicI32>,
                           ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                           owner_uid: u32,
                           peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                           mcast: Arc<crate::mcast_filter::SocketMcast>)
        -> NetResult<Arc<UdpRxQueue>> {
        self.bind_udp_socket_in(0, bind_ip, port, iface, error, reuseaddr, reuseport,
            ip_mtu_discover, owner_uid, peer, bpf_filter, mcast)
    }

    /// Bind an IPv4 UDP endpoint in its owning network namespace. # C: O(N_port)
    pub fn bind_udp_socket_in(&self, net_ns: u64, bind_ip: Ipv4Addr, port: u16,
                           iface: Option<NetIfaceId>, error: Arc<crate::SocketError>,
                           reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
                           reuseport: Arc<::core::sync::atomic::AtomicI32>,
                           ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                           owner_uid: u32,
                           peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                           mcast: Arc<crate::mcast_filter::SocketMcast>)
        -> NetResult<Arc<UdpRxQueue>> {
        let namespace = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns).ok_or(NetError::Enodev)? };
        self.bind_udp_socket_owned(crate::SocketOwner::root(namespace, owner_uid), bind_ip,
            port, iface, error, reuseaddr, reuseport, ip_mtu_discover,
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            Arc::new(::core::sync::atomic::AtomicI32::new(0)), peer, bpf_filter, mcast)
    }

    /// Bind an IPv4 UDP endpoint retaining one socket's canonical owner. # C: O(N_port)
    pub fn bind_udp_socket_owned(&self, owner: Arc<crate::SocketOwner>,
                           bind_ip: Ipv4Addr, port: u16, iface: Option<NetIfaceId>,
                           error: Arc<crate::SocketError>,
                           reuseaddr: Arc<::core::sync::atomic::AtomicI32>,
                           reuseport: Arc<::core::sync::atomic::AtomicI32>,
                           ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
                           gro: Arc<::core::sync::atomic::AtomicI32>,
                           encap_type: Arc<::core::sync::atomic::AtomicI32>,
                           peer: Arc<Spinlock<Option<(Ipv4Addr, u16)>, StackLockClass>>,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
                           mcast: Arc<crate::mcast_filter::SocketMcast>)
        -> NetResult<Arc<UdpRxQueue>> {
        let net_ns = owner.net_ns();
        let owner_uid = owner.owner_uid;
        let reuseport_member = reuseport.load(::core::sync::atomic::Ordering::Acquire) != 0;
        let tables = self.inet_tables_for(&owner.net_namespace);
        let mut g = tables.udp.lock();
        let udp6 = tables.udp6.lock();
        if let Some(v6_group) = udp6.get(&port) {
            let iface_raw = iface.map(|i| i.raw()).unwrap_or(0);
            for old in v6_group {
                if old.v6only.load(::core::sync::atomic::Ordering::Acquire) != 0 { continue; }
                let addr_overlap = old.bound_ip == Ipv6Addr::ANY
                    || old.bound_ip.to_v4_mapped().is_some_and(|ip| {
                        bind_ip.is_unspecified() || ip == bind_ip
                    });
                if !addr_overlap { continue; }
                let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
                let iface_overlap = old_iface == 0 || iface_raw == 0 || old_iface == iface_raw;
                let shared = old.reuseport_member() && reuseport_member
                        && old.owner_uid == owner_uid
                    || old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0
                        && reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
                if iface_overlap && !shared { return Err(NetError::Eaddrinuse); }
            }
        }
        let group = g.entry(port).or_default();
        let iface_raw = iface.map(|i| i.raw()).unwrap_or(0);
        for old in group.iter() {
            let old_iface = old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire);
            let iface_overlap = old_iface == 0 || iface_raw == 0 || old_iface == iface_raw;
            let addr_overlap = old.bound_ip.is_unspecified() || bind_ip.is_unspecified()
                || old.bound_ip == bind_ip;
            let old_reuseport = old.reuseport_member();
            let old_reuseaddr = old.reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
            let shared = old_reuseport && reuseport_member
                    && old.owner_uid == owner_uid
                || old_reuseaddr && reuseaddr.load(::core::sync::atomic::Ordering::Acquire) != 0;
            if iface_overlap && addr_overlap && !shared { return Err(NetError::Eaddrinuse); }
        }
        let q = Arc::new(UdpRxQueue::new_socket(
            net_ns, bind_ip, port, error, reuseaddr,
            Arc::new(::core::sync::atomic::AtomicI32::new(i32::from(reuseport_member))),
            ip_mtu_discover, gro, encap_type, owner, peer, bpf_filter, mcast,
        ));
        q.bound_ifindex.store(iface.map(|i| i.raw()).unwrap_or(0),
            ::core::sync::atomic::Ordering::Release);
        group.push(q.clone());
        Ok(q)
    }
}
