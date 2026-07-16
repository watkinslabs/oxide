use super::*;
use ::core::sync::atomic::Ordering;

fn iface_overlap(a: Option<NetIfaceId>, b: Option<NetIfaceId>) -> bool {
    a.is_none() || b.is_none() || a == b
}

fn addr_overlap(a: &TcpBindReservation, b: &TcpBindReservation) -> bool {
    match (a.local.ip, b.local.ip) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x.is_unspecified() || y.is_unspecified() || x == y,
        (IpAddr::V6(x), IpAddr::V6(y)) => x.is_unspecified() || y.is_unspecified() || x == y,
        (IpAddr::V4(_), IpAddr::V6(y)) => !b.v6only && y.is_unspecified(),
        (IpAddr::V6(x), IpAddr::V4(_)) => !a.v6only && x.is_unspecified(),
    }
}

fn may_share(a: &TcpBindReservation, b: &TcpBindReservation) -> bool {
    a.reuseaddr && b.reuseaddr
        || listener_may_share(a, b)
}

fn listener_may_share(a: &TcpBindReservation, b: &TcpBindReservation) -> bool {
    a.reuseport && b.reuseport && a.owner_uid == b.owner_uid && a.v6only == b.v6only
        && matches!((a.local.ip, b.local.ip),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)))
}

fn reservation_conflict(group: &mut Vec<alloc::sync::Weak<TcpBindReservation>>,
                        candidate: &TcpBindReservation) -> bool {
    let mut conflict = false;
    group.retain(|weak| {
        let Some(old) = weak.upgrade() else { return false; };
        if old.role.load(Ordering::Acquire) == TCP_BIND_CONNECT { return true; }
        let share = if old.role.load(Ordering::Acquire) == TCP_BIND_LISTEN {
            listener_may_share(&old, candidate)
        } else {
            may_share(&old, candidate)
        };
        if addr_overlap(&old, candidate)
            && iface_overlap(old.bound_iface(), candidate.bound_iface())
            && !share
        {
            conflict = true;
        }
        true
    });
    conflict
}

impl NetStack {
    fn tcp_transport_conflict(&self, tables: &super::inet_tables::InetTables,
                              candidate: &TcpBindReservation) -> bool {
        let listeners = tables.tcp_listens.lock();
        for entries in listeners.values() {
            for entry in entries {
                if entry.bind.local.port == candidate.local.port
                    && addr_overlap(&entry.bind, candidate)
                    && iface_overlap(entry.bound_iface(), candidate.bound_iface())
                    && !listener_may_share(&entry.bind, candidate)
                {
                    return true;
                }
            }
        }
        drop(listeners);
        let conns = tables.tcp_conns.lock();
        conns.values().any(|entry| {
            let Some(old) = entry.bind.as_ref() else { return false; };
            let state = entry.conn.lock().state;
            state != crate::tcp_state::TcpState::Closed
                && !(state == crate::tcp_state::TcpState::TimeWait && candidate.reuseaddr)
                && old.local.port == candidate.local.port
                && addr_overlap(old, candidate)
                && iface_overlap(old.bound_iface(), candidate.bound_iface())
                && !may_share(old, candidate)
        })
    }

    fn tcp_try_reserve_locked(&self,
        tables: &super::inet_tables::InetTables,
        namespace: &network_namespace::NetworkNamespaceRef,
        binds: &mut BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>,
        local_ip: IpAddr, port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
        reuseport: bool, owner_uid: u32, v6only: bool)
        -> Option<Arc<TcpBindReservation>>
    {
        let bind = Arc::new(TcpBindReservation::new(
            namespace.clone(), Endpoint { ip: local_ip, port }, iface, reuseaddr,
            reuseport, owner_uid, v6only,
        ));
        let group = binds.entry(port).or_default();
        if reservation_conflict(group, &bind) || self.tcp_transport_conflict(tables, &bind) {
            if group.is_empty() { binds.remove(&port); }
            return None;
        }
        group.push(Arc::downgrade(&bind));
        Some(bind)
    }

    /// Atomically reserve an explicit or ephemeral TCP local name. # C: O(range * N_port)
    pub fn tcp_reserve(&self, local_ip: IpAddr, requested_port: u16,
                       iface: Option<NetIfaceId>, reuseaddr: bool, reuseport: bool,
                       owner_uid: u32, v6only: bool)
        -> NetResult<Arc<TcpBindReservation>>
    {
        self.tcp_reserve_in(0, local_ip, requested_port, iface, reuseaddr, reuseport,
            owner_uid, v6only)
    }

    /// Reserve a TCP local name using its owning network namespace's port policy. # C: O(range * N_port)
    pub fn tcp_reserve_in(&self, net_ns: u64, local_ip: IpAddr, requested_port: u16,
                          iface: Option<NetIfaceId>, reuseaddr: bool, reuseport: bool,
                          owner_uid: u32, v6only: bool)
        -> NetResult<Arc<TcpBindReservation>>
    {
        let namespace = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns).ok_or(NetError::Enodev)? };
        let tables = self.inet_tables(net_ns);
        let mut binds = tables.tcp_binds.lock();
        if requested_port != 0 {
            return self.tcp_try_reserve_locked(&tables, &namespace, &mut binds,
                local_ip, requested_port, iface,
                reuseaddr, reuseport, owner_uid, v6only).ok_or(NetError::Eaddrinuse);
        }
        let range = crate::ephemeral::range_in(net_ns).ok_or(NetError::Enodev)?;
        for _ in 0..range.count() {
            let seq = tables.next_tcp_ephemeral.fetch_add(1, Ordering::Relaxed);
            let port = range.port(seq);
            if let Some(bind) = self.tcp_try_reserve_locked(&tables, &namespace, &mut binds,
                local_ip, port, iface,
                reuseaddr, reuseport, owner_uid, v6only)
            {
                return Ok(bind);
            }
        }
        Err(NetError::Eaddrnotavail)
    }

    fn tcp_bind_registered_locked(&self,
        binds: &mut BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>,
        bind: &Arc<TcpBindReservation>) -> bool
    {
        let Some(group) = binds.get_mut(&bind.local.port) else { return false; };
        let mut found = false;
        group.retain(|weak| {
            let Some(current) = weak.upgrade() else { return false; };
            if Arc::ptr_eq(&current, bind) { found = true; }
            true
        });
        found
    }

    /// Remove exactly one socket-owned TCP local reservation. # C: O(N_port)
    pub fn tcp_release_bind(&self, bind: &Arc<TcpBindReservation>) {
        let tables = self.inet_tables(bind.net_ns());
        let mut binds = tables.tcp_binds.lock();
        if let Some(group) = binds.get_mut(&bind.local.port) {
            group.retain(|weak| weak.upgrade().is_some_and(|old| !Arc::ptr_eq(&old, bind)));
            if group.is_empty() { binds.remove(&bind.local.port); }
        }
    }

    /// Transactionally change SO_BINDTODEVICE scope for one TCP bind. # C: O(N_port)
    pub fn tcp_rebind_iface(&self, bind: &Arc<TcpBindReservation>, iface: Option<NetIfaceId>)
        -> NetResult<()>
    {
        let tables = self.inet_tables(bind.net_ns());
        let mut binds = tables.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        let candidate = TcpBindReservation::new(bind.namespace.clone(), bind.local, iface,
            bind.reuseaddr, bind.reuseport, bind.owner_uid, bind.v6only);
        if let Some(group) = binds.get_mut(&bind.local.port) {
            for weak in group.iter() {
                let Some(old) = weak.upgrade() else { continue; };
                if Arc::ptr_eq(&old, bind) { continue; }
                if addr_overlap(&old, &candidate)
                    && iface_overlap(old.bound_iface(), iface)
                    && !may_share(&old, &candidate)
                {
                    return Err(NetError::Eaddrinuse);
                }
            }
        }
        bind.bound_ifindex.store(iface.map(|id| id.raw()).unwrap_or(0), Ordering::Release);
        Ok(())
    }

    /// Transition one reserved local name into the listener table. # C: O(N)
    pub fn tcp_listen_reserved(&self, bind: &Arc<TcpBindReservation>)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_filter(bind,
            Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Publish a listener sharing the owning socket's live filter. # C: O(N)
    pub fn tcp_listen_reserved_filter(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_filter_pmtu(bind, bpf_filter,
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
    }

    /// Publish a listener sharing the socket's filter and IPv4 PMTU mode. # C: O(N)
    pub fn tcp_listen_reserved_filter_pmtu(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_filter_pmtu_modes(bind, bpf_filter, ip_mtu_discover,
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)))
    }

    /// Publish a listener sharing both socket PMTU modes. # C: O(N)
    pub fn tcp_listen_reserved_filter_pmtu_modes(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> NetResult<Arc<TcpListenEntry>>
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
                {
                    return Err(NetError::Eaddrinuse);
                }
            }
        }
        if !bind.reuseaddr {
            let conns = tables.tcp_conns.lock();
            let conflict = conns.values().any(|entry| {
                entry.conn.lock().state == crate::tcp_state::TcpState::TimeWait
                    && entry.bind.as_ref().is_some_and(|old| {
                        old.local.port == bind.local.port
                            && addr_overlap(old, bind)
                            && iface_overlap(old.bound_iface(), bind.bound_iface())
                    })
            });
            if conflict { return Err(NetError::Eaddrinuse); }
        }
        let entry = Arc::new(TcpListenEntry::new_with_filter(
            bind.clone(), bpf_filter, ip_mtu_discover, ipv6_mtu_discover));
        let key = TcpListenKey { local_ip: bind.local.ip, local_port: bind.local.port };
        listeners.entry(key).or_default().push(entry.clone());
        bind.role.store(TCP_BIND_LISTEN, Ordering::Release);
        Ok(entry)
    }

    /// Transition one reservation into an active-open tuple. # C: O(log N + xmit)
    pub fn tcp_connect_reserved(&self, bind: &Arc<TcpBindReservation>, local_ip: IpAddr,
        remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_reserved_filter(bind, local_ip, remote_ip, remote_port, error,
            Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Active-open while sharing the owning socket's live filter. # C: O(log N + xmit)
    pub fn tcp_connect_reserved_filter(&self, bind: &Arc<TcpBindReservation>, local_ip: IpAddr,
        remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_reserved_filter_pmtu(bind, local_ip, remote_ip, remote_port, error,
            bpf_filter,
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)))
    }

    /// Active-open while sharing the socket's filter and IPv4 PMTU mode. # C: O(log N + xmit)
    pub fn tcp_connect_reserved_filter_pmtu(&self, bind: &Arc<TcpBindReservation>, local_ip: IpAddr,
        remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_reserved_filter_pmtu_modes(bind, local_ip, remote_ip, remote_port, error,
            bpf_filter, ip_mtu_discover,
            Arc::new(::core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)))
    }

    /// Active-open while sharing both socket PMTU modes. # C: O(log N + xmit)
    pub fn tcp_connect_reserved_filter_pmtu_modes(&self, bind: &Arc<TcpBindReservation>,
        local_ip: IpAddr, remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>) -> NetResult<Arc<TcpEntry>>
    {
        let tables = self.inet_tables(bind.net_ns());
        let mut binds = tables.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        if bind.role.load(Ordering::Acquire) != TCP_BIND_BOUND { return Err(NetError::Einval); }
        let key = TcpKey { local_ip, local_port: bind.local.port, remote_ip, remote_port };
        let mut conns = tables.tcp_conns.lock();
        if conns.contains_key(&key) { return Err(NetError::Eaddrnotavail); }
        let isn = self.next_isn_value();
        let mut conn = TcpConn::new_client(
            Endpoint { ip: local_ip, port: bind.local.port },
            Endpoint { ip: remote_ip, port: remote_port }, isn,
        );
        let ip_mode = ip_mtu_discover.load(Ordering::Acquire);
        let ipv6_mode = ipv6_mtu_discover.load(Ordering::Acquire);
        conn.own_mss = self.mss_for_dst_on_iface_pmtu_modes_in(
            bind.net_ns(), remote_ip, bind.bound_iface(), ip_mode, ipv6_mode);
        let syn = conn.active_open().map_err(|_| NetError::Eio)?;
        let entry = Arc::new(TcpEntry::new_bound_with_filter_pmtu_modes(
            conn, error, Some(bind.clone()), bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover));
        conns.insert(key, entry.clone());
        drop(conns);
        if let Err(error) = self.send_tcp_segment_in(
            bind.net_ns(), local_ip, remote_ip, &syn, 0, bind.bound_iface(),
            super::tcp_tx::TcpTxPolicy::Entry(&entry),
        ) {
            super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &entry);
            return Err(error);
        }
        bind.role.store(TCP_BIND_CONNECT, Ordering::Release);
        crate::stack::stamp_last_sent_public(&entry, 1);
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: u32 = 1_000;
    const PORT: u16 = 42_123;
    const IFACE_A: NetIfaceId = NetIfaceId::from_raw(11);
    const IFACE_B: NetIfaceId = NetIfaceId::from_raw(12);

    fn reserve(stack: &NetStack, ip: IpAddr, port: u16, iface: Option<NetIfaceId>, v6only: bool)
        -> NetResult<Arc<TcpBindReservation>>
    {
        stack.tcp_reserve(ip, port, iface, false, false, UID, v6only)
    }

    #[test]
    fn exact_reservation_conflicts_until_exact_release() {
        let stack = NetStack::new();
        let first = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, None, false).unwrap();
        assert_eq!(reserve(&stack, IpAddr::V4(Ipv4Addr::LOOPBACK), PORT, None, false).err(),
                   Some(NetError::Eaddrinuse));
        stack.tcp_release_bind(&first);
        assert!(reserve(&stack, IpAddr::V4(Ipv4Addr::LOOPBACK), PORT, None, false).is_ok());
    }

    #[test]
    fn reuseaddr_cannot_bind_over_listener() {
        let stack = NetStack::new();
        let first = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT, None,
            true, false, UID, false).unwrap();
        stack.tcp_listen_reserved(&first).unwrap();
        assert!(matches!(stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT, None,
                   true, false, UID, false), Err(NetError::Eaddrinuse)));
    }

    #[test]
    fn reuseport_listener_group_requires_same_owner_uid() {
        let stack = NetStack::new();
        let first = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT + 1, None,
            false, true, UID, false).unwrap();
        let second = stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT + 1, None,
            false, true, UID, false).unwrap();
        stack.tcp_listen_reserved(&first).unwrap();
        stack.tcp_listen_reserved(&second).unwrap();
        assert_eq!(stack.tcp_reserve(IpAddr::V4(Ipv4Addr::ANY), PORT + 1, None,
            false, true, UID + 1, false).err(), Some(NetError::Eaddrinuse));
    }

    #[test]
    fn ephemeral_sequence_wraps_from_last_to_first() {
        let stack = NetStack::new();
        stack.inet_tables(0).next_tcp_ephemeral
            .store(crate::ephemeral::DEFAULT_END as u32, Ordering::Release);
        let last = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false).unwrap();
        let first = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false).unwrap();
        assert_eq!(last.local.port, crate::ephemeral::DEFAULT_END);
        assert_eq!(first.local.port, crate::ephemeral::DEFAULT_START);
    }

    #[test]
    fn ephemeral_range_is_selected_by_socket_namespace() {
        let stack = NetStack::new();
        let owner = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&owner);
        let net_ns = owner.id().as_u64();
        crate::ephemeral::set_range_in(net_ns, 45_100, 45_101).unwrap();
        let first = stack.tcp_reserve_in(net_ns, IpAddr::V4(Ipv4Addr::ANY), 0,
            None, false, false, UID, false).unwrap();
        let second = stack.tcp_reserve_in(net_ns, IpAddr::V4(Ipv4Addr::ANY), 0,
            None, false, false, UID, false).unwrap();
        assert!(matches!(first.local.port, 45_100 | 45_101));
        assert!(matches!(second.local.port, 45_100 | 45_101));
        assert_ne!(first.local.port, second.local.port);
    }

    #[test]
    fn ephemeral_exhaustion_scans_each_canonical_port_once() {
        let stack = NetStack::new();
        let range = crate::ephemeral::range().unwrap();
        let mut held = Vec::with_capacity(range.count() as usize);
        for port in range.start..=range.end {
            held.push(reserve(
                &stack, IpAddr::V4(Ipv4Addr::ANY), port as u16, None, false,
            ).unwrap());
        }
        assert_eq!(reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false).err(),
                   Some(NetError::Eaddrnotavail));
        assert_eq!(held.len(), range.count() as usize);
    }

    #[test]
    fn v6only_controls_cross_family_wildcard_conflict() {
        let stack = NetStack::new();
        let _v6 = reserve(&stack, IpAddr::V6(Ipv6Addr::ANY), PORT, None, true).unwrap();
        assert!(reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, None, false).is_ok());

        let stack = NetStack::new();
        let _v6 = reserve(&stack, IpAddr::V6(Ipv6Addr::ANY), PORT, None, false).unwrap();
        assert_eq!(reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, None, false).err(),
                   Some(NetError::Eaddrinuse));
    }

    #[test]
    fn bind_to_device_rebind_is_transactional() {
        let stack = NetStack::new();
        let a = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, Some(IFACE_A), false).unwrap();
        let _b = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), PORT, Some(IFACE_B), false).unwrap();
        assert_eq!(stack.tcp_rebind_iface(&a, Some(IFACE_B)), Err(NetError::Eaddrinuse));
        assert_eq!(a.bound_iface(), Some(IFACE_A));
    }

    #[test]
    fn listener_transition_consumes_one_reservation_role() {
        let stack = NetStack::new();
        let bind = reserve(&stack, IpAddr::V4(Ipv4Addr::LOOPBACK), PORT, None, false).unwrap();
        let listener = stack.tcp_listen_reserved(&bind).unwrap();
        assert_eq!(bind.role.load(Ordering::Acquire), TCP_BIND_LISTEN);
        assert_eq!(stack.tcp_listen_reserved(&bind).err(), Some(NetError::Einval));
        stack.tcp_unlisten_entry(&listener);
        assert_eq!(bind.role.load(Ordering::Acquire), TCP_BIND_BOUND);
    }
}
