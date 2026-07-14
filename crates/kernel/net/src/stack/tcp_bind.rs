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
    fn tcp_transport_conflict(&self, candidate: &TcpBindReservation) -> bool {
        let listeners = self.tcp_listens.lock();
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
        let conns = self.tcp_conns.lock();
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
        binds: &mut BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>,
        local_ip: IpAddr, port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
        reuseport: bool, owner_uid: u32, v6only: bool)
        -> Option<Arc<TcpBindReservation>>
    {
        let bind = Arc::new(TcpBindReservation::new(
            Endpoint { ip: local_ip, port }, iface, reuseaddr, reuseport, owner_uid, v6only,
        ));
        let group = binds.entry(port).or_default();
        if reservation_conflict(group, &bind) || self.tcp_transport_conflict(&bind) {
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
        let mut binds = self.tcp_binds.lock();
        if requested_port != 0 {
            return self.tcp_try_reserve_locked(&mut binds, local_ip, requested_port, iface,
                reuseaddr, reuseport, owner_uid, v6only).ok_or(NetError::Eaddrinuse);
        }
        let range = crate::ephemeral::range_in(net_ns);
        for _ in 0..range.count() {
            let seq = self.next_tcp_ephemeral.fetch_add(1, Ordering::Relaxed);
            let port = range.port(seq);
            if let Some(bind) = self.tcp_try_reserve_locked(&mut binds, local_ip, port, iface,
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
        let mut binds = self.tcp_binds.lock();
        if let Some(group) = binds.get_mut(&bind.local.port) {
            group.retain(|weak| weak.upgrade().is_some_and(|old| !Arc::ptr_eq(&old, bind)));
            if group.is_empty() { binds.remove(&bind.local.port); }
        }
    }

    /// Transactionally change SO_BINDTODEVICE scope for one TCP bind. # C: O(N_port)
    pub fn tcp_rebind_iface(&self, bind: &Arc<TcpBindReservation>, iface: Option<NetIfaceId>)
        -> NetResult<()>
    {
        let mut binds = self.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        let candidate = TcpBindReservation::new(bind.local, iface, bind.reuseaddr,
            bind.reuseport, bind.owner_uid, bind.v6only);
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
        let mut binds = self.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        if bind.role.load(Ordering::Acquire) != TCP_BIND_BOUND { return Err(NetError::Einval); }
        let mut listeners = self.tcp_listens.lock();
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
            let conns = self.tcp_conns.lock();
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
        let entry = Arc::new(TcpListenEntry::new(bind.clone()));
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
        let mut binds = self.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        if bind.role.load(Ordering::Acquire) != TCP_BIND_BOUND { return Err(NetError::Einval); }
        let key = TcpKey { local_ip, local_port: bind.local.port, remote_ip, remote_port };
        let mut conns = self.tcp_conns.lock();
        if conns.contains_key(&key) { return Err(NetError::Eaddrnotavail); }
        let isn = self.next_isn_value();
        let mut conn = TcpConn::new_client(
            Endpoint { ip: local_ip, port: bind.local.port },
            Endpoint { ip: remote_ip, port: remote_port }, isn,
        );
        conn.own_mss = self.mss_for_dst_on_iface(remote_ip, bind.bound_iface());
        let syn = conn.active_open().map_err(|_| NetError::Eio)?;
        let entry = Arc::new(TcpEntry::new_bound_with_error(conn, error, Some(bind.clone())));
        conns.insert(key, entry.clone());
        drop(conns);
        if let Err(error) = self.send_l4_over_ip_bound(
            local_ip, remote_ip, IpProto::Tcp, &syn, bind.bound_iface(),
        ) {
            self.tcp_conns.lock().remove(&key);
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
    fn ephemeral_sequence_wraps_from_last_to_first() {
        let stack = NetStack::new();
        stack.next_tcp_ephemeral.store(crate::ephemeral::DEFAULT_END as u32, Ordering::Release);
        let last = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false).unwrap();
        let first = reserve(&stack, IpAddr::V4(Ipv4Addr::ANY), 0, None, false).unwrap();
        assert_eq!(last.local.port, crate::ephemeral::DEFAULT_END);
        assert_eq!(first.local.port, crate::ephemeral::DEFAULT_START);
    }

    #[test]
    fn ephemeral_range_is_selected_by_socket_namespace() {
        let stack = NetStack::new();
        let net_ns = 0x8230_1001;
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
        let range = crate::ephemeral::range();
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
