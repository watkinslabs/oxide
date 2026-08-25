use super::*;

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
        conns.values().filter_map(super::TcpSlot::sock).any(|entry| {
            let Some(old) = entry.bind.as_ref() else { return false; };
            let state = entry.conn.lock().state;
            state != crate::tcp_state::TcpState::Closed
                // Linux only permits a new bind over TIME_WAIT when both the
                // old connection and the new socket opted into SO_REUSEADDR.
                // Checking only the candidate lets an opted-in socket bypass
                // a non-opted-in connection's 2MSL reservation.
                && !(state == crate::tcp_state::TcpState::TimeWait
                    && candidate.reuseaddr && old.reuseaddr)
                && old.local.port == candidate.local.port
                && addr_overlap(old, candidate)
                && iface_overlap(entry.bound_iface(), candidate.bound_iface())
                && !may_share(old, candidate)
        })
    }

    fn tcp_try_reserve_locked(&self,
        tables: &super::inet_tables::InetTables,
        owner: &Arc<crate::SocketOwner>,
        binds: &mut BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>,
        local_ip: IpAddr, port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
        reuseport: bool, v6only: bool, bound_ifindex: &Arc<AtomicU32>)
        -> Option<Arc<TcpBindReservation>>
    {
        let proposed = iface.map(NetIfaceId::raw).unwrap_or(0);
        let candidate = Arc::new(TcpBindReservation::new_owned(
            owner.clone(), Endpoint { ip: local_ip, port }, reuseaddr,
            reuseport, v6only, Arc::new(AtomicU32::new(proposed)),
        ));
        let group = binds.entry(port).or_default();
        if reservation_conflict(group, &candidate)
            || self.tcp_transport_conflict(tables, &candidate)
        {
            if group.is_empty() { binds.remove(&port); }
            return None;
        }
        bound_ifindex.store(proposed, Ordering::Release);
        let bind = Arc::new(TcpBindReservation::new_owned(
            owner.clone(), Endpoint { ip: local_ip, port }, reuseaddr,
            reuseport, v6only, bound_ifindex.clone(),
        ));
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
        self.tcp_reserve_peer_in(net_ns, local_ip, requested_port, iface, reuseaddr, reuseport,
            owner_uid, v6only, None)
    }

    /// Reserve a TCP local name retaining one socket's canonical owner. # C: O(range * N_port)
    pub fn tcp_reserve_owned(&self, owner: Arc<crate::SocketOwner>, local_ip: IpAddr,
                          requested_port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
                          reuseport: bool, v6only: bool, port_range: u32,
                          bound_ifindex: Arc<AtomicU32>)
        -> NetResult<Arc<TcpBindReservation>>
    {
        self.tcp_reserve_peer_owned(owner, local_ip, requested_port, iface, reuseaddr,
            reuseport, v6only, None, port_range, bound_ifindex)
    }

    /// Auto-bind for an outbound connection — Linux `inet_hash_connect`.
    /// Knowing the peer lets the scan start at
    /// the keyed 4-tuple offset instead of a uniform random one, which is what
    /// keeps two connections to *different* destinations from walking the same
    /// port order. # C: O(range * N_port)
    pub fn tcp_reserve_connect_in(&self, net_ns: u64, local_ip: IpAddr, requested_port: u16,
                                  iface: Option<NetIfaceId>, reuseaddr: bool, reuseport: bool,
                                  owner_uid: u32, v6only: bool, peer: (IpAddr, u16))
        -> NetResult<Arc<TcpBindReservation>>
    {
        self.tcp_reserve_peer_in(net_ns, local_ip, requested_port, iface, reuseaddr, reuseport,
            owner_uid, v6only, Some(peer))
    }

    /// Auto-bind while retaining one socket's canonical owner. # C: O(range * N_port)
    pub fn tcp_reserve_connect_owned(&self, owner: Arc<crate::SocketOwner>, local_ip: IpAddr,
                                  requested_port: u16, iface: Option<NetIfaceId>,
                                  reuseaddr: bool, reuseport: bool, v6only: bool,
                                  peer: (IpAddr, u16), port_range: u32,
                                  bound_ifindex: Arc<AtomicU32>)
        -> NetResult<Arc<TcpBindReservation>>
    {
        self.tcp_reserve_peer_owned(owner, local_ip, requested_port, iface, reuseaddr,
            reuseport, v6only, Some(peer), port_range, bound_ifindex)
    }

    fn tcp_reserve_peer_in(&self, net_ns: u64, local_ip: IpAddr, requested_port: u16,
                           iface: Option<NetIfaceId>, reuseaddr: bool, reuseport: bool,
                           owner_uid: u32, v6only: bool, peer: Option<(IpAddr, u16)>)
        -> NetResult<Arc<TcpBindReservation>>
    {
        let namespace = if net_ns == 0 { network_namespace::initial() }
            else { network_namespace::lookup_u64(net_ns).ok_or(NetError::Enodev)? };
        self.tcp_reserve_peer_owned(crate::SocketOwner::root(namespace, owner_uid),
            local_ip, requested_port, iface, reuseaddr, reuseport, v6only, peer,
            crate::local_port::NAMESPACE_WINDOW,
            Arc::new(AtomicU32::new(iface.map(NetIfaceId::raw).unwrap_or(0))))
    }

    fn tcp_reserve_peer_owned(&self, owner: Arc<crate::SocketOwner>, local_ip: IpAddr,
                           requested_port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
                           reuseport: bool, v6only: bool, peer: Option<(IpAddr, u16)>,
                           port_range: u32, bound_ifindex: Arc<AtomicU32>)
        -> NetResult<Arc<TcpBindReservation>>
    {
        // Draw the boot secret here, in process context: the passive-open
        // reader runs in softirq and must never call the CSPRNG. A SYN cannot
        // arrive for a listener that was never bound, so priming on every
        // reservation is sufficient (`secure_seq::prime`).
        crate::secure_seq::prime();
        // The cookie secret has exactly the same constraint and the same
        // sufficiency argument: it is read from softirq when a SYN arrives on
        // a queue that is full, and no such SYN can arrive for a port nobody
        // reserved.
        crate::syncookies::prime();
        let net_ns = owner.net_ns();
        let tables = self.inet_tables_for(&owner.net_namespace);
        let mut binds = tables.tcp_binds.lock();
        if requested_port != 0 {
            return self.tcp_try_reserve_locked(&tables, &owner, &mut binds,
                local_ip, requested_port, iface,
                reuseaddr, reuseport, v6only, &bound_ifindex).ok_or(NetError::Eaddrinuse);
        }
        let range = crate::local_port::range_in(net_ns, port_range).ok_or(NetError::Enodev)?;
        // Peer known (`connect`) → keyed 4-tuple offset, Linux
        // `inet_hash_connect`. Peer unknown (`bind(0)`/`listen`) → uniform
        // random offset on the opposite parity, Linux
        // `inet_csk_find_open_port`. Neither starts at the range base.
        let (bucket, scan) = match peer {
            Some((remote_ip, remote_port)) => {
                let (index, scan) = crate::secure_seq::connect_port_scan(
                    local_ip, remote_ip, remote_port, range.start, range.count());
                (Some(index), scan)
            }
            None => (None, crate::secure_seq::bind_port_scan(range.start, range.count())),
        };
        for (step, port) in scan.enumerate() {
            if let Some(bind) = self.tcp_try_reserve_locked(&tables, &owner, &mut binds,
                local_ip, port, iface,
                reuseaddr, reuseport, v6only, &bound_ifindex)
            {
                // Linux charges the walk length back to the perturb bucket so
                // the next connect to this destination resumes further along.
                if let Some(index) = bucket {
                    crate::secure_seq::perturb::record_scan(index, step as u32);
                }
                return Ok(bind);
            }
        }
        Err(NetError::Eaddrnotavail)
    }

}

