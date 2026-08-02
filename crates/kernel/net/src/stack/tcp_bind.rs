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
                // Linux only permits a new bind over TIME_WAIT when both the
                // old connection and the new socket opted into SO_REUSEADDR.
                // Checking only the candidate lets an opted-in socket bypass
                // a non-opted-in connection's 2MSL reservation.
                && !(state == crate::tcp_state::TcpState::TimeWait
                    && candidate.reuseaddr && old.reuseaddr)
                && old.local.port == candidate.local.port
                && addr_overlap(old, candidate)
                && iface_overlap(old.bound_iface(), candidate.bound_iface())
                && !may_share(old, candidate)
        })
    }

    fn tcp_try_reserve_locked(&self,
        tables: &super::inet_tables::InetTables,
        owner: &Arc<crate::SocketOwner>,
        binds: &mut BTreeMap<u16, Vec<alloc::sync::Weak<TcpBindReservation>>>,
        local_ip: IpAddr, port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
        reuseport: bool, v6only: bool)
        -> Option<Arc<TcpBindReservation>>
    {
        let bind = Arc::new(TcpBindReservation::new_owned(
            owner.clone(), Endpoint { ip: local_ip, port }, iface, reuseaddr,
            reuseport, v6only,
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
        self.tcp_reserve_peer_in(net_ns, local_ip, requested_port, iface, reuseaddr, reuseport,
            owner_uid, v6only, None)
    }

    /// Reserve a TCP local name retaining one socket's canonical owner. # C: O(range * N_port)
    pub fn tcp_reserve_owned(&self, owner: Arc<crate::SocketOwner>, local_ip: IpAddr,
                          requested_port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
                          reuseport: bool, v6only: bool, port_range: u32)
        -> NetResult<Arc<TcpBindReservation>>
    {
        self.tcp_reserve_peer_owned(owner, local_ip, requested_port, iface, reuseaddr,
            reuseport, v6only, None, port_range)
    }

    /// Auto-bind for an outbound connection — Linux `inet_hash_connect`
    /// (`net/ipv4/inet_hashtables.c`). Knowing the peer lets the scan start at
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
                                  peer: (IpAddr, u16), port_range: u32)
        -> NetResult<Arc<TcpBindReservation>>
    {
        self.tcp_reserve_peer_owned(owner, local_ip, requested_port, iface, reuseaddr,
            reuseport, v6only, Some(peer), port_range)
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
            crate::local_port::NAMESPACE_WINDOW)
    }

    fn tcp_reserve_peer_owned(&self, owner: Arc<crate::SocketOwner>, local_ip: IpAddr,
                           requested_port: u16, iface: Option<NetIfaceId>, reuseaddr: bool,
                           reuseport: bool, v6only: bool, peer: Option<(IpAddr, u16)>,
                           port_range: u32)
        -> NetResult<Arc<TcpBindReservation>>
    {
        // Draw the boot secret here, in process context: the passive-open
        // reader runs in softirq and must never call the CSPRNG. A SYN cannot
        // arrive for a listener that was never bound, so priming on every
        // reservation is sufficient (`secure_seq::prime`).
        crate::secure_seq::prime();
        let net_ns = owner.net_ns();
        let tables = self.inet_tables(net_ns);
        let mut binds = tables.tcp_binds.lock();
        if requested_port != 0 {
            return self.tcp_try_reserve_locked(&tables, &owner, &mut binds,
                local_ip, requested_port, iface,
                reuseaddr, reuseport, v6only).ok_or(NetError::Eaddrinuse);
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
                reuseaddr, reuseport, v6only)
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
        let Some(tables) = self.try_inet_tables(bind.net_ns()) else { return; };
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
        let candidate = TcpBindReservation::new_owned(bind.owner.clone(), bind.local, iface,
            bind.reuseaddr, bind.reuseport, bind.v6only);
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
        self.tcp_listen_reserved_min_hop(bind, bpf_filter, ip_mtu_discover, ipv6_mtu_discover,
            Arc::new(crate::min_hop::MinHop::new()))
    }

    /// Publish a listener sharing the socket's hop-limit minimums too.
    /// # C: O(N)
    pub fn tcp_listen_reserved_min_hop(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>) -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_reserved_fastopen(bind, bpf_filter, ip_mtu_discover, ipv6_mtu_discover,
            min_hop, Arc::new(crate::tcp_fastopen::FastOpenQueue::new()))
    }

    /// Publish a listener sharing the socket's fast-open accept-queue state
    /// too — the bound `TCP_FASTOPEN` named before this `listen`, the keys it
    /// mints with, and the occupancy that bound governs. # C: O(N)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_listen_reserved_fastopen(&self, bind: &Arc<TcpBindReservation>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>) -> NetResult<Arc<TcpListenEntry>>
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
        let entry = Arc::new(TcpListenEntry::new_with_fastopen(
            bind.clone(), bpf_filter, ip_mtu_discover, ipv6_mtu_discover, min_hop, fastopen));
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
        self.tcp_connect_reserved_min_hop(bind, local_ip, remote_ip, remote_port, error,
            bpf_filter, ip_mtu_discover, ipv6_mtu_discover,
            Arc::new(crate::min_hop::MinHop::new()),
            Arc::new(crate::sock_opts::sol_ip::IpOpts::default()))
    }

    /// Active-open while sharing the socket's hop-limit minimums and its
    /// sticky IPv4 option area too. # C: O(log N + xmit)
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_connect_reserved_min_hop(&self, bind: &Arc<TcpBindReservation>,
        local_ip: IpAddr, remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        ip_opts: Arc<crate::sock_opts::sol_ip::IpOpts>) -> NetResult<Arc<TcpEntry>>
    {
        let tables = self.inet_tables(bind.net_ns());
        let mut binds = tables.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        if bind.role.load(Ordering::Acquire) != TCP_BIND_BOUND { return Err(NetError::Einval); }
        let key = TcpKey { local_ip, local_port: bind.local.port, remote_ip, remote_port };
        let mut conns = tables.tcp_conns.lock();
        if conns.contains_key(&key) { return Err(NetError::Eaddrnotavail); }
        let (entry, syn) = self.build_active_child(bind, local_ip, remote_ip, remote_port,
            error, bpf_filter, ip_mtu_discover, ipv6_mtu_discover, min_hop, ip_opts)?;
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

    /// Materialise the client connection, its opening SYN, and the table entry
    /// that owns it.
    ///
    /// Split out and never inlined so the connection object — half a kilobyte
    /// of send and receive queues, timers, and option state — is confined to
    /// this frame. Inlined into the caller, its slots stay reserved for the
    /// whole of `tcp_connect_reserved_min_hop`, so the SYN transmit and the
    /// loopback receive it re-enters run on top of half a kilobyte of dead
    /// storage. Returning the finished `Arc` pops that before the transmit.
    /// # C: O(route lookup)
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    fn build_active_child(&self, bind: &Arc<TcpBindReservation>, local_ip: IpAddr,
        remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        ip_opts: Arc<crate::sock_opts::sol_ip::IpOpts>)
        -> NetResult<(Arc<TcpEntry>, alloc::vec::Vec<u8>)>
    {
        // The initial sequence number and the timestamp bias are the two
        // halves of one keyed hash over the connection's four-tuple, so an
        // off-path observer cannot predict either.
        let isn = crate::secure_seq::secure_tcp_seq(
            local_ip, remote_ip, bind.local.port, remote_port);
        let mut conn = TcpConn::new_client(
            Endpoint { ip: local_ip, port: bind.local.port },
            Endpoint { ip: remote_ip, port: remote_port }, isn,
        );
        conn.ts_off = crate::secure_seq::secure_tcp_ts_off(
            local_ip, remote_ip, bind.local.port, remote_port);
        let ip_mode = ip_mtu_discover.load(Ordering::Acquire);
        let ipv6_mode = ipv6_mtu_discover.load(Ordering::Acquire);
        // The sticky option area rides ahead of the TCP header on every
        // segment, so the connection gives that many bytes up from its MSS.
        conn.own_mss = crate::tcp_ext_hdr::mss_minus_ext_hdr(
            self.mss_for_dst_on_iface_pmtu_modes_in(
                bind.net_ns(), remote_ip, bind.bound_iface(), ip_mode, ipv6_mode),
            crate::tcp_ext_hdr::ext_hdr_len(ip_opts.options().as_ref()));
        conn.apply_route_metrics(self.route_metrics_for_dst_in(
            bind.net_ns(), remote_ip, bind.bound_iface()));
        let syn = conn.active_open().map_err(|_| NetError::Eio)?;
        Ok((Arc::new(TcpEntry::new_bound_ip_opts(
            conn, error, Some(bind.clone()), bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, None, min_hop, ip_opts)), syn))
    }
}

#[cfg(test)]
#[path = "tcp_bind/tests.rs"]
mod tests;
