use super::*;
use ::core::sync::atomic::{AtomicU32, Ordering};

mod frag;
mod reserve;

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
        let candidate = TcpBindReservation::new_owned(bind.owner.clone(), bind.local,
            bind.reuseaddr, bind.reuseport, bind.v6only,
            Arc::new(AtomicU32::new(iface.map(NetIfaceId::raw).unwrap_or(0))));
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
        bind.bound_ifindex.store(iface.map(NetIfaceId::raw).unwrap_or(0), Ordering::Release);
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
        self.tcp_listen_reserved_min_hop_frag(bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, Arc::new(::core::sync::atomic::AtomicI32::new(0)), min_hop)
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
        self.tcp_listen_reserved_fastopen_frag(bind, bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, Arc::new(::core::sync::atomic::AtomicI32::new(0)), min_hop,
            fastopen)
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
            Arc::new(::core::sync::atomic::AtomicI32::new(0)),
            Arc::new(crate::min_hop::MinHop::new()),
            Arc::new(crate::sock_opts::sol_ip::IpOpts::default()),
            Arc::new(crate::sock_opts::sol_ipv6::Ipv6Opts::default()),
            Arc::new(::core::sync::atomic::AtomicU64::new(u64::MAX)),
            Arc::new(::core::sync::atomic::AtomicI32::new(super::types::UNMARKED_OPTION)),
            crate::sock::tcp_fastopen::ActiveOpen::default(), &[]).map(|(entry, _)| entry)
    }

    /// Active-open while sharing the socket's hop-limit minimums and its
    /// sticky IPv4 option area too. # C: O(log N + xmit)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tcp_connect_reserved_min_hop(&self, bind: &Arc<TcpBindReservation>,
        local_ip: IpAddr, remote_ip: IpAddr, remote_port: u16, error: Arc<crate::SocketError>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        ip_opts: Arc<crate::sock_opts::sol_ip::IpOpts>,
        ipv6_opts: Arc<crate::sock_opts::sol_ipv6::Ipv6Opts>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>,
        mark: Arc<::core::sync::atomic::AtomicI32>,
        fastopen: crate::sock::tcp_fastopen::ActiveOpen,
        data: &[u8]) -> NetResult<(Arc<TcpEntry>, usize)>
    {
        let tables = self.inet_tables(bind.net_ns());
        let mut binds = tables.tcp_binds.lock();
        if !self.tcp_bind_registered_locked(&mut binds, bind) { return Err(NetError::Einval); }
        if bind.role.load(Ordering::Acquire) != TCP_BIND_BOUND { return Err(NetError::Einval); }
        let key = TcpKey { local_ip, local_port: bind.local.port, remote_ip, remote_port };
        let mut conns = tables.tcp_conns.lock();
        if conns.contains_key(&key) { return Err(NetError::Eaddrnotavail); }
        let (entry, syn, carried) = self.build_active_child(bind, local_ip, remote_ip, remote_port,
            error, bpf_filter, ip_mtu_discover, ipv6_mtu_discover, ipv6_frag_size, min_hop, ip_opts, ipv6_opts,
            max_pacing_rate, mark, fastopen, data)?;
        conns.insert(key, super::TcpSlot::Sock(entry.clone()));
        drop(conns);
        if let Err(error) = self.send_tcp_segment_in(
            bind.net_ns(), local_ip, remote_ip, &syn, 0, bind.bound_iface(),
            super::tcp_tx::TcpTxPolicy::Entry(&entry),
        ) {
            super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &entry);
            return Err(error);
        }
        crate::mib::bump(bind.net_ns(), crate::mib::Mib::TcpActiveOpens);
        bind.role.store(TCP_BIND_CONNECT, Ordering::Release);
        crate::stack::stamp_last_sent_public(&entry, 1);
        self.activate_tcp_timers(&entry);
        Ok((entry, carried))
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
        ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
        min_hop: Arc<crate::min_hop::MinHop>,
        ip_opts: Arc<crate::sock_opts::sol_ip::IpOpts>,
        ipv6_opts: Arc<crate::sock_opts::sol_ipv6::Ipv6Opts>,
        max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>,
        mark: Arc<::core::sync::atomic::AtomicI32>,
        fastopen: crate::sock::tcp_fastopen::ActiveOpen,
        data: &[u8])
        -> NetResult<(Arc<TcpEntry>, alloc::vec::Vec<u8>, usize)>
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
        // The route this connection lives on is the one its own mark selects,
        // so the path MTU, the MSS and the metrics all come from that route
        // rather than from whatever an unmarked lookup would have found.
        let mark_value = mark.load(Ordering::Acquire) as u32;
        conn.path_mtu = self.tcp_path_mtu_in(
            bind.net_ns(), remote_ip, bind.bound_iface(), ip_mode, ipv6_mode,
            mark_value).unwrap_or(0);
        // The sticky option area rides ahead of the TCP header on every
        // segment, so the connection gives that many bytes up from its MSS.
        conn.own_mss = crate::tcp_ext_hdr::mss_minus_ext_hdr(
            self.mss_for_dst_on_iface_pmtu_modes_in(
                bind.net_ns(), remote_ip, bind.bound_iface(), ip_mode, ipv6_mode, mark_value),
            crate::tcp_ext_hdr::ext_hdr_len(ip_opts.options().as_ref()));
        conn.apply_route_metrics(self.route_metrics_for_dst_mark_in(
            bind.net_ns(), remote_ip, bind.bound_iface(), mark_value));
        let (syn, carried) = conn.active_open_fastopen_with_policy(fastopen.option,
            fastopen.payload(data), crate::sysctl::tcp_option_permissions_in(bind.net_ns()))
            .map_err(|_| NetError::Eio)?;
        Ok((Arc::new(TcpEntry::new_bound_ip_opts_pacing_ipv6_mark(
            conn, error, Some(bind.clone()), bpf_filter, ip_mtu_discover,
            ipv6_mtu_discover, ipv6_frag_size, None, min_hop, ip_opts, ipv6_opts, max_pacing_rate,
            mark)), syn, carried))
    }
}

#[cfg(test)]
#[path = "tcp_bind/tests/mod.rs"]
mod tests;
