use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::addr::{IpProto, Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::ipv6::{IPV6_HDR_LEN, push_ipv6_header};
use crate::pkt::Pkt;
use crate::netfilter_hook::{nf_output, NFPROTO_IPV6};
use crate::stack::NetStack;

use super::{Ipv6AddrOrigin, Ipv6AddrState, Ipv6IfaceAddr, Udp6RxQueue};

impl NetStack {
    pub fn add_v6_addr(&self, iface: NetIfaceId, ip: Ipv6Addr) {
        self.add_v6_addr_meta(iface, ip, 128, u32::MAX, u32::MAX);
    }

    pub fn add_v6_addr_meta(
        &self,
        iface: NetIfaceId,
        ip: Ipv6Addr,
        prefixlen: u8,
        valid: u32,
        preferred: u32,
    ) {
        let mut all = self.v6_addrs.lock();
        let addrs = all.entry(iface).or_default();
        let row = Ipv6IfaceAddr {
            addr: ip, prefixlen, preferred, valid, origin: Ipv6AddrOrigin::Static,
            state: Ipv6AddrState::Assigned, deprecated: preferred == 0, notify_pending: false,
        };
        match addrs.iter().position(|addr| addr.addr == ip) {
            Some(i) => addrs[i] = row,
            None => addrs.push(row),
        }
    }

    pub(crate) fn upsert_slaac_addr(
        &self,
        iface: NetIfaceId,
        ip: Ipv6Addr,
        prefixlen: u8,
        valid: u32,
        preferred: u32,
        prefix: Ipv6Addr,
        now_ns: u64,
        retrans_timer_ns: Option<u64>,
    ) -> Option<bool> {
        let mut all = self.v6_addrs.lock();
        let addrs = all.entry(iface).or_default();
        match addrs.iter_mut().find(|addr| addr.addr == ip) {
            Some(row) => match &mut row.origin {
                Ipv6AddrOrigin::Static => return Some(false),
                Ipv6AddrOrigin::Slaac { preferred_until_ns, valid_until_ns, .. } => {
                    *valid_until_ns = slaac_valid_deadline(*valid_until_ns, valid, now_ns);
                    *preferred_until_ns = super::ra::lifetime_deadline(now_ns, preferred);
                    refresh_slaac_lifetimes(row, now_ns);
                    row.deprecated = !row.preferred_at(now_ns);
                    if let (Some(retrans_timer_ns), Ipv6AddrState::Tentative {
                        retrans_timer_ns: current, ..
                    }) = (retrans_timer_ns, &mut row.state) { *current = retrans_timer_ns; }
                    return row.valid_at(now_ns).then_some(false);
                }
            },
            None => {
                if valid == 0 { return None; }
                addrs.push(Ipv6IfaceAddr {
                    addr: ip, prefixlen, preferred, valid,
                    origin: Ipv6AddrOrigin::Slaac { prefix,
                        preferred_until_ns: super::ra::lifetime_deadline(now_ns, preferred),
                        valid_until_ns: super::ra::lifetime_deadline(now_ns, valid) },
                    state: Ipv6AddrState::Tentative {
                        dad_until_ns: None, retry_at_ns: now_ns,
                        retrans_timer_ns: retrans_timer_ns.unwrap_or(super::ra::DAD_DELAY_NS) },
                    deprecated: preferred == 0, notify_pending: false,
                });
                return Some(true);
            }
        }
    }

    pub fn v6_addr_snapshot(&self) -> Vec<(NetIfaceId, Ipv6IfaceAddr)> {
        self.v6_addr_snapshot_in(0)
    }

    /// Snapshot IPv6 interface addresses owned by one network namespace. # C: O(N)
    pub fn v6_addr_snapshot_in(&self, net_ns: u64) -> Vec<(NetIfaceId, Ipv6IfaceAddr)> {
        let now_ns = self.ra_now_ns();
        let mut out = Vec::new();
        for (iface, addrs) in self.v6_addrs.lock().iter() {
            if self.ifaces.namespace(*iface) != Some(net_ns) { continue; }
            for addr in addrs {
                let mut row = addr.clone();
                refresh_slaac_lifetimes(&mut row, now_ns);
                out.push((*iface, row));
            }
        }
        out
    }

    pub fn bind_udp6(&self, bind_ip: Ipv6Addr, port: u16) -> NetResult<Arc<Udp6RxQueue>> {
        self.bind_udp6_with_iface(bind_ip, port, None)
    }

    pub fn bind_udp6_with_iface(
        &self,
        bind_ip: Ipv6Addr,
        port: u16,
        iface: Option<NetIfaceId>,
    ) -> NetResult<Arc<Udp6RxQueue>> {
        self.bind_udp6_with_iface_error(bind_ip, port, iface, Arc::new(crate::SocketError::new()))
    }

    /// Bind an IPv6 UDP queue to one socket's canonical error state. # C: O(log N)
    pub fn bind_udp6_with_iface_error(
        &self,
        bind_ip: Ipv6Addr,
        port: u16,
        iface: Option<NetIfaceId>,
        error: Arc<crate::SocketError>,
    ) -> NetResult<Arc<Udp6RxQueue>> {
        self.bind_udp6_socket(bind_ip, port, iface, error,
                              Arc::new(core::sync::atomic::AtomicI32::new(0)),
                              Arc::new(core::sync::atomic::AtomicI32::new(0)),
                              0, Arc::new(core::sync::atomic::AtomicI32::new(0)),
                              Arc::new(sync::Spinlock::new(None)),
                              Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)),
                              Arc::new(core::sync::atomic::AtomicI32::new(crate::uapi::IPV6_PMTUDISC_WANT)),
                              Arc::new(crate::bpf_filter::SocketFilter::new()),
                              Arc::new(crate::mcast_filter::SocketMcast::new()))
    }

    /// Bind and return the exact socket-owned IPv6 UDP endpoint. # C: O(N_port)
    pub fn bind_udp6_socket(
        &self,
        bind_ip: Ipv6Addr,
        port: u16,
        iface: Option<NetIfaceId>,
        error: Arc<crate::SocketError>,
        reuseaddr: Arc<core::sync::atomic::AtomicI32>,
        reuseport: Arc<core::sync::atomic::AtomicI32>,
        owner_uid: u32,
        v6only: Arc<core::sync::atomic::AtomicI32>,
        peer: Arc<sync::Spinlock<Option<(Ipv6Addr, u16)>, sync::Socket>>,
        ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        mcast: Arc<crate::mcast_filter::SocketMcast>,
    ) -> NetResult<Arc<Udp6RxQueue>> {
        self.bind_udp6_socket_in(0, bind_ip, port, iface, error, reuseaddr, reuseport,
            owner_uid, v6only, peer, ip_mtu_discover, ipv6_mtu_discover, bpf_filter, mcast)
    }

    /// Bind an IPv6 UDP endpoint in its owning network namespace. # C: O(N_port)
    pub fn bind_udp6_socket_in(
        &self,
        net_ns: u64,
        bind_ip: Ipv6Addr,
        port: u16,
        iface: Option<NetIfaceId>,
        error: Arc<crate::SocketError>,
        reuseaddr: Arc<core::sync::atomic::AtomicI32>,
        reuseport: Arc<core::sync::atomic::AtomicI32>,
        owner_uid: u32,
        v6only: Arc<core::sync::atomic::AtomicI32>,
        peer: Arc<sync::Spinlock<Option<(Ipv6Addr, u16)>, sync::Socket>>,
        ip_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
        ipv6_mtu_discover: Arc<core::sync::atomic::AtomicI32>,
        bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
        mcast: Arc<crate::mcast_filter::SocketMcast>,
    ) -> NetResult<Arc<Udp6RxQueue>> {
        let reuseport_member = reuseport.load(core::sync::atomic::Ordering::Acquire) != 0;
        let v6only_at_bind = v6only.load(core::sync::atomic::Ordering::Acquire) != 0;
        let tables = self.inet_tables(net_ns);
        let udp4 = tables.udp.lock();
        let mut g = tables.udp6.lock();
        let bind_v4 = bind_ip.to_v4_mapped();
        if (bind_ip == Ipv6Addr::ANY || bind_v4.is_some())
            && !v6only_at_bind
        {
            if let Some(v4_group) = udp4.get(&port) {
                let iface_raw = iface.map(|i| i.raw()).unwrap_or(0);
                for old in v4_group {
                    let addr_overlap = bind_ip == Ipv6Addr::ANY || old.bound_ip.is_unspecified()
                        || bind_v4 == Some(old.bound_ip);
                    if !addr_overlap { continue; }
                    let old_iface = old.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
                    let iface_overlap = old_iface == 0 || iface_raw == 0 || old_iface == iface_raw;
                    let shared = old.reuseport_member() && reuseport_member
                            && old.owner_uid == owner_uid
                        || old.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0
                            && reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0;
                    if iface_overlap && !shared { return Err(NetError::Eaddrinuse); }
                }
            }
        }
        let group = g.entry(port).or_default();
        let iface_raw = iface.map(|i| i.raw()).unwrap_or(0);
        for old in group.iter() {
            let old_iface = old.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
            let iface_overlap = old_iface == 0 || iface_raw == 0 || old_iface == iface_raw;
            let addr_overlap = old.bound_ip == Ipv6Addr::ANY || bind_ip == Ipv6Addr::ANY
                || old.bound_ip == bind_ip;
            let old_reuseport = old.reuseport_member();
            let old_reuseaddr = old.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0;
            let shared = old_reuseport && reuseport_member
                    && old.owner_uid == owner_uid
                || old_reuseaddr && reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0;
            if iface_overlap && addr_overlap && !shared { return Err(NetError::Eaddrinuse); }
        }
        let q = Arc::new(Udp6RxQueue::new_socket(
            net_ns, bind_ip, port, error, reuseaddr,
            Arc::new(core::sync::atomic::AtomicI32::new(i32::from(reuseport_member))),
            owner_uid, Arc::new(core::sync::atomic::AtomicI32::new(i32::from(v6only_at_bind))),
            peer, ip_mtu_discover, ipv6_mtu_discover, bpf_filter, mcast,
        ));
        q.bound_ifindex
            .store(iface.map(|i| i.raw()).unwrap_or(0), core::sync::atomic::Ordering::Release);
        group.push(q.clone());
        Ok(q)
    }

    /// Select socket-owned endpoints for one received IPv6 datagram. # C: O(N_port)
    #[cfg(test)]
    pub(crate) fn udp6_demux(&self, src: Ipv6Addr, sport: u16, dst: Ipv6Addr,
                             dport: u16, iface: NetIfaceId) -> Vec<Arc<Udp6RxQueue>> {
        self.udp6_demux_in(0, src, sport, dst, dport, iface)
    }

    /// Select endpoints in the ingress interface's network namespace. # C: O(N_port)
    pub(crate) fn udp6_demux_in(&self, net_ns: u64, src: Ipv6Addr, sport: u16, dst: Ipv6Addr,
                             dport: u16, iface: NetIfaceId) -> Vec<Arc<Udp6RxQueue>> {
        let tables = self.inet_tables(net_ns);
        let group = tables.udp6.lock().get(&dport).cloned().unwrap_or_default();
        let mut matched = Vec::new();
        let mut best = 0u8;
        for q in group {
            let bound_iface = q.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
            if bound_iface != 0 && bound_iface != iface.raw() { continue; }
            if q.bound_ip != Ipv6Addr::ANY && q.bound_ip != dst { continue; }
            let peer = *q.peer.lock();
            if peer.is_some() && peer != Some((src, sport)) { continue; }
            if dst.is_multicast() && !q.mcast.accept_v6(iface, dst, src) { continue; }
            let score = u8::from(peer.is_some()) * 4
                + u8::from(q.bound_ip != Ipv6Addr::ANY) * 2
                + u8::from(bound_iface != 0);
            if dst.is_multicast() { matched.push(q); continue; }
            if score > best { matched.clear(); best = score; }
            if score == best { matched.push(q); }
        }
        if matched.len() <= 1 || dst.is_multicast() { return matched; }
        let winner = matched.last().cloned().expect("matched is nonempty");
        if !winner.reuseport_member() {
            return alloc::vec![winner];
        }
        let winner_iface = winner.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
        matched.retain(|q| {
            q.reuseport_member()
                && q.owner_uid == winner.owner_uid && q.bound_ip == winner.bound_ip
                && q.v6only_at_bind() == winner.v6only_at_bind()
                && q.bound_ifindex.load(core::sync::atomic::Ordering::Acquire) == winner_iface
        });
        let mut hash = u32::from(sport) ^ u32::from(dport);
        for byte in src.0.iter().chain(dst.0.iter()) { hash = hash.rotate_left(5) ^ u32::from(*byte); }
        let selected = matched.swap_remove(hash as usize % matched.len());
        alloc::vec![selected]
    }

    /// Init-namespace dual-stack selection for hosted tests. # C: O(N_port)
    #[cfg(test)]
    pub(crate) fn udp6_demux_v4(&self, src: crate::Ipv4Addr, sport: u16,
                                dst: crate::Ipv4Addr, dport: u16, iface: NetIfaceId)
        -> Vec<Arc<Udp6RxQueue>> {
        self.udp6_demux_v4_in(0, src, sport, dst, dport, iface)
    }

    /// Select dual-stack endpoints in one network namespace. # C: O(N_port)
    pub(crate) fn udp6_demux_v4_in(&self, net_ns: u64, src: crate::Ipv4Addr, sport: u16,
                                dst: crate::Ipv4Addr, dport: u16, iface: NetIfaceId)
        -> Vec<Arc<Udp6RxQueue>> {
        if dst.is_multicast() { return Vec::new(); }
        let src6 = Ipv6Addr::from_v4_mapped(src);
        let tables = self.inet_tables(net_ns);
        let group = tables.udp6.lock().get(&dport).cloned().unwrap_or_default();
        let mut matched = Vec::new();
        let mut best = 0u8;
        for q in group {
            if q.v6only_at_bind() { continue; }
            if q.bound_ip != Ipv6Addr::ANY && q.bound_ip.to_v4_mapped() != Some(dst) { continue; }
            let bound_iface = q.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
            if bound_iface != 0 && bound_iface != iface.raw() { continue; }
            let peer = *q.peer.lock();
            if peer.is_some() && peer != Some((src6, sport)) { continue; }
            let score = u8::from(peer.is_some()) * 2 + u8::from(bound_iface != 0);
            if dst.is_multicast() || dst.is_broadcast() { matched.push(q); continue; }
            if score > best { matched.clear(); best = score; }
            if score == best { matched.push(q); }
        }
        if matched.len() <= 1 || dst.is_multicast() || dst.is_broadcast() { return matched; }
        let winner = matched.last().cloned().expect("matched is nonempty");
        if !winner.reuseport_member() {
            return alloc::vec![winner];
        }
        let winner_iface = winner.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
        matched.retain(|q| {
            q.reuseport_member()
                && q.owner_uid == winner.owner_uid && q.bound_ip == winner.bound_ip
                && q.bound_ifindex.load(core::sync::atomic::Ordering::Acquire) == winner_iface
        });
        let mut hash = src.as_u32().rotate_left(7) ^ dst.as_u32().rotate_left(19);
        hash ^= u32::from(sport).rotate_left(11) ^ u32::from(dport);
        let selected = matched.swap_remove(hash as usize % matched.len());
        alloc::vec![selected]
    }

    /// Remove exactly one IPv6 UDP endpoint, preserving port peers. # C: O(N_port)
    pub fn unbind_udp6_endpoint(&self, endpoint: &Arc<Udp6RxQueue>) {
        let port = endpoint.bound_port;
        let Some(tables) = self.try_inet_tables(endpoint.net_ns) else {
            endpoint.deactivate();
            return;
        };
        let mut map = tables.udp6.lock();
        if let Some(group) = map.get_mut(&port) {
            group.retain(|q| !Arc::ptr_eq(q, endpoint));
            if group.is_empty() { map.remove(&port); }
        }
        endpoint.deactivate();
    }


    /// Atomically change one endpoint's device scope after conflict validation. # C: O(N_port)
    pub fn rebind_udp6_endpoint_iface(&self, endpoint: &Arc<Udp6RxQueue>, iface: Option<NetIfaceId>)
        -> NetResult<()> {
        let tables = self.inet_tables(endpoint.net_ns);
        let map4 = tables.udp.lock();
        let map = tables.udp6.lock();
        let group = map.get(&endpoint.bound_port).ok_or(NetError::Einval)?;
        let new_iface = iface.map(|i| i.raw()).unwrap_or(0);
        if !endpoint.v6only_at_bind() {
            let endpoint_v4 = endpoint.bound_ip.to_v4_mapped();
            if endpoint.bound_ip == Ipv6Addr::ANY || endpoint_v4.is_some() {
                if let Some(group4) = map4.get(&endpoint.bound_port) {
                    for old in group4 {
                        let addr_overlap = endpoint.bound_ip == Ipv6Addr::ANY
                            || old.bound_ip.is_unspecified() || endpoint_v4 == Some(old.bound_ip);
                        if !addr_overlap { continue; }
                        let old_iface = old.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
                        let iface_overlap = old_iface == 0 || new_iface == 0 || old_iface == new_iface;
                        let shared = old.reuseport_member() && endpoint.reuseport_member()
                                && old.owner_uid == endpoint.owner_uid
                            || old.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0
                                && endpoint.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0;
                        if iface_overlap && !shared { return Err(NetError::Eaddrinuse); }
                    }
                }
            }
        }
        for old in group {
            if Arc::ptr_eq(old, endpoint) { continue; }
            let old_iface = old.bound_ifindex.load(core::sync::atomic::Ordering::Acquire);
            let iface_overlap = old_iface == 0 || new_iface == 0 || old_iface == new_iface;
            let addr_overlap = old.bound_ip == Ipv6Addr::ANY || endpoint.bound_ip == Ipv6Addr::ANY
                || old.bound_ip == endpoint.bound_ip;
            let shared = old.reuseport_member() && endpoint.reuseport_member()
                    && old.owner_uid == endpoint.owner_uid
                || old.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0
                    && endpoint.reuseaddr.load(core::sync::atomic::Ordering::Acquire) != 0;
            if iface_overlap && addr_overlap && !shared { return Err(NetError::Eaddrinuse); }
        }
        endpoint.bound_ifindex.store(new_iface, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    pub fn send_udp6_to(
        &self,
        src_ip: Ipv6Addr,
        src_port: u16,
        dst_ip: Ipv6Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> NetResult<()> {
        self.send_udp6_to_in(0, src_ip, src_port, dst_ip, dst_port, payload)
    }

    /// Send UDP/IPv6 through one network namespace. # C: O(payload + N)
    pub fn send_udp6_to_in(&self, net_ns: u64, src_ip: Ipv6Addr, src_port: u16,
        dst_ip: Ipv6Addr, dst_port: u16, payload: &[u8]) -> NetResult<()>
    {
        let src_ip = if src_ip == Ipv6Addr::ANY && dst_ip == Ipv6Addr::LOOPBACK {
            Ipv6Addr::LOOPBACK
        } else {
            src_ip
        };
        let (iface_id, iface) = self.route6_iface_in(net_ns, dst_ip).ok_or(NetError::Enetunreach)?;
        let src_ip = if src_ip.is_unspecified() {
            let hint = self.routes6.lookup_in(net_ns, dst_ip)
                .filter(|route| route.iface == iface_id).and_then(|route| route.src_hint);
            self.v6_select_source(iface_id, dst_ip, hint).ok_or(NetError::Eaddrnotavail)?
        } else { src_ip };
        let l4_len = 8 + payload.len();
        let total = IPV6_HDR_LEN + l4_len;
        let mut p = Pkt::with_capacity(IPV6_HDR_LEN, total + IPV6_HDR_LEN);
        let body = p.put(l4_len).map_err(|_| NetError::Enobufs)?;
        crate::udp::build_into_v6(src_port, dst_port, src_ip, dst_ip, payload, body);
        push_ipv6_header(&mut p, src_ip, dst_ip, IpProto::Udp)
            .map_err(|_| NetError::Enobufs)?;
        p.proto = crate::addr::eth_p::IPV6;
        p.iface = Some(iface_id);
        if !nf_output(&p, NFPROTO_IPV6) {
            return Ok(());
        }
        iface.xmit(p)
    }
}

pub(super) fn refresh_slaac_lifetimes(row: &mut Ipv6IfaceAddr, now_ns: u64) {
    let Ipv6AddrOrigin::Slaac { preferred_until_ns, valid_until_ns, .. } = &row.origin else { return; };
    row.valid = super::ra::remaining_lifetime(now_ns, *valid_until_ns);
    row.preferred = super::ra::remaining_lifetime(now_ns, *preferred_until_ns);
}

fn slaac_valid_deadline(old_deadline_ns: u64, advertised: u32, now_ns: u64) -> u64 {
    let advertised_deadline = super::ra::lifetime_deadline(now_ns, advertised);
    let two_hours_deadline = super::ra::lifetime_deadline(now_ns, super::ra::TWO_HOURS_SECS);
    if advertised > super::ra::TWO_HOURS_SECS || advertised_deadline > old_deadline_ns {
        advertised_deadline
    } else if old_deadline_ns <= two_hours_deadline {
        old_deadline_ns
    } else {
        two_hours_deadline
    }
}
