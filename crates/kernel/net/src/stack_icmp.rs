// F174: ICMP Destination Unreachable handler — extracted from
// stack.rs for the 1000-line cap (docs/08§7). Reconstructs the
// original 4-tuple from the echoed IPv4 header + first 8 bytes
// of L4 and surfaces ECONNREFUSED on the originating socket.

use crate::addr::{IpAddr, IpProto, NetIfaceId};
use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN};
use crate::netdev::{NetError, NetResult};
use crate::stack::{NetStack, TcpKey};

const IPV6_MIN_MTU: u32 = 1_280;

fn rfc4884_data(kind: u8, icmp: &[u8], quote_data_at: usize) -> u32 {
    if !matches!(kind, crate::icmp::ICMP_TYPE_DEST_UNREACH | crate::icmp::ICMP_TYPE_TIME_EXC | 12)
        || icmp.len() < 8 { return 0; }
    let wire_len = usize::from(icmp[5]) * 4;
    if wire_len < 128 || wire_len < quote_data_at { return 0; }
    let ext_at = 8usize.saturating_add(wire_len);
    if ext_at.saturating_add(4) > icmp.len() { return 0; }
    let ext = &icmp[ext_at..];
    let mut flags = 0u8;
    if ext[0] >> 4 == 2 {
        if ext[2..4] != [0, 0] && crate::ipv4::ip_checksum(ext) != 0 { flags = 1; }
        let mut at = 4usize;
        while at < ext.len() {
            if at.saturating_add(4) > ext.len() { flags = 1; break; }
            let len = usize::from(u16::from_be_bytes([ext[at], ext[at + 1]]));
            if len < 4 || at.saturating_add(len) > ext.len() { flags = 1; break; }
            at += len;
        }
    }
    let len = (wire_len - quote_data_at) as u16;
    u32::from_ne_bytes([len.to_ne_bytes()[0], len.to_ne_bytes()[1], flags, 0])
}

fn cached_pmtu(stack: &NetStack, net_ns: u64, iface: NetIfaceId, dst: IpAddr, link_mtu: u32) -> u32 {
    stack.inet_tables(net_ns).pmtu.get(iface, dst, link_mtu)
}

fn update_pmtu_on_iface(stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                        dst: IpAddr, mtu: u32, floor: u32) -> Option<u32> {
    let Some(link_mtu) = stack.ifaces.lookup_in_ns(iface, net_ns).map(|dev| dev.mtu()) else {
        return None;
    };
    Some(stack.inet_tables(net_ns).pmtu.update(iface, dst, mtu, link_mtu, floor))
}

fn update_pmtu_v4(stack: &NetStack, net_ns: u64, dst: crate::Ipv4Addr,
                  bound: Option<NetIfaceId>, mtu: u32) -> Option<u32> {
    let route = match bound {
        Some(iface) => stack.route_v4_on_iface_in(net_ns, dst, iface).ok().flatten()?,
        None => stack.routes.lookup_result_in(net_ns, dst).ok()?,
    };
    let link_mtu = stack.ifaces.lookup_in_ns(route.iface, net_ns)?.mtu();
    if route.metrics.locked(crate::route_metrics::RTAX_MTU) {
        return Some(route.metrics.bounded_mtu(link_mtu));
    }
    update_pmtu_on_iface(stack, net_ns, route.iface, IpAddr::V4(dst), mtu,
        crate::stack::IPV4_MIN_PMTU)
}

impl NetStack {
    /// Effective path MTU for a routed destination. `probe` bypasses learned PMTU. # C: O(N)
    pub fn path_mtu(&self, dst: IpAddr, bound: Option<NetIfaceId>, probe: bool) -> NetResult<u32> {
        self.path_mtu_in(0, dst, bound, probe)
    }

    /// Effective path MTU in one network namespace. # C: O(N)
    pub fn path_mtu_in(&self, net_ns: u64, dst: IpAddr, bound: Option<NetIfaceId>, probe: bool) -> NetResult<u32> {
        if let IpAddr::V4(dst) = dst {
            let route = match bound {
                Some(iface) => self.route_v4_on_iface_in(net_ns, dst, iface)?
                    .unwrap_or(crate::ResolvedRoute {
                        iface,
                        gateway: None,
                        src_hint: None,
                        table: crate::policy_rule::RT_TABLE_MAIN,
                        priority: 0,
                        metrics: crate::RouteMetrics::NONE,
                    }),
                None => self.routes.lookup_result_in(net_ns, dst)?,
            };
            let link_mtu = self.ifaces.lookup_in_ns(route.iface, net_ns)
                .ok_or(NetError::Enetunreach)?.mtu();
            if probe { return Ok(link_mtu); }
            let base_mtu = route.metrics.bounded_mtu(link_mtu);
            if route.metrics.locked(crate::route_metrics::RTAX_MTU) {
                return Ok(base_mtu);
            }
            return Ok(cached_pmtu(self, net_ns, route.iface, IpAddr::V4(dst), base_mtu));
        }
        let (iface, link_mtu) = match (dst, bound) {
            (_, Some(iface)) => (iface, self.ifaces.lookup_in_ns(iface, net_ns)
                .ok_or(NetError::Enetunreach)?.mtu()),
            (IpAddr::V6(dst), None) => {
                let (iface, dev) = self.route6_iface_in(net_ns, dst).ok_or(NetError::Enetunreach)?;
                (iface, dev.mtu())
            }
            (IpAddr::V4(_), None) => unreachable!(),
        };
        if probe { return Ok(link_mtu); }
        Ok(cached_pmtu(self, net_ns, iface, dst, link_mtu))
    }

    /// Init-namespace PMTU update for hosted tests. # C: O(log N)
    #[cfg(test)]
    pub(crate) fn update_pmtu_v6(&self, iface: NetIfaceId, dst: crate::Ipv6Addr, mtu: u32) {
        self.update_pmtu_v6_in(0, iface, dst, mtu)
    }

    /// Record validated ICMPv6 PMTU in one network namespace. # C: O(log N)
    pub(crate) fn update_pmtu_v6_in(&self, net_ns: u64, iface: NetIfaceId, dst: crate::Ipv6Addr, mtu: u32) {
        update_pmtu_on_iface(self, net_ns, iface, IpAddr::V6(dst), mtu, IPV6_MIN_MTU);
    }
}

enum UdpErrorTarget {
    V4(alloc::sync::Arc<crate::UdpRxQueue>),
    V6(alloc::sync::Arc<crate::stack_ipv6::Udp6RxQueue>),
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum UdpReuseGroup {
    V4(u32, crate::Ipv4Addr, u32),
    V6(u32, crate::Ipv6Addr, u32),
}

impl UdpErrorTarget {
    fn bound_iface(&self) -> Option<NetIfaceId> {
        use core::sync::atomic::Ordering;
        let raw = match self {
            Self::V4(endpoint) => endpoint.bound_ifindex.load(Ordering::Acquire),
            Self::V6(endpoint) => endpoint.bound_ifindex.load(Ordering::Acquire),
        };
        (raw != 0).then(|| NetIfaceId::from_raw(raw))
    }

    fn pmtudisc(&self) -> i32 {
        use core::sync::atomic::Ordering;
        match self {
            Self::V4(endpoint) => endpoint.ip_mtu_discover.load(Ordering::Acquire),
            Self::V6(endpoint) => endpoint.ip_mtu_discover.load(Ordering::Acquire),
        }
    }

    fn reuseport(&self) -> bool {
        use core::sync::atomic::Ordering;
        match self {
            Self::V4(endpoint) => endpoint.reuseport.load(Ordering::Acquire) != 0,
            Self::V6(endpoint) => endpoint.reuseport.load(Ordering::Acquire) != 0,
        }
    }

    fn reuse_group(&self) -> UdpReuseGroup {
        use core::sync::atomic::Ordering;
        match self {
            Self::V4(endpoint) => UdpReuseGroup::V4(
                endpoint.owner_uid, endpoint.bound_ip,
                endpoint.bound_ifindex.load(Ordering::Acquire),
            ),
            Self::V6(endpoint) => UdpReuseGroup::V6(
                endpoint.owner_uid, endpoint.bound_ip,
                endpoint.bound_ifindex.load(Ordering::Acquire),
            ),
        }
    }

    fn publish(self, entry: crate::SocketErrorEntry, hard: bool) {
        match self {
            Self::V4(endpoint) => { endpoint.publish_error(entry, hard); }
            Self::V6(endpoint) => { endpoint.publish_error(entry, hard); }
        }
    }

}

fn udp_error_target(stack: &NetStack, net_ns: u64, iface: crate::NetIfaceId,
                    local: crate::Ipv4Addr, local_port: u16,
                    remote: crate::Ipv4Addr, remote_port: u16) -> Option<UdpErrorTarget> {
    use core::sync::atomic::Ordering;
    let mut candidates = alloc::vec::Vec::new();
    let tables = stack.inet_tables(net_ns);
    for endpoint in tables.udp.lock().get(&local_port).cloned().unwrap_or_default() {
        let bound_iface = endpoint.bound_ifindex.load(Ordering::Acquire);
        if bound_iface != 0 && bound_iface != iface.raw() { continue; }
        if !endpoint.bound_ip.is_unspecified() && endpoint.bound_ip != local { continue; }
        let peer = *endpoint.peer.lock();
        if peer.is_some() && peer != Some((remote, remote_port)) { continue; }
        let score = u8::from(peer.is_some()) * 4
            + u8::from(!endpoint.bound_ip.is_unspecified()) * 2 + u8::from(bound_iface != 0);
        candidates.push((score, UdpErrorTarget::V4(endpoint)));
    }
    let remote6 = crate::Ipv6Addr::from_v4_mapped(remote);
    for endpoint in tables.udp6.lock().get(&local_port).cloned().unwrap_or_default() {
        if endpoint.v6only.load(Ordering::Acquire) != 0 { continue; }
        let bound_iface = endpoint.bound_ifindex.load(Ordering::Acquire);
        if bound_iface != 0 && bound_iface != iface.raw() { continue; }
        if endpoint.bound_ip != crate::Ipv6Addr::ANY
            && endpoint.bound_ip.to_v4_mapped() != Some(local) { continue; }
        let peer = *endpoint.peer.lock();
        if peer.is_some() && peer != Some((remote6, remote_port)) { continue; }
        let score = u8::from(peer.is_some()) * 4
            + u8::from(endpoint.bound_ip != crate::Ipv6Addr::ANY) * 2 + u8::from(bound_iface != 0);
        candidates.push((score, UdpErrorTarget::V6(endpoint)));
    }
    let best = candidates.iter().map(|(score, _)| *score).max()?;
    candidates.retain(|(score, _)| *score == best);
    if candidates.len() == 1 { return candidates.pop().map(|(_, endpoint)| endpoint); }
    let winner = candidates.last().map(|(_, endpoint)| endpoint);
    if winner.is_some_and(UdpErrorTarget::reuseport) {
        let group = candidates.last().expect("candidates is nonempty").1.reuse_group();
        candidates.retain(|(_, endpoint)| endpoint.reuseport() && endpoint.reuse_group() == group);
        let hash = remote.as_u32().rotate_left(7) ^ local.as_u32().rotate_left(19)
            ^ u32::from(remote_port).rotate_left(11) ^ u32::from(local_port);
        return Some(candidates.swap_remove(hash as usize % candidates.len()).1);
    }
    candidates.pop().map(|(_, endpoint)| endpoint)
}

/// Init-namespace hosted-test entry point. # C: O(log N)
#[cfg(test)]
pub fn handle_error(stack: &NetStack, iface: crate::NetIfaceId, offender: crate::Ipv4Addr,
                    kind: u8, code: u8, payload: &[u8]) {
    handle_error_in(stack, 0, iface, offender, kind, code, payload)
}

/// Handle an IPv4 ICMP error in the ingress network namespace. # C: O(log N)
pub fn handle_error_in(stack: &NetStack, net_ns: u64, iface: crate::NetIfaceId, offender: crate::Ipv4Addr,
                    kind: u8, code: u8, payload: &[u8]) {
    const ICMP_HDR: usize = 8;
    if payload.len() < ICMP_HDR + IPV4_HDR_LEN + 8 { return; }
    let orig_ip = &payload[ICMP_HDR..];
    let orig_hdr = match Ipv4Hdr::parse(orig_ip) { Ok(h) => h, Err(_) => return };
    let orig_l4_off = orig_hdr.ihl_bytes();
    if orig_ip.len() < orig_l4_off + 8 { return; }
    let orig_l4 = &orig_ip[orig_l4_off..orig_l4_off + 8];
    let src_port = u16::from_be_bytes([orig_l4[0], orig_l4[1]]);
    let dst_port = u16::from_be_bytes([orig_l4[2], orig_l4[3]]);
    let reported_mtu = u16::from_be_bytes([payload[6], payload[7]]);
    let frag_mtu = if kind == crate::icmp::ICMP_TYPE_DEST_UNREACH && code == 4 {
        Some(u32::from(reported_mtu))
    } else { None };
    let (eno, hard) = match kind {
        k if k == crate::icmp::ICMP_TYPE_TIME_EXC =>
            (syscall::errno::Errno::Ehostunreach as i32, false),
        12 => (syscall::errno::Errno::Eproto as i32, true),
        k if k == crate::icmp::ICMP_TYPE_DEST_UNREACH => match code {
            0 => (syscall::errno::Errno::Enetunreach as i32, false),
            1 => (syscall::errno::Errno::Ehostunreach as i32, false),
            2 => (syscall::errno::Errno::Enoprotoopt as i32, true),
            3 => (syscall::errno::Errno::Econnrefused as i32, true),
            4 => (syscall::errno::Errno::Emsgsize as i32, false),
            5 => (syscall::errno::Errno::Eopnotsupp as i32, false),
            6 | 9 => (syscall::errno::Errno::Enetunreach as i32, true),
            7 => (syscall::errno::Errno::Ehostdown as i32, true),
            8 => (syscall::errno::Errno::Enonet as i32, true),
            10 | 13 | 14 | 15 => (syscall::errno::Errno::Ehostunreach as i32, true),
            11 => (syscall::errno::Errno::Enetunreach as i32, false),
            12 => (syscall::errno::Errno::Ehostunreach as i32, false),
            _ => return,
        },
        _ => return,
    };
    let raw_entry = crate::SocketErrorEntry {
        errno: eno, origin: crate::socket_error::SO_EE_ORIGIN_ICMP,
        kind, code, info: frag_mtu.map_or(0, |_| u32::from(reported_mtu)),
        data: rfc4884_data(kind, payload, orig_l4_off),
        offender: IpAddr::V4(offender), destination: IpAddr::V4(orig_hdr.dst),
        destination_port: 0, ifindex: iface.raw(),
        payload: orig_ip[orig_l4_off..].to_vec(),
    };
    for endpoint in stack.inet_tables(net_ns).raw4.endpoints(orig_hdr.proto) {
        if endpoint.matches_error(iface, orig_hdr.src, orig_hdr.dst) {
            if let Some(mtu) = frag_mtu {
                if crate::uapi::ip_pmtudisc_accepts_pmtu(endpoint.pmtudisc()) {
                    update_pmtu_v4(stack, net_ns, orig_hdr.dst,
                        endpoint.snapshot().bound_iface, mtu);
                }
            }
            endpoint.publish_quoted_error(raw_entry.clone(), hard, orig_ip);
        }
    }
    if orig_hdr.proto == IpProto::Icmp as u8 {
        // The quoted probe carries the echo identifier this kernel stamped, so
        // an error reaches the endpoint that originated it.
        let quoted = &orig_ip[orig_l4_off..];
        stack.report_ping_error_v4(net_ns, iface, orig_hdr.src, quoted, raw_entry.clone(), hard,
            orig_ip);
    }
    if kind == crate::icmp::ICMP_TYPE_DEST_UNREACH && code == 4
        && orig_hdr.proto == IpProto::Tcp as u8
    {
        let key = TcpKey {
            local_ip:    IpAddr::V4(orig_hdr.src),
            local_port:  src_port,
            remote_ip:   IpAddr::V4(orig_hdr.dst),
            remote_port: dst_port,
        };
        let quoted_seq = u32::from_be_bytes([orig_l4[4], orig_l4[5], orig_l4[6], orig_l4[7]]);
        if let Some(entry) = stack.tcp_frag_needed_entry_in(net_ns, key, quoted_seq) {
            if !entry.accepts_pmtu_update() { return; }
            let mtu = frag_mtu.expect("frag-needed MTU is present");
            if let Some(effective) = update_pmtu_v4(
                stack, net_ns, orig_hdr.dst, entry.bound_iface(), mtu,
            ) {
                stack.tcp_mtu_reduced(&entry, effective);
            }
        }
        return;
    }
    match orig_hdr.proto {
        p if p == IpProto::Udp as u8 => {
            let entry = crate::SocketErrorEntry {
                    errno: eno,
                    origin: crate::socket_error::SO_EE_ORIGIN_ICMP,
                    kind,
                    code,
                    info: if frag_mtu.is_some() { u32::from(reported_mtu) } else { 0 },
                    data: rfc4884_data(kind, payload, orig_l4_off + 8),
                    offender: IpAddr::V4(offender),
                    destination: IpAddr::V4(orig_hdr.dst),
                    destination_port: dst_port,
                    ifindex: iface.raw(),
                    payload: orig_ip[orig_l4_off + 8..].to_vec(),
                };
            if let Some(target) = udp_error_target(
                stack, net_ns, iface, orig_hdr.src, src_port, orig_hdr.dst, dst_port,
            ) {
                if let Some(mtu) = frag_mtu {
                    let mode = target.pmtudisc();
                    if crate::uapi::ip_pmtudisc_accepts_pmtu(mode) {
                        update_pmtu_v4(stack, net_ns, orig_hdr.dst, target.bound_iface(), mtu);
                    }
                    if mode == crate::uapi::IP_PMTUDISC_DONT { return; }
                    target.publish(entry, true);
                } else { target.publish(entry, hard); }
            }
        }
        p if p == IpProto::Tcp as u8 => {
            let key = TcpKey {
                local_ip:    IpAddr::V4(orig_hdr.src),
                local_port:  src_port,
                remote_ip:   IpAddr::V4(orig_hdr.dst),
                remote_port: dst_port,
            };
            if let Some(entry) = stack.inet_tables(net_ns).tcp_conns.lock().get(&key).cloned() {
                let mut c = entry.conn.lock();
                c.state = crate::tcp_state::TcpState::Closed;
                drop(c);
                entry.set_error(eno);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
        }
        _ => {}
    }
}
