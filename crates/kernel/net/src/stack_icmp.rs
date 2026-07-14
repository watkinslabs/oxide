// F174: ICMP Destination Unreachable handler — extracted from
// stack.rs for the 1000-line cap (docs/08§7). Reconstructs the
// original 4-tuple from the echoed IPv4 header + first 8 bytes
// of L4 and surfaces ECONNREFUSED on the originating socket.

use crate::addr::{IpAddr, IpProto, NetIfaceId};
use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN};
use crate::netdev::{NetError, NetResult};
use crate::stack::{NetStack, TcpKey};

const IPV4_MIN_MTU: u32 = 68;
const IPV6_MIN_MTU: u32 = 1_280;
const IPV4_PLATEAUS: [u32; 10] = [65_535, 32_000, 17_914, 8_166, 4_352, 2_002, 1_492, 1_006, 508, 296];

fn cached_pmtu(stack: &NetStack, net_ns: u64, iface: NetIfaceId, dst: IpAddr, link_mtu: u32) -> u32 {
    stack.inet_tables(net_ns).pmtu.lock().get(&(iface, dst)).copied()
        .unwrap_or(link_mtu).min(link_mtu)
}

fn update_pmtu(stack: &NetStack, net_ns: u64, iface: NetIfaceId, dst: IpAddr, mtu: u32) {
    let key = (iface, dst);
    let tables = stack.inet_tables(net_ns);
    let mut cache = tables.pmtu.lock();
    match cache.get_mut(&key) {
        Some(old) if mtu < *old => *old = mtu,
        None => { cache.insert(key, mtu); }
        _ => {}
    }
}

fn ipv4_frag_needed_mtu(hdr: &Ipv4Hdr, reported: u16) -> u32 {
    if reported != 0 { return u32::from(reported).max(IPV4_MIN_MTU); }
    let packet_len = u32::from(hdr.total_len);
    IPV4_PLATEAUS.iter().copied().find(|mtu| *mtu < packet_len).unwrap_or(IPV4_MIN_MTU)
}

impl NetStack {
    /// Effective path MTU for a routed destination. `probe` bypasses learned PMTU. # C: O(N)
    pub fn path_mtu(&self, dst: IpAddr, bound: Option<NetIfaceId>, probe: bool) -> NetResult<u32> {
        self.path_mtu_in(0, dst, bound, probe)
    }

    /// Effective path MTU in one network namespace. # C: O(N)
    pub fn path_mtu_in(&self, net_ns: u64, dst: IpAddr, bound: Option<NetIfaceId>, probe: bool) -> NetResult<u32> {
        let (iface, link_mtu) = match (dst, bound) {
            (_, Some(iface)) => (iface, self.ifaces.lookup_in_ns(iface, net_ns)
                .ok_or(NetError::Enetunreach)?.mtu()),
            (IpAddr::V4(dst), None) => {
                let route = self.routes.lookup_result_in(net_ns, dst)?;
                let mtu = self.ifaces.lookup_in_ns(route.iface, net_ns).ok_or(NetError::Enetunreach)?.mtu();
                (route.iface, mtu)
            }
            (IpAddr::V6(dst), None) => {
                let (iface, dev) = self.route6_iface_in(net_ns, dst).ok_or(NetError::Enetunreach)?;
                (iface, dev.mtu())
            }
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
        update_pmtu(self, net_ns, iface, IpAddr::V6(dst), mtu.max(IPV6_MIN_MTU));
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

    fn suppress_frag_needed(&self) -> bool {
        use core::sync::atomic::Ordering;
        match self {
            Self::V4(endpoint) => endpoint.ip_mtu_discover.load(Ordering::Acquire)
                == crate::uapi::IP_PMTUDISC_DONT,
            Self::V6(_) => false,
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
        let mtu = ipv4_frag_needed_mtu(&orig_hdr, reported_mtu);
        update_pmtu(stack, net_ns, iface, IpAddr::V4(orig_hdr.dst), mtu);
        Some(mtu)
    } else { None };
    // F191: ICMP code 4 (fragmentation needed) carries the next-hop
    // MTU in payload bytes 6..8 of the ICMP message (the part that
    // used to be "unused"). Use it to clamp the affected TCP conn's
    // peer_mss; do NOT surface as a fatal SO_ERROR.
    if kind == crate::icmp::ICMP_TYPE_DEST_UNREACH && code == 4
        && orig_hdr.proto == IpProto::Tcp as u8
    {
        let new_mss = frag_mtu.unwrap_or(IPV4_MIN_MTU).saturating_sub(40)
            .min(u32::from(u16::MAX)) as u16;
        let key = TcpKey {
            local_ip:    IpAddr::V4(orig_hdr.src),
            local_port:  src_port,
            remote_ip:   IpAddr::V4(orig_hdr.dst),
            remote_port: dst_port,
        };
        if let Some(entry) = stack.inet_tables(net_ns).tcp_conns.lock().get(&key).cloned() {
            let mut c = entry.conn.lock();
            if new_mss >= 536 && (c.peer_mss == 0 || new_mss < c.peer_mss) {
                c.peer_mss = new_mss;
            }
        }
        return;
    }
    let (eno, hard) = match kind {
        k if k == crate::icmp::ICMP_TYPE_TIME_EXC =>
            (syscall::errno::Errno::Ehostunreach as i32, false),
        12 => (syscall::errno::Errno::Eproto as i32, true),
        k if k == crate::icmp::ICMP_TYPE_DEST_UNREACH => match code {
            0 => (syscall::errno::Errno::Enetunreach as i32, false),
            1 => (syscall::errno::Errno::Ehostunreach as i32, false),
            2 => (syscall::errno::Errno::Enoprotoopt as i32, true),
            3 => (syscall::errno::Errno::Econnrefused as i32, true),
            4 => (syscall::errno::Errno::Emsgsize as i32, true),
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
    match orig_hdr.proto {
        p if p == IpProto::Udp as u8 => {
            let entry = crate::SocketErrorEntry {
                    errno: eno,
                    origin: crate::socket_error::SO_EE_ORIGIN_ICMP,
                    kind,
                    code,
                    info: if frag_mtu.is_some() { u32::from(reported_mtu) } else { 0 },
                    data: 0,
                    offender: IpAddr::V4(offender),
                    destination: IpAddr::V4(orig_hdr.dst),
                    destination_port: dst_port,
                    ifindex: iface.raw(),
                    payload: orig_ip[orig_l4_off + 8..].to_vec(),
                };
            if let Some(target) = udp_error_target(
                stack, net_ns, iface, orig_hdr.src, src_port, orig_hdr.dst, dst_port,
            ) {
                if kind == crate::icmp::ICMP_TYPE_DEST_UNREACH && code == 4
                    && target.suppress_frag_needed() { return; }
                target.publish(entry, hard);
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
