use super::*;
use core::sync::atomic::Ordering;

const SOCK_DGRAM: u8 = 2;
const ETHERNET_HEADER_LEN: usize = 14;
const PACKET_QUEUE_MAX: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketAddr {
    pub ifindex: u32,
    pub protocol: u16,
    pub hatype: u16,
    pub pkttype: u8,
    pub halen: u8,
    pub addr: [u8; 8],
}

#[derive(Clone)]
pub struct PacketFrame {
    pub payload: Vec<u8>,
    pub addr: PacketAddr,
}

struct Observation<'a> {
    bytes: &'a [u8],
    raw_protocol: u16,
    datagram_protocol: u16,
    link_header_len: usize,
    pkttype: u8,
    hatype: u16,
    halen: u8,
    addr: [u8; 8],
}

/// Process-global weak AF_PACKET socket registry; dead rows are collected on use.
pub static PACKET_REGISTRY: Spinlock<Vec<alloc::sync::Weak<InetSocket>>, SockLockClass>
    = Spinlock::new(Vec::new());

/// Add one packet socket idempotently. # C: O(N)
pub fn register_packet(sock: &Arc<InetSocket>) {
    let mut registry = PACKET_REGISTRY.lock();
    registry.retain(|weak| weak.upgrade().is_some());
    if registry.iter().filter_map(alloc::sync::Weak::upgrade)
        .any(|registered| Arc::ptr_eq(&registered, sock)) { return; }
    registry.push(Arc::downgrade(sock));
}

/// Stable identity used only while a retained socket performs synchronous transmit. # C: O(1)
pub fn packet_origin(sock: &Arc<InetSocket>) -> usize { Arc::as_ptr(sock) as usize }

/// Observe one admitted Ethernet ingress frame exactly once. # C: O(N sockets + frame)
pub fn deliver_packet_ingress_in(lease: &crate::IngressLease, frame: &[u8]) {
    if frame.len() < ETHERNET_HEADER_LEN { return; }
    let (raw_protocol, datagram_protocol, link_header_len) = link_protocols(frame);
    let mut source = [0u8; 8]; source[..6].copy_from_slice(&frame[6..12]);
    let mut destination = [0u8; 6]; destination.copy_from_slice(&frame[..6]);
    let pkttype = if destination == crate::MacAddr::BROADCAST.0 {
        crate::uapi::PACKET_BROADCAST
    } else if crate::MacAddr(destination).is_multicast() {
        crate::uapi::PACKET_MULTICAST
    } else if destination == lease.device().mac().0 {
        crate::uapi::PACKET_HOST
    } else {
        crate::uapi::PACKET_OTHERHOST
    };
    deliver(lease.net_ns(), lease.iface(), Observation {
        bytes: frame, raw_protocol, datagram_protocol, link_header_len, pkttype,
        hatype: link_hatype(lease.device()), halen: 6, addr: source,
    }, None);
}

/// Observe one admitted loopback ingress packet with Linux's headerless view. # C: O(N sockets + packet)
pub fn deliver_packet_loopback_in(lease: &crate::IngressLease, packet: &[u8], protocol: u16) {
    deliver(lease.net_ns(), lease.iface(), Observation {
        bytes: packet, raw_protocol: protocol, datagram_protocol: protocol,
        link_header_len: 0, pkttype: crate::uapi::PACKET_HOST,
        hatype: crate::uapi::ARPHRD_LOOPBACK, halen: 6, addr: [0; 8],
    }, None);
}

/// Observe one admitted egress packet before driver ownership transfer. # C: O(N sockets + packet)
pub(crate) fn deliver_packet_egress_in(lease: &crate::EgressLease, bytes: &[u8],
    protocol: u16, link_header_len: usize, origin: Option<usize>)
{
    if link_header_len > bytes.len() { return; }
    let (raw_protocol, datagram_protocol, link_header_len) = if link_header_len >= ETHERNET_HEADER_LEN {
        link_protocols(bytes)
    } else { (protocol, protocol, link_header_len) };
    let mut source = [0u8; 8];
    let hatype = link_hatype(lease.device());
    let halen = if link_header_len >= ETHERNET_HEADER_LEN {
        source[..6].copy_from_slice(&bytes[6..12]); 6
    } else if hatype == crate::uapi::ARPHRD_LOOPBACK { 6 } else { 0 };
    deliver(lease.net_ns(), lease.iface(), Observation {
        bytes, raw_protocol, datagram_protocol, link_header_len,
        pkttype: crate::uapi::PACKET_OUTGOING,
        hatype, halen, addr: source,
    }, origin);
}

fn deliver(net_ns: u64, iface: NetIfaceId, observation: Observation<'_>, origin: Option<usize>) {
    let sockets = {
        let mut registry = PACKET_REGISTRY.lock();
        registry.retain(|weak| weak.upgrade().is_some());
        registry.iter().filter_map(alloc::sync::Weak::upgrade).collect::<Vec<_>>()
    };
    let mut woken = Vec::new();
    for sock in sockets {
        if sock.net_ns() != net_ns || origin == Some(Arc::as_ptr(&sock) as usize) { continue; }
        let kind = sock.kind.lock();
        let SockKind::Packet { ifindex, protocol, sock_type, options, rx } = &*kind else { continue };
        let wanted_iface = ifindex.load(Ordering::Acquire);
        if wanted_iface != 0 && wanted_iface != iface.raw() { continue; }
        let datagram = sock_type.load(Ordering::Acquire) == SOCK_DGRAM;
        let observed_protocol = if datagram {
            observation.datagram_protocol
        } else { observation.raw_protocol };
        let wanted_protocol = protocol.load(Ordering::Acquire);
        if wanted_protocol != crate::eth_p::ALL && wanted_protocol != observed_protocol { continue; }
        if observation.pkttype == crate::uapi::PACKET_OUTGOING
            && options.ignore_outgoing() { continue; }
        let header_len = if datagram { observation.link_header_len } else { 0 };
        let packet = &observation.bytes[header_len..];
        let verdict = sock.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
            packet, protocol: observed_protocol, ifindex: Some(iface.raw()),
            pay_offset: packet_payload_offset(packet, if datagram { 0 } else { observation.link_header_len }),
            hatype: observation.hatype,
        });
        if verdict == 0 { continue; }
        let queued = PacketFrame {
            payload: packet[..packet.len().min(verdict as usize)].to_vec(),
            addr: PacketAddr { ifindex: iface.raw(), protocol: observed_protocol,
                hatype: observation.hatype, pkttype: observation.pkttype,
                halen: observation.halen, addr: observation.addr },
        };
        let mut queue = rx.lock();
        if queue.len() >= PACKET_QUEUE_MAX { continue; }
        queue.push_back(queued);
        drop(queue); drop(kind);
        woken.push(sock);
    }
    for sock in woken {
        #[cfg(target_os = "oxide-kernel")]
        sock.recv_waiters.wake_all();
        sock.poll_subs.notify();
    }
}

fn link_protocols(frame: &[u8]) -> (u16, u16, usize) {
    if frame.len() < ETHERNET_HEADER_LEN { return (0, 0, 0); }
    let raw = u16::from_be_bytes([frame[12], frame[13]]);
    let mut protocol = raw;
    let mut header_len = ETHERNET_HEADER_LEN;
    while matches!(protocol, crate::eth_p::VLAN | crate::eth_p::VLAN_AD)
        && frame.len() >= header_len + crate::ethernet::ETH_VLAN_TAG_LEN
    {
        protocol = u16::from_be_bytes([frame[header_len + 2], frame[header_len + 3]]);
        header_len += crate::ethernet::ETH_VLAN_TAG_LEN;
    }
    (raw, protocol, header_len)
}

fn link_hatype(device: &dyn crate::NetDev) -> u16 {
    device.hardware_type()
}

fn packet_payload_offset(packet: &[u8], link_header_len: usize) -> u32 {
    let network = link_header_len;
    let Some(version) = packet.get(network).map(|byte| byte >> 4) else { return network as u32 };
    let offset = match version {
        4 => {
            let ihl = packet.get(network).map_or(20, |byte| ((byte & 0x0f) as usize * 4).max(20));
            transport_payload_offset(packet, network + ihl,
                packet.get(network + 9).copied().unwrap_or(0))
        }
        6 => transport_payload_offset(packet, network + 40,
            packet.get(network + 6).copied().unwrap_or(0)),
        _ => network,
    };
    offset.min(packet.len()) as u32
}

fn transport_payload_offset(packet: &[u8], transport: usize, protocol: u8) -> usize {
    match protocol {
        6 => transport + packet.get(transport + 12)
            .map_or(20, |byte| ((byte >> 4) as usize * 4).max(20)),
        17 => transport + 8,
        _ => transport,
    }
}
