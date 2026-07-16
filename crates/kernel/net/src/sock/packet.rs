use super::*;
use crate::{PacketRxMetadata, PacketVlan};
use core::sync::atomic::Ordering;

const SOCK_DGRAM: u8 = 2;
const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone, Copy)]
struct PacketReceivePolicy { vnet_hdr_size: u8, copy_thresh: bool, timestamp: i32 }

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
    pub aux: PacketAuxData,
    pub(crate) charge: usize,
}

#[derive(Clone, Copy)]
struct Observation<'a> {
    bytes: &'a [u8],
    raw_protocol: u16,
    datagram_protocol: u16,
    link_header_len: usize,
    pkttype: u8,
    hatype: u16,
    halen: u8,
    addr: [u8; 8],
    metadata: PacketRxMetadata,
    fallback_timestamp_ns: u64,
    original_iface: NetIfaceId,
    inline_vlan: Option<PacketVlan>,
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

/// Close packet sockets owned by one network namespace before its state drops. # C: O(N)
pub(crate) fn teardown_packet_namespace(net_ns: u64) -> bool {
    let sockets = {
        let mut registry = PACKET_REGISTRY.lock();
        registry.retain(|weak| weak.upgrade().is_some());
        registry.iter().filter_map(alloc::sync::Weak::upgrade)
            .filter(|socket| socket.net_ns() == net_ns).collect::<Vec<_>>()
    };
    let mut removed = false;
    for socket in sockets {
        if socket.released.swap(true, Ordering::AcqRel) { continue; }
        removed = true;
        socket.read_shut.store(true, Ordering::Release);
        socket.release_packet_memberships();
        socket.release_packet_fanout();
        socket.release_packet_rings();
        socket.error.set(syscall::errno::Errno::Enetdown as i32);
        socket.poll_subs.notify();
        #[cfg(target_os = "oxide-kernel")]
        socket.recv_waiters.wake_all();
    }
    removed
}

/// Stable identity used only while a retained socket performs synchronous transmit. # C: O(1)
pub fn packet_origin(sock: &InetSocket) -> usize { sock as *const InetSocket as usize }

/// Observe one admitted Ethernet ingress frame exactly once. # C: O(N sockets + frame)
pub fn deliver_packet_ingress_in(lease: &crate::IngressLease, frame: &[u8]) {
    deliver_packet_ingress_meta_in(lease, frame, PacketRxMetadata::default());
}

/// Observe Ethernet ingress with driver checksum/VLAN metadata. # C: O(N sockets + frame)
pub fn deliver_packet_ingress_meta_in(lease: &crate::IngressLease, frame: &[u8],
                                      metadata: PacketRxMetadata) {
    deliver_packet_ingress_from_in(lease, lease, frame, metadata);
}

/// Observe bridged ingress while retaining observed and original generations. # C: O(N sockets + frame)
pub fn deliver_packet_ingress_from_in(lease: &crate::IngressLease,
    original: &crate::IngressLease, frame: &[u8], metadata: PacketRxMetadata)
{
    if original.net_ns() != lease.net_ns() { return; }
    deliver_packet_link_receive(lease.net_ns(), lease.iface(), lease.device(),
        original.iface(), frame, metadata);
}

/// Inject one loopback transmit into Linux's receive packet tap. # C: O(N sockets + frame)
pub(crate) fn deliver_packet_loopback_frame_in(lease: &crate::EgressLease, frame: &[u8]) {
    deliver_packet_link_receive(lease.net_ns(), lease.iface(), lease.device(),
        lease.iface(), frame, PacketRxMetadata::default());
}

fn deliver_packet_link_receive(net_ns: u64, iface: NetIfaceId, device: &dyn crate::NetDev,
    original_iface: NetIfaceId, frame: &[u8], metadata: PacketRxMetadata)
{
    if frame.len() < ETHERNET_HEADER_LEN { return; }
    let fallback_timestamp_ns = vfs::inode_times::realtime_now_ns();
    let (raw_protocol, datagram_protocol, link_header_len) = link_protocols(frame);
    let mut source = [0u8; 8]; source[..6].copy_from_slice(&frame[6..12]);
    let mut destination = [0u8; 6]; destination.copy_from_slice(&frame[..6]);
    let pkttype = if destination == device.broadcast().0 {
        crate::uapi::PACKET_BROADCAST
    } else if crate::MacAddr(destination).is_multicast() {
        crate::uapi::PACKET_MULTICAST
    } else if destination == device.mac().0 {
        crate::uapi::PACKET_HOST
    } else {
        crate::uapi::PACKET_OTHERHOST
    };
    deliver(net_ns, iface, Observation {
        bytes: frame, raw_protocol, datagram_protocol, link_header_len, pkttype,
        hatype: link_hatype(device), halen: 6, addr: source,
        metadata, fallback_timestamp_ns, original_iface,
        inline_vlan: inline_vlan(frame),
    }, None);
}

/// Observe one admitted loopback ingress packet with Linux's headerless view. # C: O(N sockets + packet)
pub fn deliver_packet_loopback_in(lease: &crate::IngressLease, packet: &[u8], protocol: u16) {
    let metadata = PacketRxMetadata::default();
    let fallback_timestamp_ns = vfs::inode_times::realtime_now_ns();
    deliver(lease.net_ns(), lease.iface(), Observation {
        bytes: packet, raw_protocol: protocol, datagram_protocol: protocol,
        link_header_len: 0, pkttype: crate::uapi::PACKET_HOST,
        hatype: crate::uapi::ARPHRD_LOOPBACK, halen: 6, addr: [0; 8],
        metadata, fallback_timestamp_ns, original_iface: lease.iface(),
        inline_vlan: None,
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
    let metadata = PacketRxMetadata::default();
    let fallback_timestamp_ns = vfs::inode_times::realtime_now_ns();
    deliver(lease.net_ns(), lease.iface(), Observation {
        bytes, raw_protocol, datagram_protocol, link_header_len,
        pkttype: crate::uapi::PACKET_OUTGOING,
        hatype, halen, addr: source,
        metadata, fallback_timestamp_ns, original_iface: lease.iface(),
        inline_vlan: inline_vlan(bytes),
    }, origin);
}

fn deliver(net_ns: u64, iface: NetIfaceId, observation: Observation<'_>, origin: Option<usize>) {
    let sockets = {
        let mut registry = PACKET_REGISTRY.lock();
        registry.retain(|weak| weak.upgrade().is_some());
        registry.iter().filter_map(alloc::sync::Weak::upgrade).collect::<Vec<_>>()
    };
    let mut ordinary = Vec::new();
    let mut groups = Vec::new();
    let mut origin_group = None;
    for sock in sockets {
        if sock.net_ns() != net_ns { continue; }
        let is_origin = origin == Some(Arc::as_ptr(&sock) as usize);
        if let Some(member) = packet_fanout_membership(&sock) {
            let group = packet_fanout_group(&member);
            if is_origin { origin_group = Some(group); continue; }
            if !groups.iter().any(|known| Arc::ptr_eq(known, &group)) { groups.push(group); }
        } else if !is_origin { ordinary.push(sock); }
    }
    if let Some(origin_group) = origin_group {
        groups.retain(|group| !Arc::ptr_eq(group, &origin_group));
    }
    let mut woken = Vec::new();
    for sock in ordinary {
        if enqueue_packet(&sock, net_ns, iface, observation, origin, true) { woken.push(sock); }
    }
    for group in groups {
        if observation.pkttype == crate::uapi::PACKET_OUTGOING {
            if !group.accepts_outgoing() || group.ignores_outgoing() { continue; }
        }
        let defragmented = if group.defrag() {
            match group.defragment(observation.bytes, observation.link_header_len) {
                Some(packet) => Some(packet), None => continue,
            }
        } else { None };
        let group_observation = if let Some(packet) = defragmented.as_deref() {
            Observation { bytes: packet, ..observation }
        } else { observation };
        let packet = group_observation.bytes;
        let context = crate::bpf_filter::FilterContext {
            packet, protocol: observation.datagram_protocol, ifindex: Some(iface.raw()),
            pay_offset: packet_payload_offset(packet, observation.link_header_len),
            hatype: observation.hatype,
        };
        let charge = linux_packet_skb_truesize(packet.len());
        let Some(member) = group.select(packet, context,
            packet_flow_hash(packet, observation.link_header_len), current_cpu(),
            observation.metadata.queue as u32, charge) else { continue; };
        let Some((sock, queued)) = with_packet_fanout_socket(&member, |sock| {
            enqueue_packet(sock, net_ns, iface, group_observation, origin, false)
        }) else { continue; };
        if queued { woken.push(sock); }
    }
    for sock in woken {
        #[cfg(target_os = "oxide-kernel")]
        sock.recv_waiters.wake_all();
        sock.poll_subs.notify();
    }
}

fn enqueue_packet(sock: &Arc<InetSocket>, net_ns: u64, iface: NetIfaceId,
                  observation: Observation<'_>, origin: Option<usize>, socket_hook: bool) -> bool {
        if sock.released.load(Ordering::Acquire) { return false; }
        if sock.net_ns() != net_ns || origin == Some(Arc::as_ptr(sock) as usize) { return false; }
        let mut rings = sock.packet_rings.lock();
        let kind = sock.kind.lock();
        let SockKind::Packet { ifindex, protocol, sock_type, options, rx } = &*kind else { return false };
        let policy = PacketReceivePolicy {
            vnet_hdr_size: options.vnet_hdr_size().min(
                crate::uapi::VIRTIO_NET_HDR_MRG_RXBUF_LEN) as u8,
            copy_thresh: options.copy_thresh() != 0,
            timestamp: options.timestamp(),
        };
        let wanted_iface = ifindex.load(Ordering::Acquire);
        if wanted_iface != 0 && wanted_iface != iface.raw() { return false; }
        let datagram = sock_type.load(Ordering::Acquire) == SOCK_DGRAM;
        let observed_protocol = if datagram {
            observation.datagram_protocol
        } else { observation.raw_protocol };
        let wanted_protocol = protocol.load(Ordering::Acquire);
        if observation.pkttype == crate::uapi::PACKET_OUTGOING
            && wanted_protocol != crate::eth_p::ALL { return false; }
        if wanted_protocol != crate::eth_p::ALL && wanted_protocol != observed_protocol { return false; }
        if socket_hook && observation.pkttype == crate::uapi::PACKET_OUTGOING
            && options.ignore_outgoing() { return false; }
        let header_len = if datagram { observation.link_header_len } else { 0 };
        let packet = &observation.bytes[header_len..];
        let verdict = sock.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
            packet, protocol: observed_protocol, ifindex: Some(iface.raw()),
            pay_offset: packet_payload_offset(packet, if datagram { 0 } else { observation.link_header_len }),
            hatype: observation.hatype,
        });
        if verdict == 0 { return false; }
        let captured_len = packet.len().min(verdict as usize);
        let rxhash = packet_flow_hash(packet,
            if datagram { 0 } else { observation.link_header_len });
        let addr = PacketAddr {
                ifindex: if options.origdev() { observation.original_iface.raw() } else { iface.raw() },
                protocol: observed_protocol,
                hatype: observation.hatype, pkttype: observation.pkttype,
                halen: observation.halen, addr: observation.addr };
        let mut aux = PacketAuxData::from_receive(packet.len(), captured_len,
                if datagram { 0 } else { observation.link_header_len },
                observation.pkttype, observation.metadata, observation.inline_vlan, datagram);
        let (timestamp_ns, timestamp_status) = receive_timestamp(observation.metadata,
            policy.timestamp, observation.fallback_timestamp_ns);
        aux.timestamp_ns = Some(timestamp_ns);
        aux.timestamp_status = timestamp_status;
        aux.vnet_hdr_size = if datagram { 0 } else { policy.vnet_hdr_size };
        aux.copy_thresh = policy.copy_thresh;
        if aux.vnet_hdr_size != 0 {
            let Ok(header) = receive_vnet_header(observation.metadata) else { return false };
            aux.vnet_header = header;
        }
        let mut payload = Vec::with_capacity(aux.vnet_hdr_size as usize + captured_len);
        payload.extend_from_slice(&aux.vnet_header[..aux.vnet_hdr_size as usize]);
        payload.extend_from_slice(&packet[..captured_len]);
        let queued = PacketFrame {
            payload, addr, aux,
            charge: linux_packet_skb_truesize(observation.bytes.len()),
        };
        let limit = sock.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
        let mut queue = rx.lock();
        route_packet_receive_locked(&mut rings, &mut queue, PacketRingInput {
            payload: &packet[..captured_len], addr, aux, datagram, rxhash,
        }, queued, packet, limit, observation.fallback_timestamp_ns)
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn current_cpu() -> u32 { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn current_cpu() -> u32 { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
#[cfg(not(target_os = "oxide-kernel"))]
fn current_cpu() -> u32 { 0 }

fn packet_flow_hash(packet: &[u8], network: usize) -> u32 {
    let Some(version) = packet.get(network).map(|byte| byte >> 4) else {
        return hash_bytes(packet);
    };
    let mut fields = Vec::new();
    match version {
        4 if packet.len() >= network + 20 => {
            fields.extend_from_slice(&packet[network + 12..network + 20]);
            fields.push(packet[network + 9]);
            let ihl = ((packet[network] & 0x0f) as usize * 4).max(20);
            let transport = network + ihl;
            if matches!(packet[network + 9], 6 | 17) && packet.len() >= transport + 4 {
                fields.extend_from_slice(&packet[transport..transport + 4]);
            }
        }
        6 if packet.len() >= network + 40 => {
            fields.extend_from_slice(&packet[network + 8..network + 40]);
            fields.push(packet[network + 6]);
            let transport = network + 40;
            if matches!(packet[network + 6], 6 | 17) && packet.len() >= transport + 4 {
                fields.extend_from_slice(&packet[transport..transport + 4]);
            }
        }
        _ => return hash_bytes(packet),
    }
    hash_bytes(&fields)
}

fn hash_bytes(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes { hash = (hash ^ *byte as u32).wrapping_mul(0x0100_0193); }
    hash
}

fn inline_vlan(frame: &[u8]) -> Option<PacketVlan> {
    if frame.len() < ETHERNET_HEADER_LEN + crate::ethernet::ETH_VLAN_TAG_LEN { return None; }
    let tpid = u16::from_be_bytes([frame[12], frame[13]]);
    if !matches!(tpid, crate::eth_p::VLAN | crate::eth_p::VLAN_AD) { return None; }
    Some(PacketVlan { tci: u16::from_be_bytes([frame[14], frame[15]]), tpid })
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
