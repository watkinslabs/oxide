use super::*;
use core::sync::atomic::Ordering;

const SOCK_DGRAM: u8 = 2;
const VLAN_HEADER_LEN: usize = 4;
const SOCKADDR_LL_ADDR_OFFSET: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketTxAddress {
    pub ifindex: u32,
    pub protocol: u16,
    pub address: [u8; 8],
    pub name_len: u32,
}

pub(crate) struct PacketTxTarget {
    lease: crate::netdev::EgressLease,
    protocol: u16,
    datagram: bool,
    destination: [u8; 6],
    vnet_header_size: u32,
    qdisc_bypass: bool,
}

impl PacketTxTarget {
    /// Maximum payload accepted by Linux packet transmit without offload. # C: O(1)
    pub(crate) fn max_len(&self) -> usize {
        self.lease.mtu() as usize + VLAN_HEADER_LEN
            + if self.datagram { 0 } else { crate::ethernet::ETH_HDR_LEN }
    }

    pub(crate) fn validate(&self, payload: &[u8]) -> crate::NetResult<()> {
        if payload.len() > self.max_len() { return Err(crate::NetError::Emsgsize); }
        if !self.datagram && payload.len() < crate::ethernet::ETH_HDR_LEN {
            return Err(crate::NetError::Einval);
        }
        Ok(())
    }

    pub(crate) fn datagram(&self) -> bool { self.datagram }

    /// Transmit one packet through the retained interface generation. # C: O(payload + sockets)
    pub(crate) fn transmit(&self, socket: &InetSocket, payload: &[u8]) -> crate::NetResult<usize> {
        let prepared = super::packet_virtio::prepare(payload, self.vnet_header_size,
            self.max_len())?;
        for body in &prepared.frames {
            if self.datagram {
                self.validate(body)?;
                let source = self.lease.mac().0;
                let mut frame = Vec::new();
                frame.try_reserve_exact(crate::ethernet::ETH_HDR_LEN + body.len())
                    .map_err(|_| crate::NetError::Enobufs)?;
                frame.extend_from_slice(&self.destination);
                frame.extend_from_slice(&source);
                frame.extend_from_slice(&self.protocol.to_be_bytes());
                frame.extend_from_slice(body);
                self.lease.xmit_raw_policy_from(&frame, Some(packet_origin(socket)),
                    self.qdisc_bypass)?;
            } else {
                self.lease.xmit_raw_policy_from(body, Some(packet_origin(socket)),
                    self.qdisc_bypass)?;
            }
        }
        Ok(prepared.payload_len)
    }
}

/// Resolve one packet destination to a retained namespace-qualified device generation. # C: O(ifaces)
pub(crate) fn resolve_packet_tx(socket: &InetSocket, address: Option<PacketTxAddress>)
    -> crate::NetResult<PacketTxTarget>
{
    let (bound_ifindex, kind, bound_protocol) = match &*socket.kind.lock() {
        SockKind::Packet { ifindex, sock_type, protocol, .. } => (
            ifindex.load(Ordering::Acquire), sock_type.load(Ordering::Acquire),
            protocol.load(Ordering::Acquire)),
        _ => return Err(crate::NetError::Enoprotoopt),
    };
    let ifindex = address.map(|value| value.ifindex).unwrap_or(bound_ifindex);
    let protocol = address.map(|value| value.protocol).unwrap_or(bound_protocol);
    if ifindex == 0 { return Err(crate::NetError::Enodev); }
    let lease = stack().ifaces.acquire_egress_in_ns(
        crate::NetIfaceId::from_raw(ifindex), socket.net_ns())
        .ok_or(crate::NetError::Enodev)?;
    if lease.flags() & crate::netdev::iff::IFF_UP == 0 {
        return Err(crate::NetError::Enetdown);
    }
    let datagram = kind == SOCK_DGRAM;
    if datagram && address.is_some_and(|value| {
        (value.name_len as usize) < SOCKADDR_LL_ADDR_OFFSET + lease.address_len() as usize
    }) { return Err(crate::NetError::Einval); }
    let mut destination = [0xff; 6];
    if let Some(value) = address { destination.copy_from_slice(&value.address[..6]); }
    let vnet_header_size = socket.packet_vnet_hdr_size()?;
    let qdisc_bypass = socket.packet_qdisc_bypass()?;
    Ok(PacketTxTarget { lease, protocol, datagram, destination,
        vnet_header_size, qdisc_bypass })
}

/// Transmit one ordinary AF_PACKET payload through canonical retained state. # C: O(ifaces + payload)
pub fn send_packet(socket: &InetSocket, payload: &[u8], address: Option<PacketTxAddress>)
    -> crate::NetResult<usize>
{
    resolve_packet_tx(socket, address)?.transmit(socket, payload)?;
    Ok(payload.len())
}
