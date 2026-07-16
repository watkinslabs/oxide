use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::{Error, KResult};

#[derive(Clone, Copy)]
struct PacketAddress { ifindex: u32, protocol: u16, mac: [u8; 6] }

fn decode(raw: Option<&[u8]>) -> KResult<Option<PacketAddress>> {
    let Some(raw) = raw else { return Ok(None); };
    if raw.len() < 20 { return Err(Error::Einval); }
    if u16::from_ne_bytes(raw[..2].try_into().unwrap()) != 17 { return Err(Error::Eafnosupport); }
    let ifindex = i32::from_ne_bytes(raw[4..8].try_into().unwrap());
    if ifindex <= 0 { return Err(Error::Enxio); }
    let mut mac = [0u8; 6]; mac.copy_from_slice(&raw[12..18]);
    Ok(Some(PacketAddress { ifindex: ifindex as u32,
        protocol: u16::from_be_bytes(raw[2..4].try_into().unwrap()), mac }))
}

/// Validate one optional AF_PACKET destination snapshot. # C: O(1)
pub(crate) fn validate(name: Option<&[u8]>) -> KResult<()> { decode(name).map(|_| ()) }

/// Transmit one AF_PACKET message from kernel-owned snapshots. # C: O(payload)
pub(crate) fn send(socket: &Arc<net::sock::InetSocket>, payload: &[u8], name: Option<&[u8]>)
    -> KResult<usize>
{
    let address = decode(name)?;
    let (bound_ifindex, kind, bound_protocol) = match &*socket.kind.lock() {
        net::sock::SockKind::Packet { ifindex, sock_type, protocol, .. } => (
            ifindex.load(Ordering::Acquire), sock_type.load(Ordering::Acquire),
            protocol.load(Ordering::Acquire)),
        _ => return Err(Error::Enotsock),
    };
    let ifindex = address.map(|addr| addr.ifindex).unwrap_or(bound_ifindex);
    let protocol = address.and_then(|addr| (addr.protocol != 0).then_some(addr.protocol))
        .unwrap_or(bound_protocol);
    if ifindex == 0 { return Err(Error::Einval); }
    let device = net::sock::stack().ifaces.acquire_egress_in_ns(
        net::NetIfaceId::from_raw(ifindex), socket.net_ns()).ok_or(Error::Enxio)?;
    if kind == 2 {
        let destination = address.map(|addr| addr.mac).unwrap_or([0xff; 6]);
        let source = device.mac().0;
        let mut frame = alloc::vec::Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(&destination); frame.extend_from_slice(&source);
        frame.push((protocol >> 8) as u8); frame.push((protocol & 0xff) as u8);
        frame.extend_from_slice(payload);
        device.xmit_raw_from(&frame, Some(net::sock::packet_origin(socket)))
            .map_err(|_| Error::Enobufs)?;
    } else {
        device.xmit_raw_from(payload, Some(net::sock::packet_origin(socket)))
            .map_err(|_| Error::Enobufs)?;
    }
    Ok(payload.len())
}
