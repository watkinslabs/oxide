use alloc::sync::Arc;
use crate::{Error, KResult};

#[derive(Clone, Copy)]
struct PacketAddress(net::sock::PacketTxAddress);

fn decode(raw: Option<&[u8]>) -> KResult<Option<PacketAddress>> {
    let Some(raw) = raw else { return Ok(None); };
    if raw.len() < 20 { return Err(Error::Einval); }
    let ifindex = i32::from_ne_bytes(raw[4..8].try_into().unwrap());
    if ifindex <= 0 { return Err(Error::Enxio); }
    let halen = raw[11] as usize;
    if raw.len() < 12usize.saturating_add(halen) { return Err(Error::Einval); }
    let mut address = [0u8; 8];
    let take = core::cmp::min(address.len(), raw.len().saturating_sub(12));
    address[..take].copy_from_slice(&raw[12..12 + take]);
    Ok(Some(PacketAddress(net::sock::PacketTxAddress {
        ifindex: ifindex as u32,
        protocol: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
        address, name_len: raw.len() as u32,
    })))
}

/// Validate one optional AF_PACKET destination snapshot. # C: O(1)
pub(crate) fn validate(name: Option<&[u8]>) -> KResult<()> { decode(name).map(|_| ()) }

/// Transmit one AF_PACKET message from kernel-owned snapshots. # C: O(payload)
pub(crate) fn send(socket: &Arc<net::sock::InetSocket>, payload: &[u8], name: Option<&[u8]>)
    -> KResult<usize>
{
    let address = decode(name)?.map(|value| value.0);
    let result = if socket.has_packet_tx_ring() {
        socket.kick_packet_tx_ring(address)
    } else { net::sock::send_packet(socket, payload, address) };
    result.map_err(Error::from)
}
