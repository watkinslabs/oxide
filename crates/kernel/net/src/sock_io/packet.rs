use super::{InetSocket, NetError, Received, RecvOptions, SockKind};
use crate::sock::PacketReceive;
use core::sync::atomic::Ordering;

/// Receive one AF_PACKET queue record when `sock` belongs to that family. # C: O(payload)
pub(super) fn recv(sock: &InetSocket, max_len: usize, opts: RecvOptions)
    -> Option<Result<Received, NetError>>
{
    let kind = sock.kind.lock();
    let SockKind::Packet { rx, ifindex, protocol, .. } = &*kind else { return None };
    let ifindex = ifindex.load(Ordering::Acquire);
    let bound_protocol = protocol.load(Ordering::Acquire);
    let frame = {
        let mut queue = rx.lock();
        let limit = sock.opts.rcvbuf.load(Ordering::Acquire).max(0) as usize;
        queue.receive(opts.peek, limit)
    };
    let Some(frame) = frame else { return Some(Err(NetError::Eagain)) };
    if let Err(error) = crate::sock::validate_vnet_receive_capacity(
        frame.aux.vnet_hdr_size, max_len) { return Some(Err(error)); }
    let full_len = frame.payload.len();
    let take = core::cmp::min(max_len, full_len);
    let mut payload = alloc::vec::Vec::with_capacity(take);
    payload.extend_from_slice(&frame.payload[..take]);
    let mut packet = frame.addr;
    if packet.ifindex == 0 { packet.ifindex = ifindex; }
    if packet.protocol == 0 { packet.protocol = bound_protocol; }
    Some(Ok(Received { payload, full_len, peer: None, peer6: None,
        pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None,
        packet: Some(PacketReceive { addr: packet, aux: frame.aux }) }))
}
