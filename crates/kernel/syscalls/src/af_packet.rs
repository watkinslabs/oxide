// F131: AF_PACKET / PF_PACKET helpers. dhcpcd opens
// `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` + `bind(sll)`
// + `sendto(L2_frame)` to push the DHCPDISCOVER frame onto eth0
// before it owns an IPv4 address. The socket admission, bind
// parsing, and SockKind storage live in net.rs / sock.rs; the
// hot-path sendto helper lives here so the surrounding net.rs
// stays under the 1000-line cap (`08§7`).

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use net::sock::{InetSocket, SockKind};

/// Copy a Linux `sockaddr_ll` using value-result `addrlen` semantics. # C: O(1)
pub fn copy_sockaddr_ll_to_user(src_p: u64, src_len: u64, meta: net::sock::PacketAddr) -> i64 {
    let mut sa = [0u8; 20];
    sa[0..2].copy_from_slice(&17u16.to_ne_bytes());
    sa[2..4].copy_from_slice(&meta.protocol.to_be_bytes());
    sa[4..8].copy_from_slice(&(meta.ifindex as i32).to_ne_bytes());
    sa[8..10].copy_from_slice(&meta.hatype.to_ne_bytes());
    sa[10] = meta.pkttype;
    sa[11] = meta.halen;
    sa[12..20].copy_from_slice(&meta.addr);
    let mut raw_len = [0u8; 4];
    if uaccess::copy_from_user(&mut raw_len, src_len).is_err() { return -(Errno::Efault.as_i32() as i64); }
    let user_len = i32::from_ne_bytes(raw_len);
    if user_len < 0 { return -(Errno::Einval.as_i32() as i64); }
    if uaccess::copy_to_user(src_len, &(sa.len() as u32).to_ne_bytes()).is_err() { return -(Errno::Efault.as_i32() as i64); }
    let take = core::cmp::min(user_len as usize, sa.len());
    if uaccess::copy_to_user(src_p, &sa[..take]).is_err() { return -(Errno::Efault.as_i32() as i64); }
    0
}

/// AF_PACKET sendto path. Returns Some(rv) when `sock` is a
/// PACKET socket and we attempted xmit; None otherwise so the
/// caller falls through to AF_INET/AF_UNIX dispatch.
///
/// F146: differentiate SOCK_RAW vs SOCK_DGRAM. SOCK_RAW (3) hands
/// the body to xmit_raw — caller already built the ethernet
/// header. SOCK_DGRAM (2) — kernel prepends an ethernet header
/// using `dest_mac` (from sendto's sockaddr_ll.sll_addr if
/// supplied; broadcast otherwise) and the socket's stored
/// protocol as ethertype. A SOCK_DGRAM DHCP client uses this.
///
/// # SAFETY: `bufp..bufp+len` validated < USER_VA_END by caller.
/// # C: O(len) — single copy into a fresh Vec.
#[derive(Clone, Copy)]
pub struct PacketSendAddr {
    ifindex: u32,
    protocol: u16,
    mac: [u8; 6],
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Decode a kernel-owned Linux `sockaddr_ll`. # C: O(1)
pub fn decode_send_addr(raw: &[u8]) -> Result<Option<PacketSendAddr>, i64> {
    if raw.is_empty() { return Ok(None); }
    if raw.len() < 20 { return Err(err(Errno::Einval)); }
    if u16::from_ne_bytes(raw[..2].try_into().unwrap()) != 17 { return Err(err(Errno::Eafnosupport)); }
    let ifindex = i32::from_ne_bytes(raw[4..8].try_into().unwrap());
    if ifindex <= 0 { return Err(err(Errno::Enxio)); }
    let mut mac = [0u8; 6]; mac.copy_from_slice(&raw[12..18]);
    Ok(Some(PacketSendAddr { ifindex: ifindex as u32,
        protocol: u16::from_be_bytes(raw[2..4].try_into().unwrap()), mac }))
}

pub fn sendto(
    sock: &Arc<InetSocket>,
    body: &[u8],
    dest_p: u64,
    dest_len: usize,
) -> Option<i64> {
    let addr = if dest_p == 0 { None } else {
        if dest_len < 20 { return Some(err(Errno::Einval)); }
        let mut raw = [0u8; 20];
        if uaccess::copy_from_user(&mut raw, dest_p).is_err() { return Some(err(Errno::Efault)); }
        match decode_send_addr(&raw) { Ok(addr) => addr, Err(e) => return Some(e) }
    };
    sendto_imported(sock, body, addr)
}

/// AF_PACKET send from a kernel-owned sendmsg snapshot. # C: O(len)
pub fn sendto_imported(sock: &Arc<InetSocket>, body: &[u8], addr: Option<PacketSendAddr>) -> Option<i64> {
    let (bound_ifi, sock_type, bound_proto) = {
        let g = sock.kind.lock();
        match &*g {
            SockKind::Packet { ifindex, sock_type, protocol, .. } => (
                ifindex.load(Ordering::Acquire),
                sock_type.load(Ordering::Acquire),
                protocol.load(Ordering::Acquire),
            ),
            _ => return None,
        }
    };
    let ifi = addr.map(|a| a.ifindex).unwrap_or(bound_ifi);
    let proto_host = addr.and_then(|a| if a.protocol != 0 { Some(a.protocol) } else { None }).unwrap_or(bound_proto);
    if ifi == 0 { return Some(-(Errno::Einval.as_i32() as i64)); }
    let net_ns = sock.net_ns.load(Ordering::Acquire);
    let dev = match net::sock::stack().ifaces.lookup_in_ns(net::NetIfaceId::from_raw(ifi), net_ns) {
        Some(d) => d,
        None    => return Some(-(Errno::Enoent.as_i32() as i64)),
    };
    const SOCK_DGRAM: u8 = 2;
    if sock_type == SOCK_DGRAM {
        // Prepend ethernet header: dst MAC = dest_mac or broadcast;
        // src MAC = iface's hwaddr; ethertype = socket's stored proto
        // (host order; on-wire is be).
        let dst = addr.map(|a| a.mac).unwrap_or([0xff; 6]);
        let src = dev.mac().0;
        let mut frame = alloc::vec::Vec::with_capacity(14 + body.len());
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&src);
        frame.push((proto_host >> 8) as u8);
        frame.push((proto_host & 0xff) as u8);
        frame.extend_from_slice(&body);
        return match dev.xmit_raw(&frame) {
            Ok(()) => Some(body.len() as i64),
            Err(_) => Some(-(Errno::Enobufs.as_i32() as i64)),
        };
    }
    // SOCK_RAW: caller-supplied full L2 frame.
    match dev.xmit_raw(body) {
        Ok(()) => Some(body.len() as i64),
        Err(_) => Some(-(Errno::Enobufs.as_i32() as i64)),
    }
}
