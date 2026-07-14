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

use hal::USER_VA_END;
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
pub fn sendto(
    sock: &Arc<InetSocket>,
    body: &[u8],
    dest_p: u64,
    dest_len: usize,
) -> Option<i64> {
    // F146: extract sll_addr from sockaddr_ll if caller supplied
    // dest; SOCK_DGRAM uses it as the L2 destination MAC.
    let dest_mac: Option<[u8; 6]> = if dest_p != 0 && dest_len >= 20 && dest_p + 20 <= USER_VA_END {
        // SAFETY: dest_p..dest_p+20 bounds-checked above; user page mapped under caller's AS at CPL=0; sockaddr_ll layout is little-endian fixed-shape u16 family + u16 proto + i32 ifindex + u16 hatype + u8 pkttype + u8 halen + u8[8] addr.
        let fam = unsafe { core::ptr::read_volatile(dest_p as *const u16) };
        if fam == 17 {
            let mut mac = [0u8; 6];
            // SAFETY: same bounds-check range; addr field starts at +12 inside the 20-byte sockaddr_ll; per-byte volatile reads.
            unsafe {
                for i in 0..6 {
                    mac[i] = core::ptr::read_volatile((dest_p + 12 + i as u64) as *const u8);
                }
            }
            Some(mac)
        } else { None }
    } else { None };
    let (ifi, sock_type, proto_host) = {
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
    if ifi == 0 { return Some(-(Errno::Einval.as_i32() as i64)); }
    let dev = match net::sock::stack().ifaces.lookup(net::NetIfaceId::from_raw(ifi)) {
        Some(d) => d,
        None    => return Some(-(Errno::Enoent.as_i32() as i64)),
    };
    const SOCK_DGRAM: u8 = 2;
    if sock_type == SOCK_DGRAM {
        // Prepend ethernet header: dst MAC = dest_mac or broadcast;
        // src MAC = iface's hwaddr; ethertype = socket's stored proto
        // (host order; on-wire is be).
        let dst = dest_mac.unwrap_or([0xff; 6]);
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
