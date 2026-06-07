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

/// F139: write `sockaddr_ll` (20 bytes) into `src_p` for a frame
/// just popped from an AF_PACKET socket's rx queue. `frame` is the
/// full L2 frame so src MAC + pkttype (broadcast vs unicast) can
/// be parsed inline. Bounds-checks `src_p..src_p+20 < USER_VA_END`.
/// # SAFETY: caller verified bufp..bufp+len fit; src_p is the
/// caller-supplied source-address output. We write exactly 20 B.
/// # C: O(1)
pub fn write_sockaddr_ll(src_p: u64, sock: &Arc<InetSocket>, frame: &[u8]) {
    if src_p == 0 || src_p + 20 > USER_VA_END { return; }
    let (ifi, proto_host) = {
        let g = sock.kind.lock();
        if let SockKind::Packet { ifindex, protocol, .. } = &*g {
            (ifindex.load(Ordering::Acquire),
             protocol.load(Ordering::Acquire))
        } else { return; }
    };
    let src_mac: [u8; 6] = if frame.len() >= 12 {
        [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]]
    } else { [0; 6] };
    let is_bcast = frame.len() >= 6 && frame[..6] == [0xff; 6];
    let pkttype: u8 = if is_bcast { 1 } else { 0 };
    // SAFETY: src_p bounds-checked above; sockaddr_ll spans 20 bytes; volatile writes prevent the compiler from coalescing past the user copy.
    unsafe {
        let p = src_p as *mut u8;
        core::ptr::write_volatile(p as *mut u16, 17u16);
        core::ptr::write_volatile(p.add(2) as *mut u16, proto_host.swap_bytes());
        core::ptr::write_volatile(p.add(4) as *mut i32, ifi as i32);
        core::ptr::write_volatile(p.add(8) as *mut u16, 1u16);
        core::ptr::write_volatile(p.add(10), pkttype);
        core::ptr::write_volatile(p.add(11), 6u8);
        for i in 0..6 { core::ptr::write_volatile(p.add(12 + i), src_mac[i]); }
        for i in 6..8 { core::ptr::write_volatile(p.add(12 + i), 0); }
    }
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
    bufp: u64,
    len: usize,
    dest_p: u64,
) -> Option<i64> {
    // F146: extract sll_addr from sockaddr_ll if caller supplied
    // dest; SOCK_DGRAM uses it as the L2 destination MAC.
    let dest_mac: Option<[u8; 6]> = if dest_p != 0 && dest_p + 20 <= USER_VA_END {
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
    if bufp == 0 || bufp >= USER_VA_END || len == 0 {
        return Some(-(Errno::Einval.as_i32() as i64));
    }
    // SAFETY: caller verified bufp..bufp+len is in the user range and the user page is mapped under the active AS; CPL=0 read.
    let body: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(bufp as *const u8, len).to_vec()
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
    match dev.xmit_raw(&body) {
        Ok(()) => Some(body.len() as i64),
        Err(_) => Some(-(Errno::Enobufs.as_i32() as i64)),
    }
}
