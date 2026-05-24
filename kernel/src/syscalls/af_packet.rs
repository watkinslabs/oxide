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
/// # SAFETY: `bufp..bufp+len` validated < USER_VA_END by caller.
/// # C: O(len) — single copy into a fresh Pkt.
pub fn sendto(sock: &Arc<InetSocket>, bufp: u64, len: usize) -> Option<i64> {
    let ifi = {
        let g = sock.kind.lock();
        match &*g {
            SockKind::Packet { ifindex, .. } => ifindex.load(Ordering::Acquire),
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
    let frame: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(bufp as *const u8, len).to_vec()
    };
    // F135: AF_PACKET caller already framed the L2 header — go
    // through NetDev::xmit_raw so the driver doesn't prepend
    // another ethernet header on top.
    match dev.xmit_raw(&frame) {
        Ok(()) => Some(frame.len() as i64),
        Err(_) => Some(-(Errno::Enobufs.as_i32() as i64)),
    }
}
