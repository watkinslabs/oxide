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
