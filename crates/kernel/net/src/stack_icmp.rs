// F174: ICMP Destination Unreachable handler — extracted from
// stack.rs for the 1000-line cap (docs/08§7). Reconstructs the
// original 4-tuple from the echoed IPv4 header + first 8 bytes
// of L4 and surfaces ECONNREFUSED on the originating socket.

use core::sync::atomic::Ordering;

use crate::addr::{IpAddr, IpProto};
use crate::ipv4::{Ipv4Hdr, IPV4_HDR_LEN};
use crate::stack::{NetStack, TcpKey};

/// # C: O(log N) demux lookups.
pub fn handle_dest_unreach(stack: &NetStack, code: u8, payload: &[u8]) {
    const ICMP_HDR: usize = 8;
    if payload.len() < ICMP_HDR + IPV4_HDR_LEN + 8 { return; }
    let orig_ip = &payload[ICMP_HDR..];
    let orig_hdr = match Ipv4Hdr::parse(orig_ip) { Ok(h) => h, Err(_) => return };
    let orig_l4_off = orig_hdr.ihl_bytes();
    if orig_ip.len() < orig_l4_off + 8 { return; }
    let orig_l4 = &orig_ip[orig_l4_off..orig_l4_off + 8];
    let src_port = u16::from_be_bytes([orig_l4[0], orig_l4[1]]);
    let dst_port = u16::from_be_bytes([orig_l4[2], orig_l4[3]]);
    // F191: ICMP code 4 (fragmentation needed) carries the next-hop
    // MTU in payload bytes 6..8 of the ICMP message (the part that
    // used to be "unused"). Use it to clamp the affected TCP conn's
    // peer_mss; do NOT surface as a fatal SO_ERROR.
    if code == 4 && orig_hdr.proto == IpProto::Tcp as u8 {
        let mtu_hint = u16::from_be_bytes([payload[6], payload[7]]);
        let new_mss = mtu_hint.saturating_sub(40);
        let key = TcpKey {
            local_ip:    IpAddr::V4(orig_hdr.src),
            local_port:  src_port,
            remote_ip:   IpAddr::V4(orig_hdr.dst),
            remote_port: dst_port,
        };
        if let Some(entry) = stack.tcp_conns_map().lock().get(&key).cloned() {
            let mut c = entry.conn.lock();
            if new_mss >= 536 && (c.peer_mss == 0 || new_mss < c.peer_mss) {
                c.peer_mss = new_mss;
            }
        }
        return;
    }
    let eno = syscall::errno::Errno::Econnrefused as i32;
    match orig_hdr.proto {
        p if p == IpProto::Udp as u8 => {
            if let Some(q) = stack.udp_map().lock().get(&src_port).cloned() {
                q.error_eno.store(eno, Ordering::Release);
                #[cfg(target_os = "oxide-kernel")]
                q.waiters.wake_all();
            }
        }
        p if p == IpProto::Tcp as u8 => {
            let key = TcpKey {
                local_ip:    IpAddr::V4(orig_hdr.src),
                local_port:  src_port,
                remote_ip:   IpAddr::V4(orig_hdr.dst),
                remote_port: dst_port,
            };
            if let Some(entry) = stack.tcp_conns_map().lock().get(&key).cloned() {
                let mut c = entry.conn.lock();
                if c.error_eno == 0 { c.error_eno = eno; }
                c.state = crate::tcp_state::TcpState::Closed;
                drop(c);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
        }
        _ => {}
    }
}
