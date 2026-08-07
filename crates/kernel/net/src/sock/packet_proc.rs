use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{InetSocket, SockKind, PACKET_REGISTRY};

/// One live AF_PACKET socket projected by `/proc/net/packet`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketProcRow {
    pub socket: usize,
    pub ref_count: usize,
    pub socket_type: u8,
    pub protocol: u16,
    pub ifindex: u32,
    pub running: bool,
    pub receive_memory: usize,
    pub uid: u32,
    pub inode: u64,
}

fn row(sock: Arc<InetSocket>) -> Option<PacketProcRow> {
    // A registry weak reference can still upgrade while a teardown or a ring
    // pin holds the final object alive.  Once close unhooks the socket it no
    // longer has a packet-table row.
    if sock.released.load(Ordering::Acquire) { return None; }
    let kind = sock.kind.lock();
    let SockKind::Packet { ifindex, protocol, sock_type, rx, .. } = &*kind else { return None; };
    let receive_memory = rx.lock().charged_bytes();
    let inode = sock.file.lock().upgrade().map_or(0, |file| file.inode().ino());
    Some(PacketProcRow {
        socket: Arc::as_ptr(&sock) as usize,
        // The projection owns one temporary strong reference that is not a
        // socket reference, unlike `sk_refcnt`.
        ref_count: Arc::strong_count(&sock).saturating_sub(1),
        socket_type: sock_type.load(Ordering::Acquire),
        protocol: protocol.load(Ordering::Acquire),
        ifindex: ifindex.load(Ordering::Acquire),
        running: true,
        receive_memory,
        uid: sock.owner.owner_uid,
        inode,
    })
}

/// Snapshot AF_PACKET socket state in one network namespace. # C: O(N sockets)
pub fn packet_proc_rows(net_ns: u64) -> Vec<PacketProcRow> {
    let sockets = {
        let mut registry = PACKET_REGISTRY.lock_bh::<sched::bh::SchedBh>();
        let Some(sockets) = registry.get_mut(&net_ns) else { return Vec::new(); };
        sockets.retain(|weak| weak.upgrade().is_some());
        sockets.iter().filter_map(alloc::sync::Weak::upgrade).collect::<Vec<_>>()
    };
    sockets.into_iter().filter_map(row).collect()
}

/// Render `/proc/net/packet` for one network namespace. # C: O(N sockets)
pub fn render_proc_packet(net_ns: u64) -> Vec<u8> {
    use core::fmt::Write as _;
    let mut out = alloc::string::String::from("sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n");
    for row in packet_proc_rows(net_ns) {
        let _ = writeln!(out, "{:016x} {:<6} {:<4} {:04x}   {:<5} {} {:<6} {:<6} {}",
            row.socket, row.ref_count, row.socket_type, row.protocol, row.ifindex,
            row.running as u8, row.receive_memory, row.uid, row.inode);
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_reads_the_canonical_packet_socket_and_queue() {
        let ns = crate::net_ns::current_namespace();
        let sock = Arc::new(InetSocket::new_packet_in(crate::eth_p::IPV4, 3, ns));
        super::super::register_packet(&sock);
        let rows = packet_proc_rows(sock.net_ns());
        assert!(rows.iter().any(|row| row.socket == Arc::as_ptr(&sock) as usize
            && row.protocol == crate::eth_p::IPV4 && row.socket_type == 3
            && row.running && row.uid == sock.owner.owner_uid));
        sock.release_file();
        assert!(!packet_proc_rows(sock.net_ns()).iter()
            .any(|row| row.socket == Arc::as_ptr(&sock) as usize));
    }
}
