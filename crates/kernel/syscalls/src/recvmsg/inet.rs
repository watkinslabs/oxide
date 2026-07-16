use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use net::sock::{InetSocket, Received, SockKind};
use net::uapi::{MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_common::errno_from_neterr;
use crate::net_sockaddr::{encoded_sockaddr_for_socket, encoded_sockaddr_in6};
use crate::recv_user::RecvUser;
use crate::recv_control::Control;

const IPPROTO_IP: i32 = 0;
const IP_TTL: i32 = 2;
const IP_PKTINFO: i32 = 8;
const IPPROTO_IPV6: i32 = 41;
const IPV6_PKTINFO: i32 = 50;
const IPV6_HOPLIMIT: i32 = 52;
const IP_RECVERR: i32 = 11;
const IPV6_RECVERR: i32 = 25;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn oob_error(sock: &InetSocket, flags: u64) -> Option<Errno> {
    if flags & MSG_OOB == 0 { return None; }
    match *sock.kind.lock() {
        SockKind::Raw4(_) | SockKind::Raw6(_) => Some(Errno::Eopnotsupp),
        SockKind::Packet { .. } => Some(Errno::Einval),
        _ => None,
    }
}

fn sockaddr(addr: net::IpAddr, port: u16, family: u16, ifindex: u32) -> Vec<u8> {
    if family == net::sock::AF_INET6 {
        let ip = match addr {
            net::IpAddr::V4(ip) => net::Ipv6Addr::from_v4_mapped(ip),
            net::IpAddr::V6(ip) => ip,
        };
        let mut out = alloc::vec![0u8; 28];
        out[0..2].copy_from_slice(&net::sock::AF_INET6.to_ne_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        out[8..24].copy_from_slice(&ip.0);
        if ip.is_link_local() { out[24..28].copy_from_slice(&ifindex.to_ne_bytes()); }
        return out;
    }
    match addr {
        net::IpAddr::V4(ip) => {
            let mut out = alloc::vec![0u8; 16];
            out[0..2].copy_from_slice(&2u16.to_ne_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[4..8].copy_from_slice(&ip.octets());
            out
        }
        net::IpAddr::V6(ip) => {
            let mut out = alloc::vec![0u8; 28];
            out[0..2].copy_from_slice(&10u16.to_ne_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[8..24].copy_from_slice(&ip.0);
            out
        }
    }
}

fn extended_error_data(entry: &net::SocketErrorEntry, family: u16) -> Vec<u8> {
    let offender = sockaddr(entry.offender, 0, family, entry.ifindex);
    let mut out = alloc::vec![0u8; 16 + offender.len()];
    out[0..4].copy_from_slice(&(entry.errno as u32).to_ne_bytes());
    out[4] = entry.origin;
    out[5] = entry.kind;
    out[6] = entry.code;
    out[8..12].copy_from_slice(&entry.info.to_ne_bytes());
    out[12..16].copy_from_slice(&entry.data.to_ne_bytes());
    out[16..].copy_from_slice(&offender);
    out
}

/// Consume one Linux extended socket error and encode its payload/name/cmsg. # C: O(payload)
pub(crate) fn recv_error(sock: &Arc<InetSocket>, user: &RecvUser, flags: u64) -> i64 {
    if let Some(e) = oob_error(sock, flags) { return err(e); }
    let Some(entry) = sock.take_extended_error() else { return err(Errno::Eagain); };
    let family = sock.family.load(Ordering::Acquire);
    let copied = match user.copy_payload(&entry.payload) { Ok(n) => n, Err(e) => return e };
    if let Err(e) = user.copy_name(&sockaddr(
        entry.destination, entry.destination_port, family, entry.ifindex,
    )) { return e; }
    let mut ctrl = Control::new(if user.control == 0 { 0 } else { user.controllen });
    let (level, kind) = if family == net::sock::AF_INET6 {
        (IPPROTO_IPV6, IPV6_RECVERR)
    } else { (IPPROTO_IP, IP_RECVERR) };
    ctrl.push(level, kind, &extended_error_data(&entry, family));
    let ctrl_len = match ctrl.copy_to(user) { Ok(len) => len, Err(e) => return e };
    let mut out_flags = ctrl.flags | MSG_ERRQUEUE as u32 | crate::recv_control::output_flags(flags);
    if entry.payload.len() > copied { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(ctrl_len, out_flags) { return e; }
    copied as i64
}
fn control(sock: &InetSocket, rcv: &Received, cap: usize) -> Control {
    let mut out = Control::new(cap);
    if sock.opts.ip_pktinfo.load(Ordering::Acquire) != 0 {
        if let Some((dst, iface)) = rcv.pktinfo {
            let mut data = [0u8; 12];
            data[0..4].copy_from_slice(&(iface.raw() as i32).to_ne_bytes());
            data[4..8].copy_from_slice(&dst.octets());
            data[8..12].copy_from_slice(&dst.octets());
            out.push(IPPROTO_IP, IP_PKTINFO, &data);
        }
    }
    if sock.opts.ip_recvttl.load(Ordering::Acquire) != 0 {
        if let Some(ttl) = rcv.ttl { out.push(IPPROTO_IP, IP_TTL, &(ttl as i32).to_ne_bytes()); }
    }
    if sock.opts.ipv6_recvpktinfo.load(Ordering::Acquire) != 0 {
        if let Some((dst, iface)) = rcv.pktinfo6 {
            let mut data = [0u8; 20];
            data[..16].copy_from_slice(&dst.0);
            data[16..].copy_from_slice(&iface.raw().to_ne_bytes());
            out.push(IPPROTO_IPV6, IPV6_PKTINFO, &data);
        }
    }
    if sock.opts.ipv6_recvhoplimit.load(Ordering::Acquire) != 0 {
        if let Some(hop) = rcv.hoplimit { out.push(IPPROTO_IPV6, IPV6_HOPLIMIT, &(hop as i32).to_ne_bytes()); }
    }
    if sock.packet_auxdata() == Ok(true) {
        if let Some(packet) = rcv.packet {
            out.push(net::uapi::SOL_PACKET as i32, net::uapi::PACKET_AUXDATA as i32,
                &packet.aux.to_ne_bytes());
        }
    }
    out
}

fn copy_packet_name(user: &RecvUser, meta: net::sock::PacketAddr) -> Result<(), i64> {
    let mut sa = [0u8; 20];
    sa[0..2].copy_from_slice(&17u16.to_ne_bytes());
    sa[2..4].copy_from_slice(&meta.protocol.to_be_bytes());
    sa[4..8].copy_from_slice(&(meta.ifindex as i32).to_ne_bytes());
    sa[8..10].copy_from_slice(&meta.hatype.to_ne_bytes());
    sa[10] = meta.pkttype;
    sa[11] = meta.halen;
    sa[12..20].copy_from_slice(&meta.addr);
    user.copy_name(&sa)
}

fn copy_name(user: &RecvUser, sock: &InetSocket, rcv: &Received) -> Result<(), i64> {
    if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
        return match rcv.packet {
            Some(meta) => copy_packet_name(user, meta.addr),
            None => user.copy_name(&[]),
        };
    }
    if let Some((ip, port, scope_id)) = rcv.peer6 {
        let port = if matches!(*sock.kind.lock(), SockKind::Raw6(_)) { 0 } else { port };
        return user.copy_name(encoded_sockaddr_in6(ip.0, port.to_be(), scope_id).as_bytes());
    }
    if let Some((ip, port)) = rcv.peer {
        let port = if matches!(*sock.kind.lock(), SockKind::Raw4(_)) { 0 } else { port };
        return user.copy_name(encoded_sockaddr_for_socket(sock, ip, port).as_bytes());
    }
    if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
        let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
        return user.copy_name(encoded_sockaddr_for_socket(sock, ip, port).as_bytes());
    }
    user.copy_name(&[])
}

fn receive(sock: &Arc<InetSocket>, len: usize, flags: u64, file_nonblock: bool) -> Result<Received, i64> {
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let opts = net::sock::RecvOptions { peek: flags & MSG_PEEK != 0 };
    match net::sock::recvfrom_opts(sock, len, opts) {
        Ok(rcv) => return Ok(rcv),
        Err(net::NetError::Eagain) => {}
        Err(e) => return Err(errno_from_neterr(e)),
    }
    let pending = sock.take_pending_recv_error();
    if pending != 0 { return Err(-(pending as i64)); }
    if nonblock { return Err(err(Errno::Eagain)); }
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    net::sock_recv::recv_blocking(sock, len, opts, deadline).map_err(errno_from_neterr)
}

pub(crate) fn tcp_with_copy_pinned<F>(sock: &Arc<InetSocket>, capacity: usize, flags: u64, file_nonblock: bool, mut copy: F) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>
{
    if capacity == 0 { return Ok(0); }
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(),
        _ => return Err(err(Errno::Einval)),
    };
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let peek = flags & MSG_PEEK != 0;
    let waitall = flags & MSG_WAITALL != 0;
    let mut total = 0usize;
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    loop {
        net::sock::drain_loopback();
        let offset = if peek { total } else { 0 };
        match net::sock::stack().tcp_recv_with_offset(&entry, capacity - total, peek, offset,
            |bytes| copy(total, bytes).map(|n| (n, n))) {
            Ok(Some(copied)) => {
                total += copied;
                if !waitall || total == capacity { return Ok(total); }
            }
            Ok(None) => {
                if total == 0 {
                    let pending = sock.take_pending_recv_error();
                    if pending != 0 { return Err(-(pending as i64)); }
                } else if sock.has_pending_recv_error() {
                    return Ok(total);
                }
                if sock.read_shut.load(Ordering::Acquire) || net::sock_io::tcp_recv_eof(entry.conn.lock().state) { return Ok(total); }
            }
            Err(e) => return if total != 0 { Ok(total) } else { Err(e) },
        }
        if nonblock { return if total != 0 { Ok(total) } else { Err(err(Errno::Eagain)) }; }
        if sched::live::deliverable_signals_self() != 0 { return if total != 0 { Ok(total) } else { Err(err(Errno::Eintr)) }; }
        if net::sock_recv::deadline_expired(deadline) { return if total != 0 { Ok(total) } else { Err(err(Errno::Eagain)) }; }
        let _ = net::sock_recv::wait_recv_source_after(sock, deadline, offset);
    }
}

fn tcp_oob_with_copy(sock: &Arc<InetSocket>, user: &RecvUser, flags: u64,
    file_nonblock: bool) -> Result<usize, i64> {
    if user.capacity == 0 { return Ok(0); }
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(),
        _ => return Err(err(Errno::Einval)),
    };
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let peek = flags & MSG_PEEK != 0;
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    loop {
        net::sock::drain_loopback();
        match net::sock::stack().tcp_recv_urgent(&entry, peek, |byte| {
            user.copy_payload(byte).map(|_| ())
        }) {
            Ok(Some(_)) => {
                if let Err(e) = copy_name(user, sock, &Received {
                    payload: Vec::new(), full_len: 1, peer: None, peer6: None,
                    pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None,
                }) { return Err(e); }
                user.finish(0, crate::recv_control::output_flags(flags)).map_err(|e| e)?;
                return Ok(1);
            }
            Ok(None) => {
                let pending = sock.take_pending_recv_error();
                if pending != 0 { return Err(-(pending as i64)); }
            }
            Err(e) => return Err(e),
        }
        if nonblock { return Err(err(Errno::Eagain)); }
        if sched::live::deliverable_signals_self() != 0 { return Err(err(Errno::Eintr)); }
        if net::sock_recv::deadline_expired(deadline) { return Err(err(Errno::Eagain)); }
        let _ = net::sock_recv::wait_recv_source_after(sock, deadline, 0);
    }
}

/// Internet and packet recvmsg copyout. # C: O(payload + control)
pub(crate) fn recv_pinned(sock: &Arc<InetSocket>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    if let Some(e) = oob_error(sock, flags) { return err(e); }
    if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
        if flags & MSG_OOB != 0 { return match tcp_oob_with_copy(sock, user, flags, file_nonblock) {
            Ok(copied) => copied as i64, Err(e) => e,
        }; }
        let copied = match tcp_with_copy_pinned(sock, user.capacity, flags, file_nonblock, |offset, bytes| user.copy_payload_at(offset, bytes)) {
            Ok(copied) => copied,
            Err(e) => return e,
        };
        if let Err(e) = copy_name(user, sock, &Received {
            payload: Vec::new(), full_len: copied, peer: None, peer6: None,
            pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None,
        }) { return e; }
        if let Err(e) = user.finish(0, crate::recv_control::output_flags(flags)) { return e; }
        return copied as i64;
    }
    let rcv = match receive(sock, user.capacity, flags, file_nonblock) { Ok(rcv) => rcv, Err(e) => return e };
    let copied = match user.copy_payload(&rcv.payload) { Ok(n) => n, Err(e) => return e };
    let mut ctrl = control(sock, &rcv, if user.control == 0 { 0 } else { user.controllen });
    let ctrl_len = match ctrl.copy_to(user) { Ok(len) => len, Err(e) => return e };
    if let Err(e) = copy_name(user, sock, &rcv) { return e; }
    let mut out_flags = ctrl.flags | crate::recv_control::output_flags(flags);
    if rcv.full_len > copied { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(ctrl_len, out_flags) { return e; }
    if flags & MSG_TRUNC != 0 { rcv.full_len as i64 } else { copied as i64 }
}
