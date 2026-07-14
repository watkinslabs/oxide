use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use net::sock::{InetSocket, Received, SockKind};
use net::uapi::{MSG_CTRUNC, MSG_DONTWAIT, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_common::{errno_from_neterr, file_is_nonblock};
use crate::net_sockaddr::{encoded_sockaddr_for_socket, encoded_sockaddr_in6_peer};
use crate::recv_user::RecvUser;

const CMSG_HDR: usize = 16;
const CMSG_ALIGN: usize = 8;
const IPPROTO_IP: i32 = 0;
const IP_TTL: i32 = 2;
const IP_PKTINFO: i32 = 8;
const IPPROTO_IPV6: i32 = 41;
const IPV6_PKTINFO: i32 = 50;
const IPV6_HOPLIMIT: i32 = 52;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }
fn aligned(n: usize) -> usize { (n + CMSG_ALIGN - 1) & !(CMSG_ALIGN - 1) }

struct Control {
    bytes: Vec<u8>,
    flags: u32,
    cap: usize,
}

impl Control {
    fn new(cap: usize) -> Self { Self { bytes: Vec::new(), flags: 0, cap } }

    fn push(&mut self, level: i32, ty: i32, data: &[u8]) {
        let len = CMSG_HDR + data.len();
        let space = aligned(len);
        let remaining = self.cap.saturating_sub(self.bytes.len());
        if remaining < CMSG_HDR {
            self.flags |= MSG_CTRUNC as u32;
            return;
        }
        let at = self.bytes.len();
        let write = core::cmp::min(space, remaining);
        if write < space { self.flags |= MSG_CTRUNC as u32; }
        self.bytes.resize(at + write, 0);
        self.bytes[at..at + 8].copy_from_slice(&(len as u64).to_ne_bytes());
        self.bytes[at + 8..at + 12].copy_from_slice(&level.to_ne_bytes());
        self.bytes[at + 12..at + 16].copy_from_slice(&ty.to_ne_bytes());
        let data_len = core::cmp::min(data.len(), write - CMSG_HDR);
        self.bytes[at + CMSG_HDR..at + CMSG_HDR + data_len].copy_from_slice(&data[..data_len]);
    }
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
    out
}

fn copy_packet_name(user: &RecvUser, meta: net::sock::PacketAddr) -> Result<(), i64> {
    if user.name == 0 { return user.write_namelen(0); }
    let mut sa = [0u8; 20];
    sa[0..2].copy_from_slice(&17u16.to_ne_bytes());
    sa[2..4].copy_from_slice(&meta.protocol.to_be_bytes());
    sa[4..8].copy_from_slice(&(meta.ifindex as i32).to_ne_bytes());
    sa[8..10].copy_from_slice(&meta.hatype.to_ne_bytes());
    sa[10] = meta.pkttype;
    sa[11] = meta.halen;
    sa[12..20].copy_from_slice(&meta.addr);
    let take = core::cmp::min(user.namelen as usize, sa.len());
    uaccess::copy_to_user(user.name, &sa[..take]).map_err(|_| err(Errno::Efault))?;
    user.write_namelen(sa.len() as u32)
}

fn copy_name(user: &RecvUser, sock: &InetSocket, rcv: &Received) -> Result<(), i64> {
    if matches!(*sock.kind.lock(), SockKind::Packet { .. }) {
        return match rcv.packet { Some(meta) => copy_packet_name(user, meta), None => user.write_namelen(0) };
    }
    if let Some((ip, port)) = rcv.peer6 { return user.copy_name(encoded_sockaddr_in6_peer(ip, port).as_bytes()); }
    if let Some((ip, port)) = rcv.peer { return user.copy_name(encoded_sockaddr_for_socket(sock, ip, port).as_bytes()); }
    if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
        let (ip, port) = (*sock.peer.lock()).unwrap_or((net::Ipv4Addr::ANY, 0));
        return user.copy_name(encoded_sockaddr_for_socket(sock, ip, port).as_bytes());
    }
    user.write_namelen(0)
}

fn receive(fd: u64, sock: &Arc<InetSocket>, len: usize, flags: u64) -> Result<Received, i64> {
    let nonblock = flags & MSG_DONTWAIT != 0 || file_is_nonblock(fd);
    let opts = net::sock::RecvOptions { peek: flags & MSG_PEEK != 0 };
    if nonblock { return net::sock::recvfrom_opts(sock, len, opts).map_err(errno_from_neterr); }
    let is_v6 = sock.family.load(Ordering::Acquire) == net::sock::AF_INET6;
    if matches!(*sock.kind.lock(), SockKind::Udp) && !is_v6 {
        if let Some(port) = *sock.local_port.lock() {
            if let Some(q) = net::sock::stack().udp_queue_arc(port) {
                let queued = q.take_error();
                if queued != 0 { return Err(-(queued as i64)); }
            }
        }
    }
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    net::sock_recv::recv_blocking(sock, len, opts, deadline).map_err(errno_from_neterr)
}

pub(crate) fn tcp_with_copy<F>(fd: u64, sock: &Arc<InetSocket>, capacity: usize, flags: u64, mut copy: F) -> Result<usize, i64>
where F: FnMut(usize, &[u8]) -> Result<usize, i64>
{
    if capacity == 0 { return Ok(0); }
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(),
        _ => return Err(err(Errno::Einval)),
    };
    let nonblock = flags & MSG_DONTWAIT != 0 || file_is_nonblock(fd);
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

/// Internet and packet recvmsg copyout. # C: O(payload + control)
pub(crate) fn recv(fd: u64, sock: &Arc<InetSocket>, user: &RecvUser, flags: u64) -> i64 {
    if matches!(*sock.kind.lock(), SockKind::TcpConn(_)) {
        let copied = match tcp_with_copy(fd, sock, user.capacity, flags, |offset, bytes| user.copy_payload_at(offset, bytes)) {
            Ok(copied) => copied,
            Err(e) => return e,
        };
        if let Err(e) = copy_name(user, sock, &Received {
            payload: Vec::new(), full_len: copied, peer: None, peer6: None,
            pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None,
        }) { return e; }
        if let Err(e) = user.finish(0, 0) { return e; }
        return copied as i64;
    }
    let rcv = match receive(fd, sock, user.capacity, flags) { Ok(rcv) => rcv, Err(e) => return e };
    let copied = match user.copy_payload(&rcv.payload) { Ok(n) => n, Err(e) => return e };
    if let Err(e) = copy_name(user, sock, &rcv) { return e; }
    let ctrl = control(sock, &rcv, user.controllen);
    if !ctrl.bytes.is_empty() && uaccess::copy_to_user(user.control, &ctrl.bytes).is_err() { return err(Errno::Efault); }
    let mut out_flags = ctrl.flags;
    if rcv.full_len > copied { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(ctrl.bytes.len(), out_flags) { return e; }
    if flags & MSG_TRUNC != 0 { rcv.full_len as i64 } else { copied as i64 }
}
