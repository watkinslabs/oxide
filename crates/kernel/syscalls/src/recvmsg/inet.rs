use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use net::sock::{InetSocket, Received, SockKind};
use net::uapi::{MSG_DONTWAIT, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK, MSG_TRUNC, MSG_WAITALL};
use syscall::errno::Errno;

use crate::net_errno::errno_from_neterr;
use crate::net_sockaddr::{encoded_sockaddr_for_socket, encoded_sockaddr_in6};
use crate::recv_user::RecvUser;
use crate::recv_control::Control;

// The receive ancillary message numbers live in `net::cmsg`; only the
// error-queue pair is answered here.
const IPPROTO_IP: i32 = 0;
const IPPROTO_IPV6: i32 = 41;
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
            out[0..2].copy_from_slice(&net::sock::AF_INET.to_ne_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[4..8].copy_from_slice(&ip.octets());
            out
        }
        net::IpAddr::V6(ip) => {
            let mut out = alloc::vec![0u8; 28];
            out[0..2].copy_from_slice(&net::sock::AF_INET6.to_ne_bytes());
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
    let copied = match user.copy_payload_record(
        &entry.payload[..core::cmp::min(user.capacity, entry.payload.len())])
    { Ok(n) => n, Err(e) => return e };
    if let Err(e) = user.copy_name(&sockaddr(
        entry.destination, entry.destination_port, family, entry.ifindex,
    )) { return e; }
    let mut ctrl = Control::new(if user.control == 0 { 0 } else { user.controllen });
    let (level, kind) = if family == net::sock::AF_INET6 {
        (IPPROTO_IPV6, IPV6_RECVERR)
    } else { (IPPROTO_IP, IP_RECVERR) };
    ctrl.push(level, kind, &extended_error_data(&entry, family));
    let ctrl_len = ctrl.copy_to_recv(user);
    let mut out_flags = ctrl.flags | MSG_ERRQUEUE as u32 | crate::recv_control::output_flags(flags);
    if entry.payload.len() > copied { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(ctrl_len, out_flags) { return e; }
    copied as i64
}
/// The receive ancillary messages one datagram produces. WHICH messages, in
/// WHAT order, with WHAT payload is decided by `net::cmsg` (`docs/53§4`); this
/// file only reads the socket's option state and moves the bytes. # C: O(headers)
fn control(sock: &InetSocket, rcv: &Received, cap: usize) -> Control {
    let mut out = Control::new(cap);
    let want = wanted(sock);
    for msg in net::cmsg::plan(&want, &meta(sock, rcv)) {
        out.push(msg.level, msg.kind, &msg.bytes);
    }
    if sock.packet_auxdata() == Ok(true) {
        if let Some(packet) = rcv.packet {
            out.push(net::uapi::SOL_PACKET as i32, net::uapi::PACKET_AUXDATA as i32,
                &packet.aux.to_ne_bytes());
        }
    }
    out
}

/// The receive options this socket turned on. # C: O(1)
fn wanted(sock: &InetSocket) -> net::cmsg::Want {
    use net::sock_opts::sol_ip::flag as ip;
    use net::sock_opts::sol_ipv6::flag as ip6;
    net::cmsg::Want {
        gro: sock.opts.udp.gro.load(Ordering::Acquire) != 0,
        pktinfo: sock.opts.ip_pktinfo.load(Ordering::Acquire) != 0,
        ttl: sock.opts.ip_recvttl.load(Ordering::Acquire) != 0,
        tos: sock.opts.ip.flag(ip::RECVTOS),
        recvopts: sock.opts.ip.flag(ip::RECVOPTS),
        retopts: sock.opts.ip.flag(ip::RETOPTS),
        passsec: sock.opts.ip.flag(ip::PASSSEC),
        origdstaddr: sock.opts.ip.flag(ip::ORIGDSTADDR),
        checksum: sock.opts.ip.flag(ip::CHECKSUM),
        fragsize: sock.opts.ip.flag(ip::RECVFRAGSIZE),

        pktinfo6: sock.opts.ipv6_recvpktinfo.load(Ordering::Acquire) != 0,
        hoplimit6: sock.opts.ipv6_recvhoplimit.load(Ordering::Acquire) != 0,
        tclass6: sock.opts.ipv6_recvtclass.load(Ordering::Acquire) != 0,
        flowinfo6: sock.opts.ipv6.flag(ip6::RXFLOW),
        hopopts6: sock.opts.ipv6.flag(ip6::RXHOPOPTS),
        dstopts6: sock.opts.ipv6.flag(ip6::RXDSTOPTS),
        rthdr6: sock.opts.ipv6.flag(ip6::RXSRCRT),
        origdstaddr6: sock.opts.ipv6.flag(ip6::RXORIGDSTADDR),
        fragsize6: sock.opts.ipv6.flag(ip6::RECVFRAGSIZE),
        old_pktinfo6: sock.opts.ipv6.flag(ip6::RXOINFO),
        old_hoplimit6: sock.opts.ipv6.flag(ip6::RXOHLIM),
        old_hopopts6: sock.opts.ipv6.flag(ip6::RXOHOPOPTS),
        old_dstopts6: sock.opts.ipv6.flag(ip6::RXODSTOPTS),
        old_rthdr6: sock.opts.ipv6.flag(ip6::RXOSRCRT),
    }
}

/// The received datagram's header state, as the receive path captured it.
/// # C: O(headers)
fn meta(sock: &InetSocket, rcv: &Received) -> net::cmsg::RxMeta {
    net::cmsg::RxMeta {
        dst: rcv.pktinfo.map(|(dst, iface)| (dst.octets(), iface.raw())),
        ttl: rcv.ttl,
        tos: rcv.tos,
        options: rcv.options.clone(),
        src: rcv.peer.map_or([0u8; 4], |(addr, _)| addr.octets()),
        dport: rcv.dport,
        frag_max: rcv.frag_max,
        // No receive path in this stack retains a whole-datagram checksum, so
        // the checksum message is never produced — the same answer a Linux
        // receive gives when the device did not hand one up.
        checksum: None,
        security: peer_label(sock),
        gro: rcv.gro,
        dst6: rcv.pktinfo6.map(|(dst, iface)| (dst.0, iface.raw())),
        hoplimit: rcv.hoplimit,
        tclass: rcv.tclass,
        flowinfo: rcv.flowinfo,
        ext_headers: rcv.ext_headers.clone(),
        scope_id: rcv.peer6.map_or(0, |(_, _, scope)| scope),
    }
}

/// The peer's security label, published only by a module that labels sockets.
/// # C: O(label)
fn peer_label(sock: &InetSocket) -> Option<Vec<u8>> {
    security::network::peer_security(security::network::PeerContext {
        namespace: sock.net_ns(),
        family: sock.family.load(Ordering::Acquire),
        connected: sock.peer.lock().is_some() || sock.peer6.lock().is_some(),
    })
}

fn copy_packet_name(user: &RecvUser, meta: net::sock::PacketAddr) -> Result<(), i64> {
    let mut sa = [0u8; 20];
    sa[0..2].copy_from_slice(&net::sock::AF_PACKET.to_ne_bytes());
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

fn note_receive(sock: &InetSocket, rcv: &Received) {
    match rcv.packet.and_then(net::sock::PacketReceive::timestamp_ns) {
        Some(timestamp_ns) => sock.note_receive_timestamp(timestamp_ns),
        None => sock.note_receive_now(),
    }
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
    super::rx_trace::event(b"enter");
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(),
        _ => return Err(err(Errno::Einval)),
    };
    let nonblock = flags & MSG_DONTWAIT != 0 || file_nonblock;
    let peek = flags & MSG_PEEK != 0;
    let waitall = flags & MSG_WAITALL != 0;
    let oobinline = sock.opts.oobinline.load(Ordering::Acquire) != 0;
    let mut total = 0usize;
    let deadline = net::sock::compute_deadline_ns(sock.opts.rcvtimeo_ns.load(Ordering::Acquire));
    loop {
        net::sock::drain_loopback();
        let offset = if peek { total } else { 0 };
        match net::sock::stack().tcp_recv_with_offset_oob(&entry, capacity - total, peek, offset,
            oobinline,
            |bytes| copy(total, bytes).map(|n| (n, n))) {
            Ok(Some(copied)) => {
                total += copied;
                super::rx_trace::event(b"data");
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
        // Linux `tcp_recvmsg_locked` (`net/ipv4/tcp.c:2783-2786`):
        // `copied = sock_intr_errno(timeo)` on the nothing-copied arm, while a
        // partial transfer breaks out and returns the count (`tcp.c:2735-2742`).
        if sched::live::deliverable_signals_self() != 0 {
            super::rx_trace::event(b"intr");
            return crate::net_errno::recv_interrupted(deadline, total);
        }
        if net::sock_recv::deadline_expired(deadline) { return if total != 0 { Ok(total) } else { Err(err(Errno::Eagain)) }; }
        super::rx_trace::event(b"prepark");
        let _ = net::sock_recv::wait_recv_source_after(sock, deadline, offset);
        super::rx_trace::event(b"postpark");
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
                    payload: Vec::new(), full_len: 1, ..Default::default()
                }) { return Err(e); }
                tcp_finish(sock, user, flags)?;
                return Ok(1);
            }
            Ok(None) => {
                let pending = sock.take_pending_recv_error();
                if pending != 0 { return Err(-(pending as i64)); }
            }
            Err(e) => return Err(e),
        }
        if nonblock { return Err(err(Errno::Eagain)); }
        // Same `sock_intr_errno(timeo)` rule as the ordinary receive above.
        if sched::live::deliverable_signals_self() != 0 {
            return Err(crate::net_errno::sock_intr_errno(deadline));
        }
        if net::sock_recv::deadline_expired(deadline) { return Err(err(Errno::Eagain)); }
        let _ = net::sock_recv::wait_recv_source_after_urgent(sock, deadline, 0);
    }
}

/// The unread-bytes report a TCP receive owes its caller when `TCP_INQ` is
/// set. The count comes from the same receive queue `SIOCINQ` and
/// `SO_MEMINFO` answer from, so the three can never disagree, and it is only
/// ever built on a successful receive — a failed one publishes no control.
/// # C: O(1)
fn tcp_inq(sock: &Arc<InetSocket>) -> Option<net::sock_opts::inq::InqCmsg> {
    if !sock.opts.tcp.recvmsg_inq.load(Ordering::Acquire) { return None; }
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => entry.clone(),
        _ => return None,
    };
    let queued = entry.conn.lock().recv_buf.len;
    let eof = sock.read_shut.load(Ordering::Acquire)
        || net::sock_io::tcp_recv_eof(entry.conn.lock().state);
    Some(net::sock_opts::inq::InqCmsg::tcp(net::sock_opts::inq::tcp_inq(queued, eof)))
}

/// Publish the TCP control block for one completed receive. # C: O(control)
fn tcp_finish(sock: &Arc<InetSocket>, user: &RecvUser, flags: u64) -> Result<(), i64> {
    let mut ctrl = Control::new(if user.control == 0 { 0 } else { user.controllen });
    ctrl.push_inq(tcp_inq(sock));
    let ctrl_len = ctrl.copy_to_recv(user);
    user.finish(ctrl_len, ctrl.flags | crate::recv_control::output_flags(flags))
}

/// Internet and packet recvmsg copyout. # C: O(payload + control)
pub(crate) fn recv_pinned(sock: &Arc<InetSocket>, file_nonblock: bool, user: &RecvUser, flags: u64) -> i64 {
    let tcp = matches!(*sock.kind.lock(), SockKind::TcpConn(_));
    // TCP's normal and urgent receive paths own their copy transaction rather
    // than entering recvfrom_opts(), so they must admit here. Non-TCP normal
    // receives retain the one admission in recvfrom_opts().
    if flags & MSG_OOB != 0 || tcp {
        if let Err(error) = net::security_admission::check(sock.net_ns(),
            sock.family.load(Ordering::Acquire), security::network::Operation::Receive)
        { return errno_from_neterr(error); }
    }
    if let Some(e) = oob_error(sock, flags) { return err(e); }
    if tcp {
        if flags & MSG_OOB != 0 { return match tcp_oob_with_copy(sock, user, flags, file_nonblock) {
            Ok(copied) => {
                if copied != 0 { sock.note_receive_now(); }
                copied as i64
            }
            Err(e) => e,
        }; }
        let copied = match tcp_with_copy_pinned(sock, user.capacity, flags, file_nonblock, |offset, bytes| user.copy_payload_at(offset, bytes)) {
            Ok(copied) => copied,
            Err(e) => return e,
        };
        if let Err(e) = copy_name(user, sock, &Received {
            payload: Vec::new(), full_len: copied, ..Default::default()
        }) { return e; }
        if let Err(e) = tcp_finish(sock, user, flags) { return e; }
        if copied != 0 { sock.note_receive_now(); }
        return copied as i64;
    }
    let rcv = match receive(sock, user.capacity, flags, file_nonblock) { Ok(rcv) => rcv, Err(e) => return e };
    let copied = match user.copy_payload_record(&rcv.payload) { Ok(n) => n, Err(e) => return e };
    let mut ctrl = control(sock, &rcv, if user.control == 0 { 0 } else { user.controllen });
    let ctrl_len = ctrl.copy_to_recv(user);
    if let Err(e) = copy_name(user, sock, &rcv) { return e; }
    let mut out_flags = ctrl.flags | crate::recv_control::output_flags(flags);
    if rcv.full_len > copied { out_flags |= MSG_TRUNC as u32; }
    if let Err(e) = user.finish(ctrl_len, out_flags) { return e; }
    if rcv.full_len != 0 || rcv.peer.is_some() || rcv.peer6.is_some() || rcv.packet.is_some() {
        note_receive(sock, &rcv);
    }
    if flags & MSG_TRUNC != 0 { rcv.full_len as i64 } else { copied as i64 }
}
