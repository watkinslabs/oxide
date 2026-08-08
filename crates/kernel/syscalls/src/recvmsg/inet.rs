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

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn oob_error(sock: &InetSocket, flags: u64) -> Option<Errno> {
    if flags & MSG_OOB == 0 { return None; }
    match *sock.kind.lock() {
        SockKind::Raw4(_) | SockKind::Raw6(_) => Some(Errno::Eopnotsupp),
        SockKind::Packet { .. } => Some(Errno::Einval),
        _ => None,
    }
}

/// Consume one extended socket error and encode its payload/name/cmsg.
///
/// The record never blocks and never waits: an empty queue is `EAGAIN`
/// regardless of `MSG_DONTWAIT` or the receive timeout. Layout, the offender
/// address and whether `msg_name` is filled are decided by
/// `net::socket_error::abi`. # C: O(payload)
pub(crate) fn recv_error(sock: &Arc<InetSocket>, user: &RecvUser, flags: u64) -> i64 {
    use net::socket_error::abi;
    if let Some(e) = oob_error(sock, flags) { return err(e); }
    let Some(entry) = sock.take_extended_error() else { return err(Errno::Eagain); };
    let v6 = sock.family.load(Ordering::Acquire) == net::sock::AF_INET6;
    let copied = match user.copy_payload_record(
        &entry.payload[..core::cmp::min(user.capacity, entry.payload.len())])
    { Ok(n) => n, Err(e) => return e };
    let name = abi::name_bytes(&entry, v6).unwrap_or_default();
    if let Err(e) = user.copy_name(&name) { return e; }
    let opt_cmsg = sock.opts.timestamping.load(Ordering::Acquire)
        & net::uapi::SOF_TIMESTAMPING_OPT_CMSG != 0;
    let mut ctrl = Control::new(if user.control == 0 { 0 } else { user.controllen });
    let (level, kind) = abi::cmsg_slot(v6);
    ctrl.push(level, kind, &abi::errhdr_bytes(&entry, v6, opt_cmsg));
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

/// The received datagram's header state, as the receive path captured it. The
/// projection itself is owned by `net`, so it is checkable without a kernel;
/// only the peer label needs syscall context. # C: O(headers)
fn meta(sock: &InetSocket, rcv: &Received) -> net::cmsg::RxMeta {
    rcv.rx_meta(peer_label(sock))
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
        // Linux `tcp_recvmsg_locked`:
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
    // AF_PACKET screens the whole flag word first, before the error queue and
    // before any state is consulted.
    if matches!(*sock.kind.lock(), SockKind::Packet { .. })
        && !net::sock::packet_recv_flags_allowed(flags)
    { return err(Errno::Einval); }
    let tcp = matches!(*sock.kind.lock(), SockKind::TcpConn(_));
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
