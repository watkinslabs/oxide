// Socket I/O coordination. `error` owns canonical errno translation;
// `tcp_read` owns TCP waiting; `packet` owns AF_PACKET queue receive.

use crate::stack::{TcpConnectWait, TcpEntry};
use crate::netdev::NetError;
use crate::sock::{drain_loopback, stack, InetSocket, SockKind, AF_INET6};

mod tcp_read;
mod error;
mod packet;
mod types;
pub use types::{Received, RecvOptions};
pub(crate) use error::pending_net_error;
pub use tcp_read::tcp_recv_eof;
pub(crate) use tcp_read::{arm_tcp_read, arm_tcp_read_after, arm_tcp_read_after_mode,
    read_tcp_blocking, tcp_vfs_error};

/// F159: blocking wait for TCP connect's SYN-ACK. Park on
/// `entry.rx_waiters`; `deliver_tcp` wakes after any input (state
/// transition to Established for normal path, to Closed on RST);
/// `tcp_retx_tick` wakes after flipping state to Closed for
/// retry-exhaustion. Returns the canonical abort error, Ok on
/// Established. drain_loopback every iter so a self-loopback
/// connect doesn't depend on virtio's softirq.
/// # C: blocks until Established or Closed
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn connect_wait_established(
    sock: &InetSocket,
    entry: &alloc::sync::Arc<TcpEntry>,
) -> Result<(), NetError> {
    let deadline_ns = crate::sock::compute_deadline_ns(
        sock.opts.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire));
    loop {
        drain_loopback();
        // F168: surface -EINTR if a non-blocked signal arrived between
        // our last wake and now.
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(NetError::Eintr);
        }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
            return Err(NetError::Eagain);
        }
        #[cfg(target_os = "oxide-kernel")]
        match entry.arm_connect_wait(deadline_ns) {
            TcpConnectWait::Established => return Ok(()),
            TcpConnectWait::Closed => {
                return Err(pending_net_error(sock.take_pending_recv_error()));
            }
            TcpConnectWait::Parked => {
                // SAFETY: arm_connect_wait registered current under conn.
                unsafe { sched::live::schedule::schedule(); }
                entry.rx_waiters.remove_current();
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(NetError::Eio);
    }
}

/// F164: blocking TCP write. Repeatedly tcp_send into the conn,
/// parking on `entry.rx_waiters` (woken by `deliver_tcp` on every
/// input — ACKs that pop retx_q free up send-buffer headroom) until
/// either every byte is queued or the connection terminates.
/// Returns short on partial-write only after at least one byte
/// landed (POSIX short-write semantics — caller's libc retries).
/// # C: blocks until buf drained or peer dies
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn write_tcp_blocking(
    sock: &InetSocket,
    entry: &alloc::sync::Arc<TcpEntry>,
    buf: &[u8],
    sndbuf_cap: usize,
    deadline_ns: u64,
    nodelay: bool,
    cork: bool,
) -> vfs::KResult<usize> {
    let mut total = 0usize;
    while total < buf.len() {
        let eno = sock.take_pending_recv_error();
        if eno != 0 {
            if total > 0 { return Ok(total); }
            return Err(tcp_vfs_error(eno));
        }
        match stack().tcp_send(entry, &buf[total..], sndbuf_cap, nodelay, cork) {
            Ok(n) if n > 0 => {
                total += n;
                drain_loopback();
            }
            Ok(_) | Err(NetError::Eagain) => {
                // No space right now — park and re-check after wake.
                // First check if the conn is dead: no point waiting for
                // ACKs the peer will never send.
                let st = entry.conn.lock().state;
                if matches!(st,
                    crate::tcp_state::TcpState::Closed
                    | crate::tcp_state::TcpState::CloseWait
                    | crate::tcp_state::TcpState::LastAck
                    | crate::tcp_state::TcpState::Closing
                    | crate::tcp_state::TcpState::TimeWait
                    | crate::tcp_state::TcpState::FinWait1
                    | crate::tcp_state::TcpState::FinWait2
                ) {
                    // F166/F167: POSIX write to a closed/closing send
                    // side returns EPIPE AND raises SIGPIPE. Userspace
                    // that ignored SIGPIPE (signal(SIGPIPE, SIG_IGN))
                    // observes EPIPE; default disposition terminates
                    // the process. Short success then EPIPE on next
                    // call: surface the count now, peer hangup
                    // discovered next time.
                    #[cfg(target_os = "oxide-kernel")]
                    sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Epipe);
                }
                // F168: signal-interruptible — return short success
                // if we already accepted some bytes, else EINTR.
                #[cfg(target_os = "oxide-kernel")]
                if sched::live::deliverable_signals_self() != 0 {
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Eintr);
                }
                // F169: SO_SNDTIMEO expiry → short success or Eagain.
                #[cfg(target_os = "oxide-kernel")]
                if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Eagain);
                }
                #[cfg(target_os = "oxide-kernel")]
                if entry.arm_transmit_wait(&sock.write_shut, sndbuf_cap, deadline_ns) {
                    // SAFETY: arm_transmit_wait registered current under conn.
                    unsafe { sched::live::schedule::schedule(); }
                    entry.rx_waiters.remove_current();
                }
                #[cfg(not(target_os = "oxide-kernel"))]
                {
                    if total > 0 { return Ok(total); }
                    return Err(vfs::VfsError::Eagain);
                }
            }
            Err(_) => {
                if total > 0 { return Ok(total); }
                return Err(vfs::VfsError::Eio);
            }
        }
    }
    Ok(total)
}

/// F171: blocking read on an AF_UNIX SOCK_STREAM pair. Park on
/// the per-ring read waitq until the writer pushes or closes;
/// return EOF (Ok(0)) when peer closed AND ring is empty. Honors
/// SO_RCVTIMEO via park_with_deadline (timer scanner wake → Eagain).
/// # C: blocks until ring non-empty or peer FIN/close
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn read_unix_stream_blocking(
    pair: &alloc::sync::Arc<crate::UnixPair>,
    end: crate::UnixEnd,
    buf: &mut [u8],
    deadline_ns: u64,
) -> vfs::KResult<usize> {
    loop {
        // Fast path + interruption checks BEFORE arming the wait, matching
        // Linux (signal/timeout observed before prepare_to_wait).
        let got = pair.read(end, buf.len());
        if !got.is_empty() {
            let n = got.len();
            buf[..n].copy_from_slice(&got);
            return Ok(n);
        }
        if pair.take_reset(end) { return Err(vfs::VfsError::Econnreset); }
        if pair.is_eof(end) { return Ok(0); }
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(vfs::VfsError::Eintr);
        }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
            return Err(vfs::VfsError::Eagain);
        }
        // Race-free re-check-and-park: read_or_park registers on the reader
        // wait list UNDER the read-ring lock, so a concurrent write()+wake_all
        // (which needs that same lock to push) cannot land between the
        // emptiness check and the park and lose the wakeup (Linux
        // prepare_to_wait). A blocked D-Bus stream read that peers with a
        // writer on another CPU would otherwise stall forever.
        #[cfg(target_os = "oxide-kernel")]
        {
            use crate::unix_sock::stream::ReadOutcome;
            match pair.read_or_park(end, buf.len(), deadline_ns) {
                ReadOutcome::Data(got) => {
                    if !got.is_empty() {
                        let n = got.len();
                        buf[..n].copy_from_slice(&got);
                        return Ok(n);
                    }
                    // empty (raced to another reader) — retry
                }
                ReadOutcome::Reset => return Err(vfs::VfsError::Econnreset),
                ReadOutcome::Eof => return Ok(0),
                // SAFETY: process ctx; preempt-off owned by syscall stub; we
                // are on the reader wait list (armed under the ring lock).
                ReadOutcome::Parked => unsafe {
                    sched::live::schedule::schedule();
                    pair.reader_waiters(end).remove_current();
                }
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// F171: blocking recv on an AF_UNIX SOCK_SEQPACKET/SOCK_DGRAM
/// socketpair (UnixMsgPair). Per-message semantic: returns at
/// most one pre-truncated message per call. EOF when peer closed
/// AND queue drained.
/// # C: blocks until queue non-empty or peer FIN/close
/// # Ctx: process; preempt-off; runqueue installed
pub(crate) fn read_unix_msg_blocking(
    pair: &alloc::sync::Arc<crate::UnixMsgPair>,
    end: crate::UnixEnd,
    buf: &mut [u8],
    deadline_ns: u64,
) -> vfs::KResult<usize> {
    loop {
        if let Some(msg) = pair.recv(end, buf.len()) {
            let n = msg.len();
            buf[..n].copy_from_slice(&msg);
            return Ok(n);
        }
        if pair.take_reset(end) { return Err(vfs::VfsError::Econnreset); }
        // recv returns None only when nothing pending AND not EOF
        // (EOF returns Some(empty)). So fall through to park.
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::deliverable_signals_self() != 0 {
            return Err(vfs::VfsError::Eintr);
        }
        #[cfg(target_os = "oxide-kernel")]
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns {
            return Err(vfs::VfsError::Eagain);
        }
        #[cfg(target_os = "oxide-kernel")]
        match pair.arm_read(end, deadline_ns) {
            crate::unix_sock::msg_pair::ArmMsgRead::Retry => continue,
            crate::unix_sock::msg_pair::ArmMsgRead::Reset => {
                let _ = pair.take_reset(end);
                return Err(vfs::VfsError::Econnreset);
            }
            crate::unix_sock::msg_pair::ArmMsgRead::Eof => return Ok(0),
            crate::unix_sock::msg_pair::ArmMsgRead::Parked { reader_shutdown } => unsafe {
                sched::live::schedule::schedule();
                pair.reader_waiters(end).remove_current();
                if !reader_shutdown && pair.kind == crate::UnixMsgKind::Datagram
                    && pair.reader_shutdown(end) && !pair.has_msg(end)
                {
                    return Ok(0);
                }
            },
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        return Err(vfs::VfsError::Eagain);
    }
}

/// F169: monotonic-ns reader visible to io helpers without
/// crossing the kernel-vs-hosted boundary at every call site.
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn monotonic_ns_safe() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(target_arch = "aarch64")]
    { return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

/// F169: convert a SO_RCVTIMEO / SO_SNDTIMEO ns value into an
/// absolute monotonic deadline. `0` (no timeout configured) →
/// `0` (indefinite wait). Saturating add prevents wrap.
/// # C: O(1)
pub fn compute_deadline_ns(timeo_ns: i64) -> u64 {
    if timeo_ns <= 0 { return 0; }
    let now = monotonic_ns_safe();
    if now == 0 { return 0; }
    now.saturating_add(timeo_ns as u64)
}

/// `recvfrom` per `recvfrom(2)`. work fn. Returns the payload
/// and an optional peer address (None for AF_UNIX SOCK_DGRAM and
/// for sockets without a stored peer).
/// # C: O(payload bytes)
pub fn recvfrom(sock: &alloc::sync::Arc<InetSocket>, max_len: usize) -> Result<Received, NetError> {
    recvfrom_opts(sock, max_len, RecvOptions::default())
}

/// `recvfrom` variant with datagram flags that affect queue consumption.
/// # C: O(payload bytes)
pub fn recvfrom_opts(
    sock: &InetSocket,
    max_len: usize,
    opts: RecvOptions,
) -> Result<Received, NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Receive,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    // AF_UNIX SOCK_DGRAM.
    if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
        let q = q.clone();
        let msg = if opts.peek {
            q.msgs.lock().front().map(|msg| msg.payload.clone())
        } else {
            q.pop().map(|msg| {
                let crate::UnixDgram { payload, fds, .. } = msg;
                drop(fds);
                crate::unix_sock::collect_scm_rights();
                payload
            })
        };
        let Some(msg) = msg else {
            return Err(NetError::Eagain);
        };
        let full_len = msg.len();
        let take = core::cmp::min(max_len, full_len);
        let mut out = alloc::vec::Vec::with_capacity(take);
        out.extend_from_slice(&msg[..take]);
        return Ok(Received { payload: out, full_len, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
    }
    // AF_UNIX SOCK_STREAM socketpair (UnixPair byte rings). Same bug as the
    // SEQPACKET case below: recvmsg/recvfrom had no SockKind::Unix branch and
    // fell through to UDP → EAGAIN, never draining. systemd's sd-event reads
    // its STREAM socketpairs (notify/private bus) via recvmsg, so the fd
    // stayed perpetually POLLIN and PID1 spun ("Looping too fast"). Drain the
    // read ring here (peek leaves it intact for MSG_PEEK).
    let stream = match &*sock.kind.lock() {
        SockKind::Unix(p, e) => Some((p.clone(), *e)),
        _ => None,
    };
    if let Some((pair, end)) = stream {
        let got = if opts.peek { pair.peek(end, max_len) } else { pair.read(end, max_len) };
        if !got.is_empty() {
            let full_len = got.len();
            return Ok(Received { payload: got, full_len, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
        }
        if pair.take_reset(end) { return Err(NetError::Econnreset); }
        // Empty: EOF (peer closed + drained) → 0-byte read; else EAGAIN so the
        // caller blocks/retries rather than seeing a false EOF.
        if pair.is_eof(end) {
            return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
        }
        return Err(NetError::Eagain);
    }
    // AF_UNIX SOCK_SEQPACKET/DGRAM socketpair. The inode read() path
    // drains via read_unix_msg_blocking, but recvmsg/recvfrom landed
    // here with NO UnixMsgPair branch — so it fell through to the UDP
    // path and returned EAGAIN, never draining. systemd reads its
    // SEQPACKET socketpair via recvmsg, so the fd stayed perpetually
    // POLLIN and PID1's sd-event loop span ("Looping too fast"). Pop one
    // message (SEQPACKET per-message truncation) here too.
    let msgpair = match &*sock.kind.lock() {
        SockKind::UnixMsgPair(p, e) => Some((p.clone(), *e)),
        _ => None,
    };
    if let Some((pair, end)) = msgpair {
        return match pair.recv_payload(end, max_len, opts.peek) {
            Some((msg, full_len)) => Ok(Received { payload: msg, full_len, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None }),
            None => if pair.take_reset(end) { Err(NetError::Econnreset) } else { Err(NetError::Eagain) },
        };
    }
    if let SockKind::Raw4(endpoint) = &*sock.kind.lock() {
        let Some(datagram) = endpoint.recv(opts.peek) else {
            if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
                return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0,
                    peer: None, peer6: None, pktinfo: None, pktinfo6: None,
                    hoplimit: None, ttl: None, packet: None });
            }
            return Err(NetError::Eagain);
        };
        let full_len = datagram.packet.len();
        let take = core::cmp::min(max_len, full_len);
        return Ok(Received {
            payload: datagram.packet[..take].to_vec(), full_len,
            peer: Some((datagram.source, 0)), peer6: None,
            pktinfo: Some((datagram.destination, datagram.iface)), pktinfo6: None,
            hoplimit: None, ttl: Some(datagram.ttl), packet: None,
        });
    }
    if let SockKind::Raw6(endpoint) = &*sock.kind.lock() {
        let Some(datagram) = endpoint.recv(opts.peek) else {
            if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
                return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0,
                    peer: None, peer6: None, pktinfo: None, pktinfo6: None,
                    hoplimit: None, ttl: None, packet: None });
            }
            return Err(NetError::Eagain);
        };
        let full_len = datagram.payload.len();
        let take = core::cmp::min(max_len, full_len);
        return Ok(Received {
            payload: datagram.payload[..take].to_vec(), full_len, peer: None,
            peer6: Some((datagram.meta.source.addr, 0, datagram.meta.source.scope_id)),
            pktinfo: None, pktinfo6: Some((datagram.meta.destination, datagram.meta.iface)),
            hoplimit: Some(datagram.meta.hop_limit), ttl: None, packet: None,
        });
    }
    if let Some(received) = packet::recv(sock, max_len, opts) { return received; }
    // TCP.
    if let SockKind::TcpConn(entry) = &*sock.kind.lock() {
        let entry = entry.clone();
        drain_loopback();
        let inline = sock.opts.oobinline.load(core::sync::atomic::Ordering::Acquire) != 0;
        let payload = stack().tcp_recv_with_offset_oob(&entry, max_len, opts.peek, 0, inline,
            |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len())))
            .ok().flatten().unwrap_or_default();
        if payload.is_empty() {
            let eno = sock.take_pending_recv_error();
            if eno != 0 { return Err(pending_net_error(eno)); }
            if sock.read_shut.load(core::sync::atomic::Ordering::Acquire)
                || tcp_recv_eof(entry.conn.lock().state)
            {
                return Ok(Received { payload, full_len: 0, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
            }
            return Err(NetError::Eagain);
        }
        let full_len = payload.len();
        let peer = *sock.peer.lock();
        return Ok(Received { payload, full_len, peer, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
    }
    // UDP. AF_INET6 datagram sockets retain their exact v6 endpoint;
    // consulting the IPv4 endpoint would always miss.
    if sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6 {
        drain_loopback();
        let eno = sock.take_pending_recv_error();
        if eno != 0 { return Err(pending_net_error(eno)); }
        let endpoint = match sock.udp6.lock().as_ref().cloned() {
            Some(endpoint) => endpoint,
            None => {
                let eno = sock.take_pending_recv_error();
                if eno != 0 { return Err(pending_net_error(eno)); }
                if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
                    return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
                }
                return Err(NetError::Eagain);
            }
        };
        let got = endpoint.recv(opts.peek);
        let Some((src_ip6, src_port, dst_ip6, iface, hop, full)) = got else {
            let eno = sock.take_pending_recv_error();
            if eno != 0 { return Err(pending_net_error(eno)); }
            if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
                return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
            }
            return Err(NetError::Eagain);
        };
        let full_len = full.len();
        let take = core::cmp::min(max_len, full_len);
        let mut out = alloc::vec::Vec::with_capacity(take);
        out.extend_from_slice(&full[..take]);
        return Ok(Received {
            payload: out, full_len, peer: None,
            peer6: Some((src_ip6, src_port, if src_ip6.is_link_local() { iface.raw() } else { 0 })),
            pktinfo: None, pktinfo6: Some((dst_ip6, iface)), hoplimit: Some(hop), ttl: None, packet: None,
        });
    }
    // UDP / others (AF_INET).
    drain_loopback();
    let eno = sock.take_pending_recv_error();
    if eno != 0 { return Err(pending_net_error(eno)); }
    let endpoint = match sock.udp4.lock().as_ref().cloned() {
        Some(endpoint) => endpoint,
        None => {
            let eno = sock.take_pending_recv_error();
            if eno != 0 { return Err(pending_net_error(eno)); }
            if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
                return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
            }
            return Err(NetError::Eagain);
        }
    };
    let got = endpoint.recv(opts.peek);
    let Some((src_ip, src_port, dst_ip, iface, ttl, full)) = got else {
        let eno = sock.take_pending_recv_error();
        if eno != 0 { return Err(pending_net_error(eno)); }
        if sock.read_shut.load(core::sync::atomic::Ordering::Acquire) {
            return Ok(Received { payload: alloc::vec::Vec::new(), full_len: 0, peer: None, peer6: None, pktinfo: None, pktinfo6: None, hoplimit: None, ttl: None, packet: None });
        }
        return Err(NetError::Eagain);
    };
    let full_len = full.len();
    let take = core::cmp::min(max_len, full_len);
    let mut out = alloc::vec::Vec::with_capacity(take);
    out.extend_from_slice(&full[..take]);
    Ok(Received { payload: out, full_len, peer: Some((src_ip, src_port)), peer6: None, pktinfo: Some((dst_ip, iface)), pktinfo6: None, hoplimit: None, ttl: Some(ttl), packet: None })
}
