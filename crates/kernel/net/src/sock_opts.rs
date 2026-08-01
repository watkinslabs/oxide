// Socket option helpers split out of sock.rs to keep the socket wrapper under
// the per-file size cap.
//
// Module manifest:
// - this file: security admission plus the TCP keepalive option application.
// - `sol_socket`: the generic SOL_SOCKET option table (slots 54/55).
// - `peercred`: the `SO_PEERCRED` value encoding, including the no-peer answer.
// - `sol_ip` / `sol_ipv6` / `sol_tcp` / `sol_udp`: one option level each.

pub mod peercred;
pub mod sol_ip;
pub mod sol_ipv6;
pub mod sol_socket;
pub mod sol_tcp;
pub mod sol_udp;

use crate::sock::InetSocket;
use crate::stack::TcpEntry;

pub const TCP_KEEPIDLE_DEFAULT_S: i32 = 7200;
pub const TCP_KEEPINTVL_DEFAULT_S: i32 = 75;
pub const TCP_KEEPCNT_DEFAULT: i32 = 9;

/// Apply the canonical namespace security decision for socket option access.
/// ABI code calls this boundary but does not implement policy itself. # C: O(1)
pub fn check_option(sock: &InetSocket) -> Result<(), crate::NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Option,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

/// Canonical security admission for socketpair creation. # C: O(1)
pub fn check_socketpair(namespace: u64, family: u16, socket_type: u32, protocol: u32)
    -> Result<(), crate::NetError>
{
    let context = security::network::Context { namespace, family, socket_type, protocol,
        operation: security::network::Operation::SocketPair };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(crate::NetError::Eacces);
    }
    Ok(())
}

/// Canonical security admission for local/peer name snapshots. # C: O(1)
pub fn check_name_query(namespace: u64, family: u16) -> Result<(), crate::NetError> {
    crate::security_admission::check(namespace, family, security::network::Operation::NameQuery)
}

/// Canonical security admission for integer ioctl access. # C: O(1)
pub fn check_ioctl(namespace: u64, family: u16) -> Result<(), crate::NetError> {
    crate::security_admission::check(namespace, family, security::network::Operation::Ioctl)
}

/// Canonical security admission for a socket receive transaction. # C: O(1)
pub fn check_receive(sock: &InetSocket) -> Result<(), crate::NetError> {
    crate::security_admission::check(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire), security::network::Operation::Receive)
}

/// Canonical security admission for a socket send transaction. # C: O(1)
pub fn check_send(sock: &InetSocket) -> Result<(), crate::NetError> {
    crate::security_admission::check(sock.net_ns(),
        sock.family.load(core::sync::atomic::Ordering::Acquire), security::network::Operation::Send)
}

/// Sender credentials for AF_UNIX SCM_CREDENTIALS. Caller fetches from
/// `sched::current()` and passes the snapshot through the socket layer.
#[derive(Copy, Clone, Debug, Default)]
pub struct SenderCreds {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

impl SenderCreds {
    /// The per-message stamp these credentials produce, pinning the identity
    /// the pid names so a receiver in another namespace is told ITS number for
    /// the sender. # C: O(N_tasks) for a caller-supplied pid; O(1) otherwise
    pub fn stamp(&self) -> crate::unix_sock::MsgCred {
        let current = crate::unix_sock::MsgCred::of_current((self.pid, self.uid, self.gid));
        if current.pid == self.pid && current.uid == self.uid && current.gid == self.gid {
            return current;
        }
        crate::unix_sock::MsgCred::from_supplied((self.pid, self.uid, self.gid))
    }
}

fn keepalive_secs_to_ns(secs: i32) -> u64 {
    (secs.max(1) as u64).saturating_mul(1_000_000_000)
}

/// Copy listener TCP keepalive policy to an accepted socket. # C: O(1)
pub fn inherit_tcp_keepalive_opts(dst: &InetSocket, src: &InetSocket) {
    use core::sync::atomic::Ordering;
    dst.opts.keepalive.store(src.opts.keepalive.load(Ordering::Acquire), Ordering::Release);
    dst.opts.tcp_keepidle_s.store(src.opts.tcp_keepidle_s.load(Ordering::Acquire), Ordering::Release);
    dst.opts.tcp_keepintvl_s.store(src.opts.tcp_keepintvl_s.load(Ordering::Acquire), Ordering::Release);
    dst.opts.tcp_keepcnt.store(src.opts.tcp_keepcnt.load(Ordering::Acquire), Ordering::Release);
}

/// Copy listener OOB-inline policy to an accepted TCP socket. # C: O(1)
pub fn inherit_tcp_oobinline(dst: &InetSocket, src: &InetSocket) {
    use core::sync::atomic::Ordering;
    dst.opts.oobinline.store(src.opts.oobinline.load(Ordering::Acquire), Ordering::Release);
}

/// Apply socket-level keepalive configuration to a live TCP TCB. # C: O(1)
pub fn apply_tcp_keepalive_opts(sock: &InetSocket, entry: &TcpEntry) {
    use core::sync::atomic::Ordering;
    let mut c = entry.conn.lock();
    c.ka_enabled = sock.opts.keepalive.load(Ordering::Acquire) != 0;
    c.ka_idle_ns = keepalive_secs_to_ns(sock.opts.tcp_keepidle_s.load(Ordering::Acquire));
    c.ka_intvl_ns = keepalive_secs_to_ns(sock.opts.tcp_keepintvl_s.load(Ordering::Acquire));
    c.ka_cnt_max = sock.opts.tcp_keepcnt.load(Ordering::Acquire).max(1) as u32;
    c.ka_count = 0;
    c.next_ka_ns = 0;
}

/// Socket personality the generic SOL_SOCKET table branches on. # C: O(1)
pub fn describe(sock: &InetSocket) -> sol_socket::OptSock {
    use core::sync::atomic::Ordering;
    use crate::sock::SockKind;
    let family = sock.family.load(Ordering::Acquire);
    let inet = family == crate::sock::AF_INET || family == crate::sock::AF_INET6;
    let (tcp, udp) = match &*sock.kind.lock() {
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) => (inet, false),
        SockKind::Udp => (false, inet),
        _ => (false, false),
    };
    let stream = matches!(&*sock.kind.lock(),
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_)
        | SockKind::Unix(_, _) | SockKind::UnixUnbound(_, _) | SockKind::UnixListener(_))
        && sock.opts.so_type.load(Ordering::Acquire) == 0;
    sol_socket::OptSock {
        family, stream, tcp, udp,
        // Linux gives `set_peek_off` to the AF_UNIX protocol operations only.
        peek_off_capable: family == crate::sock::AF_UNIX,
    }
}

/// Socket personality the `IPPROTO_IP` option table branches on. # C: O(1)
pub fn describe_ip(sock: &InetSocket) -> sol_ip::set::IpSock {
    use core::sync::atomic::Ordering;
    use crate::sock::SockKind;
    let (stream, dgram, raw, inet_num) = match &*sock.kind.lock() {
        SockKind::Udp => (false, true, false, sock.local_port.lock().unwrap_or(0)),
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) =>
            (true, false, false, sock.local_port.lock().unwrap_or(0)),
        // A raw socket's `inet_num` is its protocol number, which is what the
        // protocol read and the router-alert screen both consult.
        SockKind::Raw4(endpoint) => (false, false, true, endpoint.protocol() as u16),
        SockKind::Raw6(endpoint) => (false, false, true, endpoint.protocol() as u16),
        _ => (false, false, false, 0),
    };
    sol_ip::set::IpSock {
        stream, dgram, raw, inet_num,
        on_ra_chain: sock.opts.ip.flag(sol_ip::flag::RTALERT),
        bound_if: sock.opts.bound_ifindex.load(Ordering::Acquire) as i32,
    }
}

/// Socket personality the `IPPROTO_IPV6` option table branches on.
/// # C: O(1)
pub fn describe_ipv6(sock: &InetSocket) -> sol_ipv6::set::Ipv6Sock {
    use core::sync::atomic::Ordering;
    use crate::sock::SockKind;
    let (stream, dgram, raw, protocol) = match &*sock.kind.lock() {
        SockKind::Udp => (false, true, false, crate::sock_opts::sol_ipv6::uapi::IPPROTO_UDP),
        SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::TcpConn(_) =>
            (true, false, false, crate::sock_opts::sol_ipv6::uapi::IPPROTO_TCP),
        SockKind::Raw4(endpoint) => (false, false, true, endpoint.protocol()),
        SockKind::Raw6(endpoint) => (false, false, true, endpoint.protocol()),
        _ => (false, false, false, 0),
    };
    let peer6 = *sock.peer6.lock();
    sol_ipv6::set::Ipv6Sock {
        stream, dgram, raw, protocol,
        inet_num: sock.local_port.lock().unwrap_or(0),
        v6only: sock.opts.ipv6_v6only.load(Ordering::Acquire) != 0,
        established: peer6.is_some() || sock.peer.lock().is_some(),
        daddr_v4mapped: peer6.is_some_and(|(ip, _)| ip.to_v4_mapped().is_some()),
        // No send is ever left half-committed across a socket option call in
        // this stack, so a conversion never races one.
        send_pending: false,
        bound_if: sock.opts.bound_ifindex.load(Ordering::Acquire) as i32,
        on_ra_chain: sock.opts.ipv6.flag(sol_ipv6::flag::RTALERT),
    }
}

/// `sk_get_meminfo`: the live memory report `SO_MEMINFO` publishes. The
/// receive and send charges come from the same queues `SIOCINQ` / `SIOCOUTQ`
/// count, so the two interfaces can never disagree. # C: O(queued frames)
pub fn meminfo(sock: &InetSocket) -> sol_socket::varlen::MemInfo {
    use core::sync::atomic::Ordering;
    use crate::sock::SockKind;
    let mut info = sol_socket::varlen::MemInfo {
        rcvbuf: sock.opts.rcvbuf.load(Ordering::Acquire).max(0) as u32,
        sndbuf: sock.opts.sndbuf.load(Ordering::Acquire).max(0) as u32,
        ..Default::default()
    };
    let (rmem, wmem, drops) = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => {
            let c = entry.conn.lock();
            let retx: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
            (c.recv_buf.len(), c.send_buf.len() + retx, 0)
        }
        SockKind::TcpListener(listener) => (listener.accept_q.lock().len(), 0, 0),
        SockKind::Udp => {
            let queued = if let Some(q) = sock.udp6.lock().as_ref() { q.queued_bytes() }
                else if let Some(q) = sock.udp4.lock().as_ref() { q.queued_bytes() } else { 0 };
            (queued, 0, 0)
        }
        SockKind::Raw4(endpoint) => {
            let state = endpoint.snapshot();
            (state.queued_bytes, 0, state.drops)
        }
        SockKind::Raw6(endpoint) => (endpoint.snapshot().queued_bytes, 0, 0),
        SockKind::Unix(pair, end) => match end {
            crate::UnixEnd::A => (pair.b_to_a.lock().buf.len(), pair.a_to_b.lock().buf.len(), 0),
            crate::UnixEnd::B => (pair.a_to_b.lock().buf.len(), pair.b_to_a.lock().buf.len(), 0),
        },
        SockKind::UnixDgram(q) => (q.queued_bytes(), 0, 0),
        SockKind::UnixMsgPair(pair, end) => {
            let (rx, tx) = match end {
                crate::UnixEnd::A => (pair.b_to_a.lock(), pair.a_to_b.lock()),
                crate::UnixEnd::B => (pair.a_to_b.lock(), pair.b_to_a.lock()),
            };
            let rx_bytes = rx.msgs.iter().map(|m| m.payload.len()).sum::<usize>();
            let tx_bytes = tx.msgs.iter().map(|m| m.payload.len()).sum::<usize>();
            (rx_bytes, tx_bytes, 0)
        }
        SockKind::Packet { rx, .. } => {
            let q = rx.lock();
            (q.charged_bytes(), 0, q.drop_count())
        }
        SockKind::TcpInit | SockKind::UnixUnbound(_, _) | SockKind::UnixListener(_) => (0, 0, 0),
    };
    info.rmem_alloc = rmem.min(u32::MAX as usize) as u32;
    info.wmem_alloc = wmem.min(u32::MAX as usize) as u32;
    info.wmem_queued = info.wmem_alloc;
    info.drops = drops;
    info
}
