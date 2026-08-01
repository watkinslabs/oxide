//! Lifecycle-locked INET connect admission and commit.

use alloc::sync::Arc;

use super::{
    bound_iface, ConnectAdmission, InetSocket, NetError, RemoteAddr, SockKind,
    SockLockClass,
};

enum ConnectKind {
    Udp,
    Tcp,
    Raw4(Arc<crate::raw4::Raw4Endpoint>),
    Raw6(Arc<crate::raw6::Raw6Endpoint>),
}

/// Successful generic/TCP-state admission retaining the socket lifecycle lock.
pub struct ConnectTransaction<'a> {
    sock: &'a InetSocket,
    local_port: sync::Guard<'a, Option<u16>, SockLockClass>,
    kind: ConnectKind,
    protocol: Option<u32>,
}

/// Run generic connect security and TCP state admission before cgroup policy. # C: O(1)
pub fn preflight_connect(sock: &InetSocket) -> Result<ConnectTransaction<'_>, NetError> {
    let admission = super::admit_connect(sock)?;
    preflight_connect_admitted(sock, admission)
}

/// Retain lifecycle state after generic connect security already succeeded. # C: O(1)
pub fn preflight_connect_admitted(sock: &InetSocket, _admission: ConnectAdmission)
    -> Result<ConnectTransaction<'_>, NetError>
{
    let local_port = sock.local_port.lock();
    if sock.released.load(core::sync::atomic::Ordering::Acquire) {
        return Err(NetError::Einval);
    }
    let (kind, protocol) = match &*sock.kind.lock() {
        SockKind::Udp => (ConnectKind::Udp, Some(crate::addr::IpProto::Udp as u32)),
        SockKind::TcpInit => (ConnectKind::Tcp, Some(crate::addr::IpProto::Tcp as u32)),
        SockKind::TcpConn(entry) => {
            if entry.conn.lock().state == crate::tcp_state::TcpState::Established {
                return Err(NetError::Eisconn);
            }
            return Err(NetError::Ealready);
        }
        SockKind::TcpListener(_) => return Err(NetError::Einval),
        SockKind::Raw4(endpoint) => (ConnectKind::Raw4(endpoint.clone()), None),
        SockKind::Raw6(endpoint) => (ConnectKind::Raw6(endpoint.clone()), None),
        _ => return Err(NetError::Einval),
    };
    Ok(ConnectTransaction { sock, local_port, kind, protocol })
}

impl ConnectTransaction<'_> {
    /// Socket type/protocol presented to cgroup sockaddr policy. # C: O(1)
    pub fn transport(&self) -> Option<(u32, u32)> {
        self.protocol.map(|protocol| (
            self.sock.opts.so_type.load(core::sync::atomic::Ordering::Acquire) as u32,
            protocol,
        ))
    }

    /// Whether this transaction owns a datagram socket. # C: O(1)
    pub fn is_udp(&self) -> bool { matches!(self.kind, ConnectKind::Udp) }

    /// Snapshot IPV6_V6ONLY while the lifecycle transaction remains active. # C: O(1)
    pub fn ipv6_v6only(&self) -> bool {
        self.sock.opts.ipv6_v6only.load(core::sync::atomic::Ordering::Acquire) != 0
    }

    /// Publish a rewritten destination without reopening the lifecycle race. # C: O(N + wait)
    pub fn commit(self, addr: RemoteAddr, nonblock: bool) -> Result<(), NetError> {
        let Self { sock, mut local_port, kind, .. } = self;
        match (kind, addr) {
            (ConnectKind::Udp, RemoteAddr::Inet { ip, port })
                if sock.family.load(core::sync::atomic::Ordering::Acquire)
                    == super::AF_INET6 =>
            {
                crate::sock_v6::connect_udp6_locked(
                    sock, &mut local_port, crate::Ipv6Addr::from_v4_mapped(ip), port, 0,
                )
            }
            (ConnectKind::Udp, RemoteAddr::Inet { ip, port }) => {
                sock.ensure_bound_locked(&mut local_port)?;
                *sock.peer.lock() = Some((ip, port));
                Ok(())
            }
            (ConnectKind::Udp, RemoteAddr::Inet6 { ip, port, scope_id }) => {
                crate::inet_tx::validate_udp6_mapped_destination(
                    ip,
                    sock.opts.ipv6_v6only.load(
                        core::sync::atomic::Ordering::Acquire,
                    ) != 0,
                )?;
                crate::sock_v6::connect_udp6_locked(
                    sock, &mut local_port, ip, port, scope_id,
                )
            }
            (ConnectKind::Tcp, RemoteAddr::Inet { ip, port }) => {
                let entry = super::tcp_lifecycle::connect_tcp4_locked(
                    sock, &mut local_port, ip, port,
                )?;
                drop(local_port);
                if nonblock { return Err(NetError::Einprogress); }
                crate::sock_io::connect_wait_established(sock, &entry)
            }
            (ConnectKind::Tcp, RemoteAddr::Inet6 { ip, port, scope_id }) => {
                if let Some(ip) = crate::inet_tx::tcp6_mapped_destination(
                    ip,
                    sock.opts.ipv6_v6only.load(
                        core::sync::atomic::Ordering::Acquire,
                    ) != 0,
                )? {
                    let entry = super::tcp_lifecycle::connect_tcp4_mapped_locked(
                        sock, &mut local_port, ip, port,
                    )?;
                    drop(local_port);
                    if nonblock { return Err(NetError::Einprogress); }
                    return crate::sock_io::connect_wait_established(sock, &entry);
                }
                let _ = crate::sock_v6::scoped_iface(sock, ip, scope_id)?;
                sock.peer6_scope.store(scope_id, core::sync::atomic::Ordering::Release);
                let entry = super::tcp_lifecycle::connect_tcp6_locked(
                    sock, &mut local_port, ip, port,
                )?;
                drop(local_port);
                if nonblock { return Err(NetError::Einprogress); }
                crate::sock_io::connect_wait_established(sock, &entry)
            }
            (ConnectKind::Raw4(endpoint), RemoteAddr::Inet { ip, .. }) => {
                let iface = bound_iface(sock)?;
                if ip.is_broadcast() && sock.opts.broadcast.load(
                    core::sync::atomic::Ordering::Acquire,
                ) == 0 {
                    return Err(NetError::Eacces);
                }
                endpoint.connect_routed(ip, iface)
            }
            (ConnectKind::Raw6(endpoint), RemoteAddr::Inet6 { ip, scope_id, .. }) => {
                let iface = crate::sock_v6::scoped_iface(sock, ip, scope_id)?;
                endpoint.connect_routed(crate::raw6::Raw6Address::new(ip, scope_id), iface)
            }
            _ => Err(NetError::Eafnosupport),
        }
    }
}
