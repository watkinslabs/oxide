use super::{InetSocket, NetError, SockKind, drain_loopback, stack};
pub use crate::uapi::ShutdownHow;

/// Apply shutdown through the protocol owner rather than the ABI shim.
/// # C: backend-dependent
pub fn shutdown(sock: &InetSocket, how: ShutdownHow) -> Result<(), NetError> {
    check_shutdown_admission(sock)?;
    shutdown_admitted(sock, how)
}

/// Apply a raw Linux `shutdown(2)` direction after owner-level security
/// admission. This preserves Linux's security-before-protocol-validation
/// ordering for invalid `how` values. # C: backend-dependent
pub fn shutdown_raw(sock: &InetSocket, how: u32) -> Result<(), NetError> {
    check_shutdown_admission(sock)?;
    // Linux AF_PACKET selects `sock_no_shutdown` before that helper has any
    // reason to interpret `how`, so even an invalid direction is unsupported.
    if matches!(&*sock.kind.lock(), SockKind::Packet { .. }) {
        return Err(NetError::Eopnotsupp);
    }
    let how = ShutdownHow::try_from(how).map_err(|_| NetError::Einval)?;
    shutdown_admitted(sock, how)
}

fn check_shutdown_admission(sock: &InetSocket) -> Result<(), NetError> {
    let context = security::network::Context {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        socket_type: 0, protocol: 0,
        operation: security::network::Operation::Shutdown,
    };
    if matches!(security::network::evaluate(context), security::network::Verdict::Deny) {
        return Err(NetError::Eacces);
    }
    Ok(())
}

fn shutdown_admitted(sock: &InetSocket, how: ShutdownHow) -> Result<(), NetError> {
    use core::sync::atomic::Ordering::Release;
    enum Target {
        Unix(alloc::sync::Arc<crate::UnixPair>, crate::UnixEnd),
        Msg(alloc::sync::Arc<crate::UnixMsgPair>, crate::UnixEnd),
        Tcp(alloc::sync::Arc<crate::stack::TcpEntry>),
        TcpListener(alloc::sync::Arc<crate::stack::TcpListenEntry>),
        UnixDgram(alloc::sync::Arc<crate::UnixDgramQueue>),
        UnixListener(alloc::sync::Arc<crate::UnixListener>),
        TcpListener(alloc::sync::Arc<crate::stack::TcpListenEntry>),
        UnixUnconnected,
        Udp,
        Raw4(alloc::sync::Arc<crate::raw4::Raw4Endpoint>),
        Raw6(alloc::sync::Arc<crate::raw6::Raw6Endpoint>),
        Packet,
        Unconnected,
    }
    let target = match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Target::Unix(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        SockKind::TcpConn(entry) => Target::Tcp(entry.clone()),
        SockKind::TcpListener(listener) => Target::TcpListener(listener.clone()),
        SockKind::Udp => Target::Udp,
        SockKind::Raw4(endpoint) => Target::Raw4(endpoint.clone()),
        SockKind::Raw6(endpoint) => Target::Raw6(endpoint.clone()),
        SockKind::Packet { .. } => Target::Packet,
        SockKind::UnixDgram(q) => Target::UnixDgram(q.clone()),
        SockKind::UnixListener(listener) => Target::UnixListener(listener.clone()),
        SockKind::TcpListener(listener) => Target::TcpListener(listener.clone()),
        SockKind::UnixUnbound(_, _) => Target::UnixUnconnected,
        _ => Target::Unconnected,
    };
    match target {
        Target::Unix(pair, end) => {
            if how.read() { pair.shutdown_reader(end); }
            if how.write() { pair.close_writer(end); }
        }
        Target::Msg(pair, end) => {
            if how.read() { pair.shutdown_reader(end); }
            if how.write() { pair.close_writer(end); }
        }
        Target::Tcp(entry) => {
            if how.read() { sock.read_shut.store(true, Release); }
            if how.write() { sock.write_shut.store(true, Release); }
            let active_open = stack().tcp_shutdown(&entry, how.write())?;
            if active_open {
                *sock.kind.lock() = SockKind::TcpInit;
                *sock.peer.lock() = None;
                *sock.peer6.lock() = None;
                sock.peer6_scope.store(0, Release);
                sock.read_shut.store(false, Release);
                sock.write_shut.store(false, Release);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
                sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
                return Ok(());
            }
            if how.read() {
                let c = entry.conn.lock();
                drop(c);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
            if how.write() {
                let conn = entry.conn.lock();
                drop(conn);
                drain_loopback();
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
        }
        Target::TcpListener(listener) => {
            // Linux inet_shutdown leaves a listener intact for SHUT_WR,
            // but SHUT_RD/SHUT_RDWR runs tcp_disconnect: stop accepting,
            // destroy unaccepted children, and return the socket to TCP_CLOSE.
            if !how.read() { return Ok(()); }
            stack().tcp_unlisten_entry(&listener);
            *sock.kind.lock() = SockKind::TcpInit;
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
        }
        Target::UnixDgram(q) => {
            if how.read() { q.shutdown_reader(); }
            if how.write() { sock.write_shut.store(true, Release); }
            #[cfg(target_os = "oxide-kernel")]
            q.waiters.wake_all();
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
        }
        Target::UnixListener(listener) => {
            listener.shutdown(how);
        }
        Target::TcpListener(listener) => {
            if how.read() {
                stack().tcp_unlisten_entry(&listener);
                *sock.kind.lock() = SockKind::TcpInit;
            } else if how.write() {
                sock.write_shut.store(true, Release);
            }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
        }
        Target::UnixUnconnected => {
            if how.read() { sock.read_shut.store(true, Release); }
            if how.write() { sock.write_shut.store(true, Release); }
            #[cfg(target_os = "oxide-kernel")]
            {
                sock.recv_waiters.wake_all();
                sock.connect_waiters.wake_all();
            }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
        }
        Target::Udp => {
            let connected_v4 = sock.peer.lock().is_some();
            let connected_v6 = sock.peer6.lock().is_some();
            if how.read() {
                let mut shut_queue = false;
                if let Some(q) = sock.udp4.lock().as_ref().cloned() {
                    q.shutdown_read(&sock.read_shut);
                    #[cfg(target_os = "oxide-kernel")]
                    q.waiters.wake_all();
                    shut_queue = true;
                }
                if let Some(q) = sock.udp6.lock().as_ref().cloned() {
                    q.shutdown_read(&sock.read_shut);
                    #[cfg(target_os = "oxide-kernel")]
                    q.waiters.wake_all();
                    shut_queue = true;
                }
                if !shut_queue {
                    let kind = sock.kind.lock();
                    sock.read_shut.store(true, Release);
                    drop(kind);
                    #[cfg(target_os = "oxide-kernel")]
                    sock.recv_waiters.wake_all();
                }
            }
            if how.write() { sock.write_shut.store(true, Release); }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
            if !connected_v4 && !connected_v6 { return Err(NetError::Enotconn); }
        }
        Target::Raw4(endpoint) => {
            let connected = endpoint.snapshot().remote.is_some();
            if how.read() { endpoint.shutdown_read(&sock.read_shut); }
            if how.write() { sock.write_shut.store(true, Release); }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
            if !connected { return Err(NetError::Enotconn); }
        }
        Target::Raw6(endpoint) => {
            let connected = endpoint.peer().is_some();
            if how.read() { endpoint.shutdown_read(&sock.read_shut); }
            if how.write() { sock.write_shut.store(true, Release); }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
            if !connected { return Err(NetError::Enotconn); }
        }
        // Linux AF_PACKET installs `sock_no_shutdown`; security admission
        // has already occurred in this owner before the unsupported errno.
        Target::Packet => return Err(NetError::Eopnotsupp),
        Target::Unconnected => {
            if how.read() { sock.read_shut.store(true, Release); }
            if how.write() { sock.write_shut.store(true, Release); }
            #[cfg(target_os = "oxide-kernel")]
            {
                sock.recv_waiters.wake_all();
                sock.connect_waiters.wake_all();
            }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
            return Err(NetError::Enotconn);
        }
    }
    Ok(())
}
