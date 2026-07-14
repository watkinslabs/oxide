use super::{InetSocket, NetError, SockKind, drain_loopback, stack};
pub use crate::uapi::ShutdownHow;

impl ShutdownHow {
    fn read(self) -> bool { matches!(self, Self::Read | Self::ReadWrite) }
    fn write(self) -> bool { matches!(self, Self::Write | Self::ReadWrite) }
}

/// Apply shutdown through the protocol owner rather than the ABI shim.
/// # C: backend-dependent
pub fn shutdown(sock: &InetSocket, how: ShutdownHow) -> Result<(), NetError> {
    use core::sync::atomic::Ordering::Release;
    enum Target {
        Unix(alloc::sync::Arc<crate::UnixPair>, crate::UnixEnd),
        Msg(alloc::sync::Arc<crate::UnixMsgPair>, crate::UnixEnd),
        Tcp(alloc::sync::Arc<crate::stack::TcpEntry>),
        UnixDgram(alloc::sync::Arc<crate::UnixDgramQueue>),
        Udp,
        Unconnected,
    }
    let target = match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => Target::Unix(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => Target::Msg(pair.clone(), *end),
        SockKind::TcpConn(entry) => Target::Tcp(entry.clone()),
        SockKind::Udp => Target::Udp,
        SockKind::UnixDgram(q) => Target::UnixDgram(q.clone()),
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
            if how.read() {
                sock.read_shut.store(true, Release);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
            if how.write() {
                sock.write_shut.store(true, Release);
                let _ = stack().tcp_close(&entry);
                drain_loopback();
            }
        }
        Target::UnixDgram(q) => {
            if q.peer().is_none() { return Err(NetError::Enotconn); }
            if how.read() { q.shutdown_reader(); }
            if how.write() { sock.write_shut.store(true, Release); }
            #[cfg(target_os = "oxide-kernel")]
            q.waiters.wake_all();
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
        }
        Target::Udp => {
            let connected_v4 = sock.peer.lock().is_some();
            let connected_v6 = sock.peer6.lock().is_some();
            if !connected_v4 && !connected_v6 { return Err(NetError::Enotconn); }
            if how.read() { sock.read_shut.store(true, Release); }
            if how.write() { sock.write_shut.store(true, Release); }
            #[cfg(target_os = "oxide-kernel")]
            {
                let v6 = sock.family.load(core::sync::atomic::Ordering::Acquire) == super::AF_INET6;
                if let Some(port) = *sock.local_port.lock() {
                    if v6 {
                        if let Some(q) = stack().udp6_queue_arc(port) { q.waiters.wake_all(); }
                    } else if let Some(q) = stack().udp_queue_arc(port) { q.waiters.wake_all(); }
                }
                sock.recv_waiters.wake_all();
            }
            sock.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
        }
        Target::Unconnected => return Err(NetError::Enotconn),
    }
    Ok(())
}
