use super::*;

/// Connect an AF_UNIX socket, waiting for listener backlog space when needed.
/// # C: O(wait retries)
pub(super) fn connect(sock: &Arc<InetSocket>, addr: crate::UnixAddr, nonblock: bool) -> Result<(), NetError> {
    {
        let kind = sock.kind.lock();
        if let SockKind::UnixDgram(q) = &*kind {
            if crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &addr)
                .dgram_lookup_addr(&addr).is_none() {
                return Err(NetError::Econnrefused);
            }
            q.set_peer(addr);
            return Ok(());
        }
        match &*kind {
            SockKind::Unix(_, _) => return Err(NetError::Eisconn),
            SockKind::UnixListener(_) => return Err(NetError::Einval),
            SockKind::UnixUnbound(_, _) => {}
            _ => return Err(NetError::Einval),
        }
    }
    let registry = crate::net_ns::unix_registry_for_addr_in(&sock.net_namespace, &addr);
    let candidate = match &*sock.kind.lock() {
        SockKind::UnixUnbound(pair, end) => {
            if *end != crate::UnixEnd::B { return Err(NetError::Einval); }
            pair.clone()
        }
        _ => return Err(NetError::Einval),
    };
    if let Some(c) = sched::live::current() {
        use core::sync::atomic::Ordering;
        candidate.set_end_cred(crate::UnixEnd::B, c.visible_pid(),
            c.creds.euid.load(Ordering::Relaxed), c.creds.egid.load(Ordering::Relaxed));
    }
    let timeout = sock.opts.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
    let deadline_ns = compute_deadline_ns(timeout);
    loop {
        let missing = if addr.is_pathname() { NetError::Enoent } else { NetError::Econnrefused };
        let listener = registry.lookup_listener_addr(&addr).ok_or(missing)?;
        candidate.set_bind_path(listener.path.clone());
        match listener.connect_socket(candidate.clone(), sock) {
            Ok(()) => return Ok(()),
            Err(NetError::Eagain) if nonblock => return Err(NetError::Eagain),
            Err(NetError::Eagain) => {
                // Linux `unix_stream_connect` (`net/unix/af_unix.c:1705`):
                // `sock_intr_errno(timeo)` off `sock_sndtimeo`.
                if sched::live::deliverable_signals_self() != 0 {
                    return Err(crate::sock_intr::sock_intr_net(deadline_ns));
                }
                if deadline_ns != 0 && crate::sock_io::monotonic_ns_safe() >= deadline_ns {
                    return Err(NetError::Eagain);
                }
                if listener.arm_socket_connect_wait(sock, deadline_ns) {
                    // SAFETY: arm_connect_wait registered current under the
                    // listener state lock; accept, relisten, and close wake it.
                    unsafe { sched::live::schedule::schedule(); }
                    sock.connect_waiters.remove_current();
                    listener.unregister_socket_connect_wait(sock);
                }
            }
            Err(e) => return Err(e),
        }
    }
}
