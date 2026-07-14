use super::*;

/// Connect an AF_UNIX socket, waiting for listener backlog space when needed.
/// # C: O(wait retries)
pub(super) fn connect(sock: &Arc<InetSocket>, addr: crate::UnixAddr, nonblock: bool) -> Result<(), NetError> {
    if let SockKind::UnixDgram(q) = &*sock.kind.lock() {
        if crate::net_ns::unix_registry_for_addr(&addr).dgram_lookup_addr(&addr).is_none() {
            return Err(NetError::Econnrefused);
        }
        q.set_peer(addr);
        return Ok(());
    }
    match &*sock.kind.lock() {
        SockKind::Unix(_, _) => return Err(NetError::Eisconn),
        SockKind::UnixListener(_) => return Err(NetError::Einval),
        _ => {}
    }
    let registry = crate::net_ns::unix_registry_for_addr(&addr);
    let timeout = sock.opts.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
    let deadline_ns = compute_deadline_ns(timeout);
    let pair = loop {
        match registry.connect_addr(&addr) {
            Ok(pair) => break pair,
            Err(crate::UnixConnectError::Refused) => return Err(NetError::Econnrefused),
            Err(crate::UnixConnectError::Full) if nonblock => return Err(NetError::Eagain),
            Err(crate::UnixConnectError::Full) => {
                if sched::live::deliverable_signals_self() != 0 { return Err(NetError::Eintr); }
                if deadline_ns != 0 && crate::sock_io::monotonic_ns_safe() >= deadline_ns {
                    return Err(NetError::Eagain);
                }
                let Some(listener) = registry.lookup_listener_addr(&addr) else { continue; };
                if listener.arm_connect_wait(deadline_ns) {
                    // SAFETY: arm_connect_wait registered current under the
                    // listener state lock; accept, relisten, and close wake it.
                    unsafe { sched::live::schedule::schedule(); }
                }
            }
        }
    };
    pair.register_end_subs(crate::UnixEnd::B, &sock.poll_subs);
    if let Some(c) = sched::live::current() {
        use core::sync::atomic::Ordering;
        pair.set_end_cred(crate::UnixEnd::B, c.visible_pid(),
            c.creds.euid.load(Ordering::Relaxed), c.creds.egid.load(Ordering::Relaxed));
    }
    *sock.kind.lock() = SockKind::Unix(pair, crate::UnixEnd::B);
    Ok(())
}
