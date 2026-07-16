use alloc::{sync::Arc, vec::Vec};

use super::*;

/// Outcome of a transactional VSOCK stream receive. # C: O(1)
pub enum RecvWith<R> { Data(R), Eof, Retry }

/// Linux AF_VSOCK default connect timeout. # C: O(1)
pub const VSOCK_CONNECT_TIMEOUT_NS: u64 = 2_000_000_000;

/// Send the server response only while the child remains live. Holding `st`
/// orders response transmission before any listener-close terminal frames.
/// # C: O(1)
pub(super) fn send_accept_response(c: &VsockConn) -> bool {
    let _emit = lock_emission(c);
    let tx = c.tx.lock();
    let st = c.st.lock();
    if *st == VsockState::Closed { return false; }
    let resp = c.make_hdr_with_credit(&tx.credit, VIRTIO_VSOCK_OP_RESPONSE, 0, 0);
    drop(st);
    drop(tx);
    tx_for(c.owner, &resp, &[])
}

fn finish_connect(c: &Arc<VsockConn>, error: Option<crate::NetError>) -> bool {
    cancel_connect_timeout(c);
    {
        let mut tx = c.tx.lock();
        let mut st = c.st.lock();
        if *st != VsockState::Connecting { return false; }
        tx.local_shut = true;
        *c.connect_error.lock() = error;
        *st = VsockState::Closed;
    }
    TABLE.remove_conn(c);
    let owner = c.connect_owner.lock().take().and_then(|owner| owner.upgrade());
    if let Some(owner) = owner { owner.complete_connect(c, error); }
    c.notify_poll(if error.is_some() { vfs::POLL_ERR | vfs::POLL_OUT } else { vfs::POLL_OUT });
    #[cfg(target_os = "oxide-kernel")]
    c.waiters.wake_all();
    true
}

/// Complete one outbound connect failure through its exact socket owner. # C: O(N conns)
pub fn fail_connect(c: &Arc<VsockConn>, error: crate::NetError) -> bool {
    finish_connect(c, Some(error))
}

/// Cancel one outbound connect without publishing `SO_ERROR`. # C: O(N conns)
pub fn cancel_connect(c: &Arc<VsockConn>) -> bool { finish_connect(c, None) }

/// Preserve one Arc until the nonblocking connect deadline fires. # C: O(1)
pub fn arm_connect_timeout(c: &Arc<VsockConn>, deadline_ns: u64) {
    cancel_connect_timeout(c);
    let token = Arc::new(ConnectTimerToken {
        conn: c.clone(), cancelled: core::sync::atomic::AtomicBool::new(false),
    });
    let raw = Arc::into_raw(token.clone()) as usize;
    let mut registration = c.connect_timer.lock();
    let id = timer::register_oneshot(deadline_ns, raw, connect_timeout);
    *registration = Some(ConnectTimer { id, raw, token });
}

/// Cancel the exact connection's pending timeout and release its timer Arc. # C: O(N timers)
pub fn cancel_connect_timeout(c: &VsockConn) {
    let registration = {
        let mut timer = c.connect_timer.lock();
        let Some(registration) = timer.take() else { return; };
        registration.token.cancelled.store(true, core::sync::atomic::Ordering::Release);
        registration
    };
    if timer::unregister_oneshot(registration.id) {
        // SAFETY: successful unregister transfers the raw timer Arc clone back to this path.
        unsafe { drop(Arc::from_raw(registration.raw as *const ConnectTimerToken)); }
    }
}

fn connect_timeout(arg: usize) {
    // SAFETY: timer invokes once with the raw Arc clone allocated by arm_connect_timeout.
    let token = unsafe { Arc::from_raw(arg as *const ConnectTimerToken) };
    let c = token.conn.clone();
    let claimed = {
        let mut timer = c.connect_timer.lock();
        if matches!(&*timer, Some(current) if current.raw == arg) {
            *timer = None;
            true
        } else { false }
    };
    if claimed && !token.cancelled.load(core::sync::atomic::Ordering::Acquire) {
        let _ = fail_connect(&c, crate::NetError::Etimedout);
    }
}

/// Build an unpublished client connection with its exact lifecycle owner. # C: O(1)
pub fn prepare_connect_owned(owner: Option<VsockOwner>, local_port: Option<u32>, peer_cid: u64,
    peer_port: u32, connect_owner: Option<alloc::sync::Weak<crate::vsock_socket::VsockSocket>>)
    -> Result<Arc<VsockConn>, crate::NetError>
{
    let Some((owner, local_cid)) = endpoint_by_owner(owner) else {
        return Err(crate::NetError::Enetunreach);
    };
    let local_port = local_port.unwrap_or_else(|| TABLE.alloc_port());
    let bpf_filter = connect_owner.as_ref().and_then(alloc::sync::Weak::upgrade)
        .map(|socket| socket.bpf_filter.clone())
        .unwrap_or_else(|| Arc::new(crate::bpf_filter::SocketFilter::new()));
    let c = Arc::new(VsockConn::new_with_filter(owner, local_cid, local_port, peer_cid,
        peer_port, VsockState::Connecting, bpf_filter));
    *c.connect_owner.lock() = connect_owner;
    Ok(c)
}

/// Expose and transmit one already socket-published connection attempt. # C: O(N conns)
pub fn start_connect(c: &Arc<VsockConn>) -> Result<(), crate::NetError> {
    {
        let st = c.st.lock();
        if *st != VsockState::Connecting { return Err(crate::NetError::Enotconn); }
        if !TABLE.insert(c.clone()) {
            drop(st);
            let _ = cancel_connect(c);
            return Err(crate::NetError::Eaddrinuse);
        }
    }
    let req = c.make_hdr(VIRTIO_VSOCK_OP_REQUEST, 0, 0);
    if !tx_for(c.owner, &req, &[]) {
        if cancel_connect(c) { return Err(crate::NetError::Enetunreach); }
        return match *c.st.lock() {
            VsockState::Connected => Ok(()),
            VsockState::Closed if c.connect_error.lock().is_some() => Ok(()),
            VsockState::Connecting | VsockState::RcvShutdown | VsockState::Closed =>
                Err(crate::NetError::Enotconn),
        };
    }
    Ok(())
}

/// Prepare and start a client without a socket publication boundary. # C: O(N conns)
pub fn connect_from_start_owned(owner: Option<VsockOwner>, local_port: Option<u32>, peer_cid: u64,
    peer_port: u32, connect_owner: Option<alloc::sync::Weak<crate::vsock_socket::VsockSocket>>)
    -> Result<Arc<VsockConn>, crate::NetError>
{
    let c = prepare_connect_owned(owner, local_port, peer_cid, peer_port, connect_owner)?;
    start_connect(&c)?;
    Ok(c)
}

/// Start a client connect without a socket lifecycle owner. # C: O(1)
pub fn connect_from_start(owner: Option<VsockOwner>, local_port: Option<u32>, peer_cid: u64,
    peer_port: u32) -> Result<Arc<VsockConn>, crate::NetError>
{
    connect_from_start_owned(owner, local_port, peer_cid, peer_port, None)
}

/// Wait interruptibly for exact connect completion or one absolute deadline. # C: O(RTT)
pub fn connect_wait(c: &Arc<VsockConn>) -> Result<(), crate::NetError> {
    #[cfg(not(target_os = "oxide-kernel"))]
    match *c.st.lock() {
        VsockState::Connected => return Ok(()),
        VsockState::Closed => return Err(c.connect_error.lock().unwrap_or(crate::NetError::Enotconn)),
        VsockState::Connecting | VsockState::RcvShutdown => {}
    }
    #[cfg(target_os = "oxide-kernel")]
    {
        let deadline = crate::sock_io::monotonic_ns_safe().saturating_add(VSOCK_CONNECT_TIMEOUT_NS);
        loop {
            let _ = poll_rx_for(c.owner);
            match *c.st.lock() {
                VsockState::Connected => return Ok(()),
                VsockState::Closed =>
                    return Err(c.connect_error.lock().unwrap_or(crate::NetError::Enotconn)),
                VsockState::Connecting | VsockState::RcvShutdown => {}
            }
            if sched::live::deliverable_signals_self() != 0 {
                let _ = cancel_connect(c);
                return Err(crate::NetError::Eintr);
            }
            if crate::sock_io::monotonic_ns_safe() >= deadline {
                let _ = fail_connect(c, crate::NetError::Etimedout);
                return Err(c.connect_error.lock().unwrap_or(crate::NetError::Etimedout));
            }
            let st = c.st.lock();
            if *st != VsockState::Connecting { continue; }
            // SAFETY: process context; state lock serializes completion with park publication.
            unsafe { c.waiters.park_interruptible_with_deadline(deadline); }
            drop(st);
            // SAFETY: current task was parked on this connection wait list by the call above.
            unsafe { sched::live::schedule::schedule(); }
            c.waiters.remove_current();
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    Ok(())
}

/// Client connect: start, wait for OP_RESPONSE or exact error, return conn. # C: O(RTT)
pub fn connect_from(owner: Option<VsockOwner>, local_port: Option<u32>, peer_cid: u64,
    peer_port: u32) -> Result<Arc<VsockConn>, crate::NetError>
{
    let c = connect_from_start(owner, local_port, peer_cid, peer_port)?;
    connect_wait(&c)?;
    Ok(c)
}

/// Close under the OP_RW gate, emit terminal frames once, and remove this Arc. # C: O(N)
pub fn close(c: &VsockConn) {
    cancel_connect_timeout(c);
    let emit = lock_emission(c);
    let terminal = {
        let mut tx = c.tx.lock();
        let mut st = c.st.lock();
        if *st != VsockState::Closed {
            let send = matches!(*st, VsockState::Connected | VsockState::RcvShutdown);
            tx.local_shut = true;
            *st = VsockState::Closed;
            if send {
                let sh = c.make_hdr_with_credit(&tx.credit, VIRTIO_VSOCK_OP_SHUTDOWN, 0,
                    VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND);
                let rst = c.make_hdr_with_credit(&tx.credit, VIRTIO_VSOCK_OP_RST, 0, 0);
                Some((sh, rst))
            } else { None }
        } else { None }
    };
    if let Some((sh, rst)) = terminal {
        let _ = tx_for(c.owner, &sh, &[]);
        let _ = tx_for(c.owner, &rst, &[]);
    }
    TABLE.remove_conn(c);
    drop(emit);
    c.notify_poll(vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
    #[cfg(target_os = "oxide-kernel")]
    c.waiters.wake_all();
}

/// Copy one RX prefix under its queue lock and consume only on callback success. # C: O(max)
pub fn recv_with<R, E>(c: &VsockConn, max: usize, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
    -> Result<RecvWith<R>, E>
{ recv_with_offset(c, max, peek, 0, copy) }

/// Copy an RX range after a non-consuming logical offset. # C: O(offset + max)
pub fn recv_with_offset<R, E>(c: &VsockConn, max: usize, peek: bool, offset: usize, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
    -> Result<RecvWith<R>, E>
{
    let mut rx = c.rx.lock();
    if offset >= rx.len() {
        drop(rx);
        let st = c.st.lock();
        rx = c.rx.lock();
        if offset >= rx.len() {
            let eof = matches!(*st, VsockState::RcvShutdown | VsockState::Closed);
            return Ok(if eof { RecvWith::Eof } else { RecvWith::Retry });
        }
        drop(st);
    }
    let take = core::cmp::min(max, rx.len() - offset);
    let bytes: Vec<u8> = rx.iter().skip(offset).take(take).copied().collect();
    let (copied, commit) = copy(&bytes)?;
    if peek { return Ok(RecvWith::Data(copied)); }
    let commit = core::cmp::min(commit, take);
    for _ in 0..commit { rx.pop_front(); }
    drop(rx);
    if commit != 0 {
        let mut tx = c.tx.lock();
        tx.credit.fwd_cnt = tx.credit.fwd_cnt.wrapping_add(commit as u32);
        drop(tx);
        send_credit_update(c);
    }
    Ok(RecvWith::Data(copied))
}
