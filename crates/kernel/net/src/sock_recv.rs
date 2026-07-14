// Blocking socket receive work functions shared by recvfrom/recvmsg shims.

use alloc::sync::Arc;
use crate::netdev::NetError;
use crate::sock::{InetSocket, SockKind, AF_INET6};
use crate::sock_io::{monotonic_ns_safe, recvfrom_opts, Received, RecvOptions};

/// Blocking `recvfrom`/`recvmsg` receive core. # C: blocks until data/EOF/signal/timeout
pub fn recv_blocking(sock: &Arc<InetSocket>, max_len: usize, opts: RecvOptions, deadline_ns: u64) -> Result<Received, NetError> {
    loop {
        match recvfrom_opts(sock, max_len, opts) {
            Ok(r) => return Ok(r),
            Err(NetError::Eagain) => {}
            Err(e) => return Err(e),
        }
        if sched::live::deliverable_signals_self() != 0 { return Err(NetError::Eintr); }
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns { return Err(NetError::Eagain); }
        wait_recv_source(sock, deadline_ns);
    }
}

/// Park on the receive wait source matching the socket kind. # C: O(1)
fn wait_recv_source(sock: &InetSocket, deadline_ns: u64) {
    let kind = match &*sock.kind.lock() {
        SockKind::Unix(pair, end)        => WaitKind::Unix(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => WaitKind::UnixMsgPair(pair.clone(), *end),
        SockKind::UnixDgram(q)           => WaitKind::UnixDgram(q.clone()),
        SockKind::Packet { .. }          => WaitKind::Packet,
        SockKind::TcpConn(entry)         => WaitKind::Tcp(entry.clone()),
        SockKind::Udp                    => WaitKind::Udp,
        _                                => WaitKind::Yield,
    };
    match kind {
        WaitKind::Unix(pair, end) => {
            if let crate::unix_sock::stream::ArmStreamRead::Parked = pair.arm_stream_read(end, deadline_ns) {
                // SAFETY: pair armed current under its incoming-ring lock.
                unsafe { sched::live::schedule::schedule(); }
                pair.reader_waiters(end).remove_current();
            }
        }
        WaitKind::UnixMsgPair(pair, end) => {
            if let crate::unix_sock::msg_pair::ArmMsgRead::Parked = pair.arm_read(end, deadline_ns) {
                // SAFETY: pair armed current under its incoming-queue lock.
                unsafe { sched::live::schedule::schedule(); }
                pair.reader_waiters(end).remove_current();
            }
        }
        WaitKind::UnixDgram(q) => {
            let g = q.msgs.lock();
            if !g.is_empty() { return; }
            // SAFETY: process ctx; queue lock serializes datagram push before wake.
            unsafe { q.waiters.park_with_deadline(deadline_ns); }
            drop(g);
            // SAFETY: process ctx; current task is parked on the read wait list.
            unsafe { sched::live::schedule::schedule(); }
        }
        WaitKind::Packet => {
            // SAFETY: process ctx; packet RX delivery wakes sock.recv_waiters.
            unsafe { sock.recv_waiters.park_with_deadline(deadline_ns); sched::live::schedule::schedule(); }
        }
        WaitKind::Tcp(entry) => {
            // SAFETY: process ctx; TCP input/timeout wakes entry.rx_waiters.
            unsafe { entry.rx_waiters.park_with_deadline(deadline_ns); sched::live::schedule::schedule(); }
        }
        WaitKind::Udp => wait_udp(sock, deadline_ns),
        WaitKind::Yield => {
            // SAFETY: process ctx; no receive wait source exists for this kind.
            unsafe { sched::live::tick_yield(); }
        }
    }
}

enum WaitKind {
    Unix(Arc<crate::UnixPair>, crate::UnixEnd),
    UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
    UnixDgram(Arc<crate::UnixDgramQueue>),
    Packet,
    Tcp(Arc<crate::stack::TcpEntry>),
    Udp,
    Yield,
}

fn wait_udp(sock: &InetSocket, deadline_ns: u64) {
    let is_v6 = sock.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6;
    let v6_q = if is_v6 {
        sock.local_port.lock().and_then(|p| crate::sock::stack().udp6_queue_arc(p))
    } else { None };
    let udp_q = if !is_v6 {
        sock.local_port.lock().and_then(|p| crate::sock::stack().udp_queue_arc(p))
    } else { None };
    if let Some(q) = v6_q {
        let g = q.q.lock();
        if !g.is_empty() { return; }
        // SAFETY: process ctx; UDP6 receive delivery wakes this queue.
        unsafe { q.waiters.park_with_deadline(deadline_ns); }
        drop(g);
        // SAFETY: process ctx; current task is parked on the UDP6 read wait list.
        unsafe { sched::live::schedule::schedule(); }
    } else if let Some(q) = udp_q {
        let g = q.q.lock();
        if !g.is_empty() { return; }
        // SAFETY: process ctx; UDP receive delivery wakes this queue.
        unsafe { q.waiters.park_with_deadline(deadline_ns); }
        drop(g);
        // SAFETY: process ctx; current task is parked on the UDP read wait list.
        unsafe { sched::live::schedule::schedule(); }
    } else {
        // SAFETY: process ctx; unbound UDP has no packet queue, but blocking recv must sleep.
        unsafe { sock.recv_waiters.park_with_deadline(deadline_ns); sched::live::schedule::schedule(); }
    }
}
