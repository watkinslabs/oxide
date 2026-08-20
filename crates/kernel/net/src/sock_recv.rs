// Blocking socket receive work functions shared by recvfrom/recvmsg shims.

use alloc::sync::Arc;
use crate::netdev::NetError;
use crate::sock::{InetSocket, SockKind};
use crate::sock_io::{monotonic_ns_safe, recvfrom_opts, Received, RecvOptions};

/// Blocking `recvfrom`/`recvmsg` receive core. # C: blocks until data/EOF/signal/timeout
pub fn recv_blocking(sock: &Arc<InetSocket>, max_len: usize, opts: RecvOptions, deadline_ns: u64) -> Result<Received, NetError> {
    let unix_generation = unix_shutdown_generation(sock);
    loop {
        match recvfrom_opts(sock, max_len, opts) {
            Ok(r) => return Ok(r),
            Err(NetError::Eagain) => {}
            Err(e) => return Err(e),
        }
        // Linux `__skb_wait_for_more_packets`:
        // `sock_intr_errno(*timeo)` — ERESTARTSYS with no SO_RCVTIMEO,
        // EINTR with one, because a timed wait cannot carry its remaining
        // time across a restart.
        if crate::sock_intr::signal_pending_self() {
            return Err(crate::sock_intr::sock_intr_net(deadline_ns));
        }
        if deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns { return Err(NetError::Eagain); }
        if wait_recv_source_after_generation(sock, deadline_ns, 0, unix_generation, false) {
            return Ok(empty_received());
        }
    }
}

fn empty_received() -> Received {
    Received { payload: alloc::vec::Vec::new(), full_len: 0, peer: None, peer6: None,
        ..Default::default() }
}

/// Park on the receive wait source matching the socket kind. # C: O(1)
pub fn wait_recv_source(sock: &InetSocket, deadline_ns: u64) -> bool {
    wait_recv_source_after(sock, deadline_ns, 0)
}

/// Park until receive data exists beyond a non-consuming stream offset. # C: O(1)
pub fn wait_recv_source_after(sock: &InetSocket, deadline_ns: u64, offset: usize) -> bool {
    wait_recv_source_after_generation(sock, deadline_ns, offset, None, false)
}

/// Park until TCP data or an out-of-band byte exists. # C: O(1)
pub fn wait_recv_source_after_urgent(sock: &InetSocket, deadline_ns: u64, offset: usize) -> bool {
    wait_recv_source_after_generation(sock, deadline_ns, offset, None, true)
}

/// Snapshot one AF_UNIX datagram receive-shutdown generation. # C: O(1)
pub fn unix_shutdown_generation(sock: &InetSocket) -> Option<u64> {
    match &*sock.kind.lock() {
        SockKind::UnixMsgPair(pair, end) if pair.kind == crate::UnixMsgKind::Datagram =>
            Some(pair.shutdown_generation(*end)),
        SockKind::UnixDgram(q) => Some(q.shutdown_generation()),
        _ => None,
    }
}

/// Wait using the shutdown generation captured before the first receive attempt. # C: O(1)
pub fn wait_unix_recv_source_after(sock: &InetSocket, deadline_ns: u64, offset: usize,
    generation: Option<u64>) -> bool
{
    wait_recv_source_after_generation(sock, deadline_ns, offset, generation, false)
}

fn wait_recv_source_after_generation(sock: &InetSocket, deadline_ns: u64, offset: usize,
    generation: Option<u64>, include_urgent: bool) -> bool
{
    let kind = match &*sock.kind.lock() {
        SockKind::Unix(pair, end)        => WaitKind::Unix(pair.clone(), *end),
        SockKind::UnixMsgPair(pair, end) => WaitKind::UnixMsgPair(pair.clone(), *end),
        SockKind::UnixDgram(q)           => WaitKind::UnixDgram(q.clone()),
        SockKind::Packet { .. }          => WaitKind::Packet,
        SockKind::Raw4(endpoint)          => WaitKind::Raw4(endpoint.clone()),
        SockKind::Raw6(endpoint)          => WaitKind::Raw6(endpoint.clone()),
        SockKind::TcpConn(entry)         => WaitKind::Tcp(entry.clone()),
        SockKind::Udp                    => WaitKind::Udp,
        _                                => WaitKind::Yield,
    };
    match kind {
        WaitKind::Unix(pair, end) => {
            if let crate::unix_sock::stream::ArmStreamRead::Parked = pair.arm_stream_read_after(end, offset, deadline_ns) {
                // SAFETY: pair armed current under its incoming-ring lock.
                unsafe { pair.reader_waiters(end).wait(); }
                pair.reader_waiters(end).remove_current();
            }
            false
        }
        WaitKind::UnixMsgPair(pair, end) => {
            let generation = generation.unwrap_or_else(|| pair.shutdown_generation(end));
            match pair.arm_read_after_generation(end, generation, deadline_ns) {
                crate::unix_sock::msg_pair::ArmMsgReadAfter::DatagramShutdown => return true,
                crate::unix_sock::msg_pair::ArmMsgReadAfter::Parked => {
                    // SAFETY: pair armed current under its incoming-queue lock.
                    unsafe { pair.reader_waiters(end).wait(); }
                    pair.reader_waiters(end).remove_current();
                }
                _ => {}
            }
            false
        }
        WaitKind::UnixDgram(q) => {
            let generation = generation.unwrap_or_else(|| q.shutdown_generation());
            match q.arm_read(generation, deadline_ns) {
                crate::unix_sock::dgram::ArmDgramRead::Shutdown => true,
                crate::unix_sock::dgram::ArmDgramRead::Parked => {
                    // SAFETY: queue armed current under its message lock.
                    unsafe { q.waiters.wait(); }
                    q.waiters.remove_current();
                    false
                }
                crate::unix_sock::dgram::ArmDgramRead::Retry => false,
            }
        }
        WaitKind::Packet => { wait_packet(sock, deadline_ns); false }
        WaitKind::Raw4(endpoint) => {
            if endpoint.arm_recv_wait(&sock.read_shut, deadline_ns) {
                // SAFETY: endpoint armed current while receive admission was locked.
                unsafe { endpoint.waiters.wait(); }
                endpoint.waiters.remove_current();
            }
            false
        }
        WaitKind::Raw6(endpoint) => {
            if endpoint.arm_recv_wait(&sock.read_shut, deadline_ns) {
                // SAFETY: endpoint armed current while receive admission was locked.
                unsafe { endpoint.waiters.wait(); }
                endpoint.waiters.remove_current();
            }
            false
        }
        WaitKind::Tcp(entry) => {
            if crate::sock_io::arm_tcp_read_after_mode(sock, &entry, offset, deadline_ns, include_urgent) {
                // SAFETY: arm_tcp_read published current under entry.conn.
                unsafe { entry.poll_subs.sleep().wait(); }
                entry.poll_subs.sleep().remove_current();
            }
            false
        }
        WaitKind::Udp => { wait_udp(sock, deadline_ns); false }
        WaitKind::Yield => {
            // SAFETY: process ctx; no receive wait source exists for this kind.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::tick_yield(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            std::thread::yield_now();
            false
        }
    }
}

/// Test an absolute receive deadline against the monotonic clock. # C: O(1)
pub fn deadline_expired(deadline_ns: u64) -> bool {
    deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns
}

fn wait_packet(sock: &InetSocket, deadline_ns: u64) {
    let kind = sock.kind.lock();
    let SockKind::Packet { rx, .. } = &*kind else { return; };
    let q = rx.lock();
    if !q.is_empty() { return; }
    // SAFETY: kind+RX locks serialize packet delivery before its wake.
    unsafe { sock.recv_waiters.prepare_to_wait_interruptible_with_deadline(deadline_ns); }
    drop(q);
    drop(kind);
    // SAFETY: current task is parked on the packet receive wait list.
    unsafe { sock.recv_waiters.wait(); }
    sock.recv_waiters.remove_current();
}

enum WaitKind {
    Unix(Arc<crate::UnixPair>, crate::UnixEnd),
    UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
    UnixDgram(Arc<crate::UnixDgramQueue>),
    Packet,
    Raw4(Arc<crate::raw4::Raw4Endpoint>),
    Raw6(Arc<crate::raw6::Raw6Endpoint>),
    Tcp(Arc<crate::stack::TcpEntry>),
    Udp,
    Yield,
}

fn wait_udp(sock: &InetSocket, deadline_ns: u64) {
    let v6_q = sock.udp6.lock().as_ref().cloned();
    let udp_q = sock.udp4.lock().as_ref().cloned();
    if let Some(q) = v6_q {
        if !q.park_if_idle(&sock.read_shut, deadline_ns) { return; }
        // SAFETY: process ctx; current task is parked on the UDP6 read wait list.
        unsafe { q.waiters.wait(); }
        q.waiters.remove_current();
    } else if let Some(q) = udp_q {
        if !q.park_if_idle(&sock.read_shut, deadline_ns) { return; }
        // SAFETY: process ctx; current task is parked on the UDP read wait list.
        unsafe { q.waiters.wait(); }
        q.waiters.remove_current();
    } else {
        let kind = sock.kind.lock();
        if sock.has_pending_recv_error()
            || sock.read_shut.load(core::sync::atomic::Ordering::Acquire) { return; }
        // SAFETY: process ctx; kind lock serializes unbound shutdown publication.
        unsafe { sock.recv_waiters.prepare_to_wait_interruptible_with_deadline(deadline_ns); }
        drop(kind);
        // SAFETY: current task is parked on the fallback receive wait list.
        unsafe { sock.recv_waiters.wait(); }
        sock.recv_waiters.remove_current();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;
    use core::time::Duration;

    fn wait_until(mut ready: impl FnMut() -> bool) {
        let until = std::time::Instant::now() + Duration::from_secs(1);
        while !ready() {
            assert!(std::time::Instant::now() < until, "receive path did not publish its wait");
            std::thread::yield_now();
        }
    }

    #[test]
    fn blocking_udp_receive_parks_on_the_endpoint_queue_and_wakes_on_delivery() {
        let sock = Arc::new(InetSocket::new_udp());
        let endpoint = Arc::new(crate::UdpRxQueue::new_with_error(
            crate::Ipv4Addr::ANY, 41_235, sock.error.clone()));
        *sock.udp4.lock() = Some(endpoint.clone());
        let receiver = sock.clone();
        let thread = std::thread::spawn(move || recv_blocking(&receiver, 8,
            RecvOptions::default(), crate::sock_clock::monotonic_ns_safe() + 1_000_000_000));

        wait_until(|| endpoint.waiters.has_waiters());
        let wake = std::time::Instant::now();
        assert!(endpoint.enqueue(crate::stack::UdpDatagram::plain(
            crate::Ipv4Addr::LOOPBACK, 53, crate::Ipv4Addr::LOOPBACK,
            crate::NetIfaceId::from_raw(1), 64, vec![1, 2, 3])));
        assert_eq!(thread.join().unwrap().unwrap().payload, vec![1, 2, 3]);
        assert!(wake.elapsed() < Duration::from_millis(250), "delivery did not wake the receiver");
    }

    #[test]
    fn blocking_unix_stream_receive_uses_the_production_pair_wake() {
        let pair = crate::UnixPair::new();
        let sock = Arc::new(InetSocket::new_unix_pair_end_in(
            network_namespace::initial(), pair.clone(), crate::UnixEnd::B));
        let receiver = sock.clone();
        let thread = std::thread::spawn(move || recv_blocking(&receiver, 8,
            RecvOptions::default(), crate::sock_clock::monotonic_ns_safe() + 1_000_000_000));

        wait_until(|| pair.reader_waiters(crate::UnixEnd::B).has_waiters());
        let wake = std::time::Instant::now();
        assert_eq!(pair.write(crate::UnixEnd::A, &[4, 5, 6]), Ok(3));
        assert_eq!(thread.join().unwrap().unwrap().payload, vec![4, 5, 6]);
        assert!(wake.elapsed() < Duration::from_millis(250), "write did not wake the receiver");
    }
}
