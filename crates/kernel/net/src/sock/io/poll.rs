// Socket readiness and the integer ioctls that report queue lengths. Split
// out of `sock::io` at the per-file size cutoff; the read and write paths stay
// in the parent.

use super::super::*;

impl InetSocket {
    /// # C: O(1)
    pub fn poll(&self) -> u32 {
        use vfs::{POLL_IN, POLL_OUT, POLL_HUP};
        let pending = if self.has_pending_recv_error() || self.has_extended_error() { vfs::POLL_ERR } else { 0 };
        let packet_ring_ready = self.packet_ring_readable();
        let unix_listener = {
            let kind = self.kind.lock();
            if let SockKind::UnixListener(l) = &*kind { Some(l.clone()) } else { None }
        };
        if let Some(l) = unix_listener { return l.poll_mask() | pending; }
        // The SAME cap the send paths enforce (`socket::send::send_unix_blocking`,
        // `sock_io::write_tcp_blocking`). Poll and `sendmsg` must read one
        // number, or the writer is told "writable" and handed `EAGAIN`.
        let sndbuf_cap = self.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
            .max(0) as usize;
        // `unix_dgram_poll`'s connected-peer backlog arm. Resolved outside the
        // `kind` lock: the lookup takes the per-netns unix registry lock, which
        // must never nest under it.
        let dgram_peer_writable = self.unix_dgram_peer_writable(sndbuf_cap);
        match &*self.kind.lock() {
            SockKind::Raw4(endpoint) => {
                let mut mask = endpoint.poll_mask();
                let rd = self.read_shut.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
                mask | pending
            }
            SockKind::Raw6(endpoint) => {
                let mut mask = endpoint.poll_mask();
                let rd = self.read_shut.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
                mask | pending
            }
            SockKind::Udp => {
                let mut mask = POLL_OUT;
                drain_loopback();
                let udp4 = self.udp4.lock().clone();
                let udp6 = self.udp6.lock().clone();
                let ready4 = udp4.as_ref().is_some_and(|q| q.recv(true).is_some());
                let ready6 = udp6.as_ref().is_some_and(|q| q.recv(true).is_some());
                if ready4 || ready6 { mask |= POLL_IN; }
                let inactive = udp4.as_ref().is_some_and(|q| !q.is_accepting())
                    || udp6.as_ref().is_some_and(|q| !q.is_accepting());
                if inactive { mask = (mask & !POLL_OUT) | vfs::POLL_HUP; }
                let rd = self.read_shut.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
                mask | pending
            }
            SockKind::TcpListener(l) => {
                // A connection a deferring listener is still waiting on is a
                // request, not a queued child, so the queue alone answers
                // readiness — `accept` can satisfy everything in it.
                let ready = !l.accept_q.lock().is_empty();
                crate::stack::tcp_listener::listener_poll_mask(ready, pending)
            }
            SockKind::TcpConn(entry) => {
                drain_loopback();
                let mut mask = entry.poll_mask(sndbuf_cap);
                let rd = self.read_shut.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                // `tcp_poll`: `if (!(shutdown & SEND_SHUTDOWN)) { …writeable
                // test… } else mask |= EPOLLOUT | EPOLLWRNORM;` — a send-shut
                // socket is unconditionally "writable" so the caller collects
                // its EPIPE from `send` rather than sleeping forever.
                if wr { mask |= POLL_OUT | vfs::POLL_WRNORM; }
                if rd && wr { mask |= POLL_HUP; }
                mask | pending
            }
            SockKind::Unix(pair, end) => {
                // A byte awaiting `recv(MSG_OOB)` is priority readiness, which
                // `SO_OOBINLINE` does not suppress: the option changes which
                // receive delivers the byte, not that one is there.
                let urgent = if pair.has_oob(*end) { vfs::POLL_PRI } else { 0 };
                pair.poll_mask(*end, sndbuf_cap) | urgent | pending
            }
            SockKind::UnixListener(_) => pending,
            SockKind::UnixDgram(q) => {
                // `unix_dgram_poll`: `writable = unix_writable(sk, state)`, then
                // cleared when the connected peer's receive queue is full. An
                // UNCONNECTED datagram socket has no peer to consult and stays
                // writable, exactly as Linux leaves `writable` alone when
                // `unix_peer(sk)` is NULL.
                // `writable = unix_writable(sk, state)` FIRST — the sender's own
                // `sk_wmem_alloc` watermark, which is what bounds a symmetric
                // pair — then cleared by the connected-peer backlog test, which
                // `unix_dgram_peer_writable` already skips when symmetric.
                let writable = crate::unix_sock::unix_writable(q.wmem_alloc(), sndbuf_cap)
                    && dgram_peer_writable;
                let mut mask = if writable { POLL_OUT | vfs::POLL_WRNORM } else { 0 };
                if !q.msgs.lock().is_empty() { mask |= POLL_IN; }
                let rd = q.reader_shutdown.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
                mask | pending
            }
            SockKind::UnixMsgPair(pair, end) => {
                pair.poll_mask(*end, sndbuf_cap) | pending
            }
            SockKind::Packet { rx, .. } => {
                let mut mask = POLL_OUT;
                if packet_ring_ready || !rx.lock().is_empty() { mask |= POLL_IN; }
                mask | pending
            }
            SockKind::UnixUnbound(_, _) => POLL_OUT | POLL_HUP | pending,
            SockKind::TcpInit => POLL_OUT | pending,
        }
    }

    /// Linux `SIOCINQ/FIONREAD` and `SIOCOUTQ` queue-count ioctls. # C: O(queue)
    pub fn ioctl_int(&self, cmd: vfs::IoctlIntCmd) -> vfs::KResult<u32> {
        crate::sock_opts::check_ioctl(
            self.net_ns(),
            self.family.load(core::sync::atomic::Ordering::Acquire),
        ).map_err(|_| vfs::VfsError::Eacces)?;
        match cmd {
            vfs::IoctlIntCmd::Fionread => Ok(self.inq_len() as u32),
            vfs::IoctlIntCmd::Siocoutq => Ok(self.outq_len() as u32),
            vfs::IoctlIntCmd::Siocoutqnsd => self.outq_nsd_len(),
            vfs::IoctlIntCmd::Siocatmark => {
                use crate::sock::oob_class::{at_mark, oob_shape, AtMark};
                let kind = self.kind.lock();
                match at_mark(oob_shape(&kind)) {
                    AtMark::Eopnotsupp => Err(vfs::VfsError::Eopnotsupp),
                    AtMark::Enotty => Err(vfs::VfsError::Enotty),
                    AtMark::Report => match &*kind {
                        SockKind::TcpConn(entry) => Ok(entry.conn.lock().at_urgent_mark() as u32),
                        SockKind::Unix(pair, end) => Ok(pair.at_oob_mark(*end) as u32),
                        // `at_mark` reports the mark for exactly these two.
                        _ => Err(vfs::VfsError::Enotty),
                    },
                }
            }
        }
    }

    fn inq_len(&self) -> usize {
        match &*self.kind.lock() {
            SockKind::Raw4(endpoint) => endpoint.next_len(),
            SockKind::Raw6(endpoint) => endpoint.first_len(),
            SockKind::Udp => {
                drain_loopback();
                if let Some(q) = self.udp6.lock().as_ref() {
                    q.recv(true).map(|d| d.payload.len()).unwrap_or(0)
                } else if let Some(q) = self.udp4.lock().as_ref() {
                    q.recv(true).map(|d| d.payload.len()).unwrap_or(0)
                } else { 0 }
            }
            SockKind::TcpConn(entry) => { drain_loopback(); entry.conn.lock().recv_buf.len }
            // A spent out-of-band record still holds a queue slot but delivers
            // nothing, so it is not a byte the reader can ask for.
            SockKind::Unix(pair, end) => pair.readable_len(*end),
            SockKind::UnixDgram(q) => q.msgs.lock().front().map(|m| m.payload.len()).unwrap_or(0),
            SockKind::UnixMsgPair(pair, end) => {
                let g = match end { crate::UnixEnd::A => pair.b_to_a.lock(), crate::UnixEnd::B => pair.a_to_b.lock() };
                g.msgs.front().map(|m| m.payload.len()).unwrap_or(0)
            }
            SockKind::Packet { rx, .. } => rx.lock().first_len().unwrap_or(0),
            SockKind::TcpInit | SockKind::UnixUnbound(_, _) | SockKind::TcpListener(_) | SockKind::UnixListener(_) => 0,
        }
    }

    fn outq_len(&self) -> usize {
        match &*self.kind.lock() {
            SockKind::TcpConn(entry) => {
                let c = entry.conn.lock();
                c.send_buf.len() + c.retx_q.iter().map(|s| s.payload.len()).sum::<usize>()
            }
            SockKind::Udp | SockKind::Raw4(_) | SockKind::Raw6(_)
            | SockKind::Unix(..) | SockKind::UnixDgram(_) | SockKind::UnixMsgPair(_, _)
            | SockKind::Packet { .. } | SockKind::TcpInit | SockKind::UnixUnbound(_, _) | SockKind::TcpListener(_)
            | SockKind::UnixListener(_) => 0,
        }
    }

    /// Linux TCP `SIOCOUTQNSD`: application bytes not yet passed to the
    /// transmit path. Unacknowledged segments belong to `SIOCOUTQ`, not here.
    /// # C: O(1)
    fn outq_nsd_len(&self) -> vfs::KResult<u32> {
        match &*self.kind.lock() {
            SockKind::TcpConn(entry) => Ok(entry.conn.lock().send_buf.len() as u32),
            SockKind::TcpInit => Ok(0),
            SockKind::TcpListener(_) => Err(vfs::VfsError::Einval),
            _ => Err(vfs::VfsError::Enotty),
        }
    }
}
