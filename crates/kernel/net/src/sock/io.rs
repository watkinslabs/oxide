use super::*;

impl InetSocket {
    /// `f_op->read` — blocking stream/datagram read. # C: backend-dependent
    pub fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        // F166: shutdown(SHUT_RD | SHUT_RDWR) latches read_shut →
        // read returns EOF without consulting the recv buffer.
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) {
            return Ok(0);
        }
        // F158: snapshot the kind out of its lock first so we don't
        // hold sock.kind.lock() across a park (deliver_tcp's wake path
        // doesn't touch this lock but holding it across schedule is
        // still wrong on principle and breaks AF_UNIX peers that
        // close-and-flip kind during read).
        enum K {
            Unix(Arc<crate::UnixPair>, crate::UnixEnd),
            UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
            Tcp(Arc<TcpEntry>),
            Other,
        }
        let k = match &*self.kind.lock() {
            SockKind::Unix(p, e)        => K::Unix(p.clone(), *e),
            SockKind::UnixMsgPair(p, e) => K::UnixMsgPair(p.clone(), *e),
            SockKind::TcpConn(e)        => K::Tcp(e.clone()),
            _                            => K::Other,
        };
        let timeo = self.opts.rcvtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
        let deadline_ns = compute_deadline_ns(timeo);
        match k {
            K::Unix(pair, end) => {
                crate::sock_io::read_unix_stream_blocking(&pair, end, buf, deadline_ns)
            }
            K::UnixMsgPair(pair, end) => {
                crate::sock_io::read_unix_msg_blocking(&pair, end, buf, deadline_ns)
            }
            K::Tcp(entry) => {
                // F169: convert SO_RCVTIMEO (ns) into an absolute
                // monotonic deadline; 0 = no timeout (indefinite).
                crate::sock_io::read_tcp_blocking(&entry, buf, deadline_ns)
            }
            K::Other => Err(vfs::VfsError::Einval),
        }
    }

    /// Non-blocking variant per `15§5` / vfs::Inode contract. Returns
    /// Eagain when recv_buf is empty AND the connection is still in a
    /// data-transfer state; Ok(0) only on peer FIN.
    /// # C: backend-dependent
    pub fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) {
            return Ok(0);
        }
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            drain_loopback();
            let got = stack().tcp_recv(entry, buf.len());
            if !got.is_empty() {
                let n = got.len();
                buf[..n].copy_from_slice(&got);
                return Ok(n);
            }
            let st = entry.conn.lock().state;
            if st == crate::tcp_state::TcpState::Closed
                || st == crate::tcp_state::TcpState::CloseWait
                || st == crate::tcp_state::TcpState::LastAck
            {
                return Ok(0);
            }
            return Err(vfs::VfsError::Eagain);
        }
        // Fall back to the blocking path for non-TCP sock kinds — their
        // existing read() impl already returns Eagain for empty queues
        // where applicable (UnixMsgPair).
        self.read(_off, buf)
    }

    /// # C: backend-dependent
    pub fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        // F164: snapshot kind out of its lock for parity with read();
        // a TCP write may park on entry.rx_waiters until the peer's
        // ACK frees send_buf space — we must not hold sock.kind.lock()
        // across the park.
        enum K {
            Unix(Arc<crate::UnixPair>, crate::UnixEnd),
            UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
            Tcp(Arc<TcpEntry>),
            Other,
        }
        let k = match &*self.kind.lock() {
            SockKind::Unix(p, e)        => K::Unix(p.clone(), *e),
            SockKind::UnixMsgPair(p, e) => K::UnixMsgPair(p.clone(), *e),
            SockKind::TcpConn(e)        => K::Tcp(e.clone()),
            _                            => K::Other,
        };
        match k {
            K::Unix(pair, end)        => Ok(pair.write(end, buf)),
            K::UnixMsgPair(pair, end) => Ok(pair.send(end, buf)),
            K::Tcp(entry) => {
                let cap = self.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
                    .max(TCP_SNDBUF_DEFAULT) as usize;
                let timeo = self.opts.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
                let deadline_ns = compute_deadline_ns(timeo);
                let nodelay = self.opts.tcp_nodelay.load(core::sync::atomic::Ordering::Acquire) != 0;
                let cork = self.opts.tcp_cork.load(core::sync::atomic::Ordering::Acquire) != 0;
                crate::sock_io::write_tcp_blocking(&entry, buf, cap, deadline_ns, nodelay, cork)
            }
            K::Other => Err(vfs::VfsError::Einval),
        }
    }

    /// F164: non-blocking write per O_NONBLOCK. Returns Eagain when
    /// the connection's send buffer is at SO_SNDBUF; else writes as
    /// many bytes as fit. UDP / AF_UNIX delegate to their existing
    /// write() — neither blocks on send today.
    /// # C: backend-dependent
    pub fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            let cap = self.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
                .max(TCP_SNDBUF_DEFAULT) as usize;
            let entry = entry.clone();
            // F166/F167: closing/closed send side → SIGPIPE + EPIPE
            // before tcp_send so we don't queue bytes into a corpse.
            let st = entry.conn.lock().state;
            if matches!(st,
                crate::tcp_state::TcpState::Closed
                | crate::tcp_state::TcpState::CloseWait
                | crate::tcp_state::TcpState::LastAck
                | crate::tcp_state::TcpState::Closing
                | crate::tcp_state::TcpState::TimeWait
                | crate::tcp_state::TcpState::FinWait1
                | crate::tcp_state::TcpState::FinWait2
            ) {
                sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                return Err(vfs::VfsError::Epipe);
            }
            let nodelay = self.opts.tcp_nodelay.load(core::sync::atomic::Ordering::Acquire) != 0;
            let cork = self.opts.tcp_cork.load(core::sync::atomic::Ordering::Acquire) != 0;
            return match stack().tcp_send(&entry, buf, cap, nodelay, cork) {
                Ok(n) => { drain_loopback(); Ok(n) }
                Err(crate::NetError::Eagain) => Err(vfs::VfsError::Eagain),
                Err(_) => Err(vfs::VfsError::Eio),
            };
        }
        self.write(_off, buf)
    }

    /// # C: O(1)
    pub fn poll(&self) -> u32 {
        use vfs::{POLL_IN, POLL_OUT, POLL_HUP};
        match &*self.kind.lock() {
            SockKind::Udp => {
                let mut mask = POLL_OUT;
                if let Some(p) = *self.local_port.lock() {
                    drain_loopback();
                    if stack().recv_udp(p).is_some() {
                        // Re-queue; recv_udp consumed it.
                        // To peek without consuming we'd need an
                        // explicit API; v1 just signals readable
                        // when something was recently visible.
                        mask |= POLL_IN;
                    }
                }
                mask
            }
            SockKind::TcpListener(l) => {
                if l.accept_q.lock().is_empty() { POLL_OUT } else { POLL_IN | POLL_OUT }
            }
            SockKind::TcpConn(entry) => {
                drain_loopback();
                let c = entry.conn.lock();
                let mut mask = POLL_OUT;
                if !c.recv_buf.is_empty() { mask |= POLL_IN; }
                if c.state == crate::tcp_state::TcpState::Closed
                    || c.state.is_closing() { mask |= POLL_HUP; }
                mask
            }
            SockKind::Unix(pair, end) => {
                let mut mask = POLL_OUT;
                let read_q = match end {
                    crate::UnixEnd::A => &pair.b_to_a,
                    crate::UnixEnd::B => &pair.a_to_b,
                };
                if !read_q.lock().buf.is_empty() { mask |= POLL_IN; }
                if pair.is_eof(*end) { mask |= POLL_HUP; }
                mask
            }
            SockKind::UnixListener(l) => {
                if l.accept_q.lock().is_empty() { POLL_OUT } else { POLL_IN | POLL_OUT }
            }
            SockKind::UnixDgram(q) => {
                let mut mask = POLL_OUT;
                if !q.msgs.lock().is_empty() { mask |= POLL_IN; }
                mask
            }
            SockKind::UnixMsgPair(pair, end) => {
                let mut mask = POLL_OUT;
                if pair.has_msg(*end) { mask |= POLL_IN; }
                if pair.is_eof(*end)  { mask |= POLL_HUP; }
                mask
            }
            SockKind::Packet { rx, .. } => {
                // F131: tx always ready; rx readable when rx queue
                // has a frame. v1 rx queue stays empty until the
                // virtio-net rx-deliver path lands.
                let mut mask = POLL_OUT;
                if !rx.lock().is_empty() { mask |= POLL_IN; }
                mask
            }
            SockKind::TcpInit => POLL_OUT,
        }
    }
}
