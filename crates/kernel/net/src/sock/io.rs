use super::*;

fn current_sender_creds() -> SenderCreds {
    match sched::live::current() {
        Some(t) => SenderCreds {
            pid: t.visible_pid(),
            uid: t.creds.euid.load(core::sync::atomic::Ordering::Acquire),
            gid: t.creds.egid.load(core::sync::atomic::Ordering::Acquire),
        },
        None => SenderCreds::default(),
    }
}

fn vfs_from_neterr(e: crate::NetError) -> vfs::VfsError {
    match e {
        crate::NetError::Eagain        => vfs::VfsError::Eagain,
        crate::NetError::Eio           => vfs::VfsError::Eio,
        crate::NetError::Einval        => vfs::VfsError::Einval,
        crate::NetError::Enobufs       => vfs::VfsError::Enobufs,
        crate::NetError::Enomem        => vfs::VfsError::Enomem,
        crate::NetError::Eaddrnotavail => vfs::VfsError::Eaddrnotavail,
        crate::NetError::Edestaddrreq  => vfs::VfsError::Edestaddrreq,
        crate::NetError::Enetunreach   => vfs::VfsError::Enetunreach,
        crate::NetError::Econnrefused  => vfs::VfsError::Econnrefused,
        crate::NetError::Econnreset    => vfs::VfsError::Econnreset,
        crate::NetError::Epipe         => vfs::VfsError::Epipe,
        crate::NetError::Enotconn      => vfs::VfsError::Enotconn,
        _                              => vfs::VfsError::Eio,
    }
}

impl InetSocket {
    /// `f_op->read` — blocking stream/datagram read. # C: backend-dependent
    pub fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        // F158: snapshot the kind out of its lock first so we don't
        // hold sock.kind.lock() across a park (deliver_tcp's wake path
        // doesn't touch this lock but holding it across schedule is
        // still wrong on principle and breaks AF_UNIX peers that
        // close-and-flip kind during read).
        enum K {
            Unix(Arc<crate::UnixPair>, crate::UnixEnd),
            UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
            Tcp(Arc<TcpEntry>),
            Msg,
            NotConnected,
        }
        let k = match &*self.kind.lock() {
            SockKind::Unix(p, e)        => K::Unix(p.clone(), *e),
            SockKind::UnixMsgPair(p, e) => K::UnixMsgPair(p.clone(), *e),
            SockKind::TcpConn(e)        => K::Tcp(e.clone()),
            SockKind::Udp | SockKind::UnixDgram(_) | SockKind::Packet { .. } => K::Msg,
            _                            => K::NotConnected,
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
                if self.read_shut.load(core::sync::atomic::Ordering::Acquire) {
                    let got = stack().tcp_recv(&entry, buf.len());
                    let n = got.len();
                    if n != 0 { buf[..n].copy_from_slice(&got); }
                    return Ok(n);
                }
                // F169: convert SO_RCVTIMEO (ns) into an absolute
                // monotonic deadline; 0 = no timeout (indefinite).
                crate::sock_io::read_tcp_blocking(self, &entry, buf, deadline_ns)
            }
            K::Msg => crate::sock_vfs_read::read_msg_socket_blocking(self, buf, deadline_ns),
            K::NotConnected => Err(vfs::VfsError::Enotconn),
        }
    }

    /// Non-blocking variant per `15§5` / vfs::Inode contract. Returns
    /// Eagain when recv_buf is empty AND the connection is still in a
    /// data-transfer state; Ok(0) only on peer FIN.
    /// # C: backend-dependent
    pub fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        // Snapshot the kind out of its lock (never park while holding it, and
        // never call the *blocking* read() for AF_UNIX — a nonblocking read on
        // an empty-but-open AF_UNIX stream MUST return EAGAIN, not sleep, or a
        // systemd varlink/sd-event fd drains into a park and wedges sysinit).
        enum K {
            Unix(Arc<crate::UnixPair>, crate::UnixEnd),
            UnixMsgPair(Arc<crate::UnixMsgPair>, crate::UnixEnd),
            Tcp(Arc<TcpEntry>),
            Msg,
            NotConnected,
        }
        let k = match &*self.kind.lock() {
            SockKind::Unix(p, e)        => K::Unix(p.clone(), *e),
            SockKind::UnixMsgPair(p, e) => K::UnixMsgPair(p.clone(), *e),
            SockKind::TcpConn(e)        => K::Tcp(e.clone()),
            SockKind::Udp | SockKind::UnixDgram(_) | SockKind::Packet { .. } => K::Msg,
            _                            => K::NotConnected,
        };
        match k {
            K::Tcp(entry) => {
                drain_loopback();
                let got = stack().tcp_recv(&entry, buf.len());
                if !got.is_empty() {
                    let n = got.len();
                    buf[..n].copy_from_slice(&got);
                    return Ok(n);
                }
                if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
                let st = entry.conn.lock().state;
                if st == crate::tcp_state::TcpState::Closed
                    || st == crate::tcp_state::TcpState::CloseWait
                    || st == crate::tcp_state::TcpState::LastAck
                {
                    return Ok(0);
                }
                Err(vfs::VfsError::Eagain)
            }
            // AF_UNIX SOCK_STREAM: drain what's queued; empty → EOF (peer closed
            // + drained) gives Ok(0), else EAGAIN. Never parks.
            K::Unix(pair, end) => {
                let got = pair.read(end, buf.len());
                if !got.is_empty() {
                    let n = got.len();
                    buf[..n].copy_from_slice(&got);
                    return Ok(n);
                }
                if pair.take_reset(end) { return Err(vfs::VfsError::Econnreset); }
                if pair.is_eof(end) { return Ok(0); }
                Err(vfs::VfsError::Eagain)
            }
            // AF_UNIX SOCK_SEQPACKET/DGRAM pair: recv() returns None when nothing
            // pending AND not EOF, Some(empty) on EOF, Some(data) otherwise.
            K::UnixMsgPair(pair, end) => {
                match pair.recv(end, buf.len()) {
                    Some(msg) => {
                        let n = msg.len();
                        buf[..n].copy_from_slice(&msg);
                        Ok(n)
                    }
                    None => if pair.take_reset(end) { Err(vfs::VfsError::Econnreset) } else { Err(vfs::VfsError::Eagain) },
                }
            }
            // Datagram/packet sockets: read() consumes one packet via the
            // same receive core as recvfrom(..., src=NULL). TCP init/listener
            // sockets are not connected and return ENOTCONN like Linux.
            K::Msg => match crate::sock_io::recvfrom_opts(self, buf.len(), crate::sock_io::RecvOptions::default()) {
                Ok(r) => {
                    let n = r.payload.len();
                    buf[..n].copy_from_slice(&r.payload);
                    Ok(n)
                }
                Err(e) => Err(crate::sock_vfs_read::recv_vfs_err(e)),
            },
            K::NotConnected => Err(vfs::VfsError::Enotconn),
        }
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
            K::Unix(pair, end) => match pair.write(end, buf) {
                Ok(n) => Ok(n),
                Err(crate::UnixStreamError::PeerClosed) => {
                    #[cfg(target_os = "oxide-kernel")]
                    sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                    Err(vfs::VfsError::Epipe)
                }
            },
            K::UnixMsgPair(pair, end) => match pair.send(end, buf) {
                Ok(n) => Ok(n),
                Err(crate::UnixMsgError::PeerClosed) => Err(vfs::VfsError::Epipe),
                Err(crate::UnixMsgError::PeerRefused) => Err(vfs::VfsError::Econnrefused),
            },
            K::Tcp(entry) => {
                if self.write_shut.load(core::sync::atomic::Ordering::Acquire) {
                    #[cfg(target_os = "oxide-kernel")]
                    sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                    return Err(vfs::VfsError::Epipe);
                }
                let cap = self.opts.sndbuf.load(core::sync::atomic::Ordering::Acquire)
                    .max(TCP_SNDBUF_DEFAULT) as usize;
                let timeo = self.opts.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
                let deadline_ns = compute_deadline_ns(timeo);
                let nodelay = self.opts.tcp_nodelay.load(core::sync::atomic::Ordering::Acquire) != 0;
                let cork = self.opts.tcp_cork.load(core::sync::atomic::Ordering::Acquire) != 0;
                crate::sock_io::write_tcp_blocking(&entry, buf, cap, deadline_ns, nodelay, cork)
            }
            K::Other => crate::sock::sendto(self, buf, None, current_sender_creds()).map_err(vfs_from_neterr),
        }
    }

    /// F164: non-blocking write per O_NONBLOCK. Returns Eagain when
    /// the connection's send buffer is at SO_SNDBUF; else writes as
    /// many bytes as fit. UDP / AF_UNIX delegate to their existing
    /// write() — neither blocks on send today.
    /// # C: backend-dependent
    pub fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            if self.write_shut.load(core::sync::atomic::Ordering::Acquire) {
                #[cfg(target_os = "oxide-kernel")]
                sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                return Err(vfs::VfsError::Epipe);
            }
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
        let unix_listener = {
            let kind = self.kind.lock();
            if let SockKind::UnixListener(l) = &*kind { Some(l.clone()) } else { None }
        };
        if let Some(l) = unix_listener { return l.poll_mask(); }
        match &*self.kind.lock() {
            SockKind::Udp => {
                let mut mask = POLL_OUT;
                if let Some(p) = *self.local_port.lock() {
                    drain_loopback();
                    if stack().recv_udp_opts(p, true).is_some() {
                        mask |= POLL_IN;
                    }
                }
                let rd = self.read_shut.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
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
                let rd = self.read_shut.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
                mask
            }
            SockKind::Unix(pair, end) => {
                pair.poll_mask(*end)
            }
            SockKind::UnixListener(_) => 0,
            SockKind::UnixDgram(q) => {
                let mut mask = POLL_OUT;
                if !q.msgs.lock().is_empty() { mask |= POLL_IN; }
                let rd = q.reader_shutdown.load(core::sync::atomic::Ordering::Acquire);
                let wr = self.write_shut.load(core::sync::atomic::Ordering::Acquire);
                if rd { mask |= POLL_IN | vfs::POLL_RDHUP; }
                if rd && wr { mask |= POLL_HUP; }
                mask
            }
            SockKind::UnixMsgPair(pair, end) => {
                pair.poll_mask(*end)
            }
            SockKind::Packet { rx, .. } => {
                // F131: tx always ready; rx readable when rx queue
                // has a frame. v1 rx queue stays empty until the
                // virtio-net rx-deliver path lands.
                let mut mask = POLL_OUT;
                if !rx.lock().is_empty() { mask |= POLL_IN; }
                mask
            }
            SockKind::TcpInit => {
                if self.family.load(core::sync::atomic::Ordering::Acquire) == AF_UNIX {
                    POLL_OUT | POLL_HUP
                } else { POLL_OUT }
            }
        }
    }

    /// Linux `SIOCINQ/FIONREAD` and `SIOCOUTQ` queue-count ioctls. # C: O(queue)
    pub fn ioctl_int(&self, cmd: vfs::IoctlIntCmd) -> vfs::KResult<u32> {
        match cmd {
            vfs::IoctlIntCmd::Fionread => Ok(self.inq_len() as u32),
            vfs::IoctlIntCmd::Siocoutq => Ok(self.outq_len() as u32),
        }
    }

    fn inq_len(&self) -> usize {
        match &*self.kind.lock() {
            SockKind::Udp => {
                let Some(p) = *self.local_port.lock() else { return 0; };
                drain_loopback();
                if self.family.load(core::sync::atomic::Ordering::Acquire) == AF_INET6 {
                    stack().recv_udp6_meta_opts(p, true).map(|(_, _, _, _, _, b)| b.len()).unwrap_or(0)
                } else {
                    stack().recv_udp_meta_opts(p, true).map(|(_, _, _, _, _, b)| b.len()).unwrap_or(0)
                }
            }
            SockKind::TcpConn(entry) => { drain_loopback(); entry.conn.lock().recv_buf.len() }
            SockKind::Unix(pair, end) => match end {
                crate::UnixEnd::A => pair.b_to_a.lock().buf.len(),
                crate::UnixEnd::B => pair.a_to_b.lock().buf.len(),
            },
            SockKind::UnixDgram(q) => q.msgs.lock().front().map(|m| m.payload.len()).unwrap_or(0),
            SockKind::UnixMsgPair(pair, end) => {
                let g = match end { crate::UnixEnd::A => pair.b_to_a.lock(), crate::UnixEnd::B => pair.a_to_b.lock() };
                g.msgs.front().map(|m| m.payload.len()).unwrap_or(0)
            }
            SockKind::Packet { rx, .. } => rx.lock().front().map(|b| b.len()).unwrap_or(0),
            SockKind::TcpInit | SockKind::TcpListener(_) | SockKind::UnixListener(_) => 0,
        }
    }

    fn outq_len(&self) -> usize {
        match &*self.kind.lock() {
            SockKind::TcpConn(entry) => {
                let c = entry.conn.lock();
                c.send_buf.len() + c.retx_q.iter().map(|s| s.payload.len()).sum::<usize>()
            }
            SockKind::Udp | SockKind::Unix(..) | SockKind::UnixDgram(_) | SockKind::UnixMsgPair(_, _)
            | SockKind::Packet { .. } | SockKind::TcpInit | SockKind::TcpListener(_)
            | SockKind::UnixListener(_) => 0,
        }
    }
}
