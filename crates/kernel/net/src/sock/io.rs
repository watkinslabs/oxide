use super::*;

// Readiness, the integer ioctls and the queue-length answers they report,
// split out at the per-file size cutoff.
mod poll;

/// The running task's sender credentials for an unsolicited AF_UNIX
/// credential stamp: the REAL uid/gid, which is what a receiver reads back
/// from `SCM_CREDENTIALS` (`SO_PEERCRED` is the effective-pair interface).
/// # C: O(1)
fn current_sender_creds() -> SenderCreds { SenderCreds::current() }

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
        crate::NetError::Ehostunreach  => vfs::VfsError::Ehostunreach,
        crate::NetError::Eacces        => vfs::VfsError::Eacces,
        crate::NetError::Enonet        => vfs::VfsError::Enonet,
        crate::NetError::Enoprotoopt   => vfs::VfsError::Enoprotoopt,
        crate::NetError::Eopnotsupp    => vfs::VfsError::Eopnotsupp,
        crate::NetError::Eproto        => vfs::VfsError::Eproto,
        crate::NetError::Ehostdown     => vfs::VfsError::Ehostdown,
        crate::NetError::Econnrefused  => vfs::VfsError::Econnrefused,
        crate::NetError::Econnaborted  => vfs::VfsError::Econnaborted,
        crate::NetError::Econnreset    => vfs::VfsError::Econnreset,
        crate::NetError::Etimedout     => vfs::VfsError::Etimedout,
        crate::NetError::Epipe         => vfs::VfsError::Epipe,
        crate::NetError::Enotconn      => vfs::VfsError::Enotconn,
        crate::NetError::Enodev        => vfs::VfsError::Enodev,
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
            SockKind::Udp | SockKind::Raw4(_) | SockKind::Raw6(_)
                | SockKind::UnixDgram(_) | SockKind::Packet { .. } => K::Msg,
            _                            => K::NotConnected,
        };
        // Every kind, not only the connected ones: the receive core below no
        // longer carries a verdict of its own, so this is the one place a
        // `read(2)`-shaped receive is admitted.
        crate::sock_opts::check_receive(self).map_err(vfs_from_neterr)?;
        let timeo = self.opts.base.rcvtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
        let deadline_ns = compute_deadline_ns(timeo);
        match k {
            K::Unix(pair, end) => {
                let passcred = self.opts.base.passcred.on();
                let inline = self.opts.base.oobinline.load(core::sync::atomic::Ordering::Acquire) != 0;
                let result = crate::sock_io::read_unix_stream_blocking(&pair, end, buf, deadline_ns,
                    passcred, inline);
                if matches!(result, Ok(n) if n != 0) { self.note_receive_now(); }
                result
            }
            K::UnixMsgPair(pair, end) => {
                let result = crate::sock_io::read_unix_msg_blocking(&pair, end, buf, deadline_ns);
                if matches!(result, Ok(n) if n != 0) { self.note_receive_now(); }
                result
            }
            K::Tcp(entry) => {
                // F169: convert SO_RCVTIMEO (ns) into an absolute
                // monotonic deadline; 0 = no timeout (indefinite).
                let result = crate::sock_io::read_tcp_blocking(self, &entry, buf, deadline_ns);
                if matches!(result, Ok(n) if n != 0) { self.note_receive_now(); }
                result
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
            SockKind::Udp | SockKind::Raw4(_) | SockKind::Raw6(_)
                | SockKind::UnixDgram(_) | SockKind::Packet { .. } => K::Msg,
            _                            => K::NotConnected,
        };
        // Every kind, not only the connected ones: the receive core below no
        // longer carries a verdict of its own, so this is the one place a
        // `read(2)`-shaped receive is admitted.
        crate::sock_opts::check_receive(self).map_err(vfs_from_neterr)?;
        match k {
            K::Tcp(entry) => {
                drain_loopback();
                let inline = self.opts.base.oobinline.load(core::sync::atomic::Ordering::Acquire) != 0;
                let got = stack().tcp_recv_with_offset_oob(&entry, buf.len(), false, 0, inline,
                    |bytes| Ok::<_, ()>((bytes.to_vec(), bytes.len())))
                    .ok().flatten().unwrap_or_default();
                if !got.is_empty() {
                    let n = got.len();
                    buf[..n].copy_from_slice(&got);
                    self.note_receive_now();
                    return Ok(n);
                }
                let eno = self.take_pending_recv_error();
                if eno != 0 { return Err(crate::sock_io::tcp_vfs_error(eno)); }
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
                let passcred = self.opts.base.passcred.on();
                let inline = self.opts.base.oobinline.load(core::sync::atomic::Ordering::Acquire) != 0;
                let got = pair.read_passcred(end, buf.len(), passcred, inline);
                if !got.is_empty() {
                    let n = got.len();
                    buf[..n].copy_from_slice(&got);
                    self.note_receive_now();
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
                        self.note_receive_now();
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
                    if r.full_len != 0 || r.peer.is_some() || r.peer6.is_some() || r.packet.is_some() {
                        match r.packet.and_then(crate::sock::PacketReceive::timestamp_ns) {
                            Some(timestamp_ns) => self.note_receive_timestamp(timestamp_ns),
                            None => self.note_receive_now(),
                        }
                    }
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
        // Every kind, not only the connected ones: the transport below no
        // longer carries a verdict of its own, so this is the one place a
        // `write(2)`-shaped send is admitted.
        crate::sock_opts::check_send(self).map_err(vfs_from_neterr)?;
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
                let cap = self.opts.base.sndbuf.load(core::sync::atomic::Ordering::Acquire)
                    .max(0) as usize;
                let timeo = self.opts.base.sndtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
                let deadline_ns = compute_deadline_ns(timeo);
                let nodelay = self.opts.tcp_nodelay.load(core::sync::atomic::Ordering::Acquire) != 0;
                let cork = self.opts.tcp_cork.load(core::sync::atomic::Ordering::Acquire) != 0;
                crate::sock_io::write_tcp_blocking(self, &entry, buf, cap, deadline_ns, nodelay, cork)
            }
            K::Other => crate::sock::sendto(self, buf, None, current_sender_creds(),
                &crate::send_control::SendControl::default()).map_err(vfs_from_neterr),
        }
    }

    /// Write a kernel-owned AF_UNIX stream without delivering SIGPIPE to the
    /// current task when its peer has gone away. Kernel producers have no
    /// userspace signal disposition to consult, so the caller receives EPIPE.
    /// # C: O(buf.len())
    pub fn write_kernel(&self, buf: &[u8]) -> vfs::KResult<usize> {
        let (pair, end) = match &*self.kind.lock() {
            SockKind::Unix(pair, end) => (pair.clone(), *end),
            _ => return Err(vfs::VfsError::Eopnotsupp),
        };
        crate::sock_opts::check_send(self).map_err(vfs_from_neterr)?;
        pair.write(end, buf).map_err(|_| vfs::VfsError::Epipe)
    }

    /// Read a kernel-owned AF_UNIX stream through its canonical blocking
    /// receive path without pulling unrelated protocol backends into callers.
    /// # C: O(buf.len()) or O(wait)
    pub fn read_kernel(&self, buf: &mut [u8]) -> vfs::KResult<usize> {
        let (pair, end) = match &*self.kind.lock() {
            SockKind::Unix(pair, end) => (pair.clone(), *end),
            _ => return Err(vfs::VfsError::Eopnotsupp),
        };
        crate::sock_opts::check_receive(self).map_err(vfs_from_neterr)?;
        let timeo = self.opts.base.rcvtimeo_ns.load(core::sync::atomic::Ordering::Acquire);
        let deadline_ns = compute_deadline_ns(timeo);
        let passcred = self.opts.base.passcred.on();
        let inline = self.opts.base.oobinline.load(core::sync::atomic::Ordering::Acquire) != 0;
        let result = crate::sock_io::read_unix_stream_blocking(&pair, end, buf, deadline_ns,
            passcred, inline);
        if matches!(result, Ok(n) if n != 0) { self.note_receive_now(); }
        result
    }

    /// F164: non-blocking write per O_NONBLOCK. Returns Eagain when
    /// the connection's send buffer is at SO_SNDBUF; else writes as
    /// many bytes as fit. UDP / AF_UNIX delegate to their existing
    /// write() — neither blocks on send today.
    /// # C: backend-dependent
    pub fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            crate::sock_opts::check_send(self).map_err(vfs_from_neterr)?;
            if self.write_shut.load(core::sync::atomic::Ordering::Acquire) {
                #[cfg(target_os = "oxide-kernel")]
                sched::live::send_signal_self(sched::live::Signum::Sigpipe);
                return Err(vfs::VfsError::Epipe);
            }
            let cap = self.opts.base.sndbuf.load(core::sync::atomic::Ordering::Acquire)
                .max(0) as usize;
            let entry = entry.clone();
            let eno = self.take_pending_recv_error();
            if eno != 0 { return Err(crate::sock_io::tcp_vfs_error(eno)); }
            // F166/F167: closing/closed send side → SIGPIPE + EPIPE
            // before tcp_send so we don't queue bytes into a corpse.
            let st = entry.conn.lock().state;
            if matches!(st,
                crate::tcp_state::TcpState::Closed
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

    /// Datagram writability:
    /// writable unless a CONNECTED, non-symmetrically-paired peer's receive
    /// queue is full. `true` for every non-datagram kind so the caller can
    /// evaluate this once, outside the `kind` lock.
    /// # C: O(log N_registry) when connected, O(1) otherwise
    fn unix_dgram_peer_writable(&self, sndbuf_cap: usize) -> bool {
        let local = {
            let kind = self.kind.lock();
            match &*kind { SockKind::UnixDgram(q) => q.clone(), _ => return true }
        };
        // `other = unix_peer(sk)`; NULL ⇒ Linux leaves `writable` set.
        let Some(address) = local.peer() else { return true };
        let Some(peer) = crate::net_ns::unix_registry_for_addr_in(&self.net_namespace, &address)
            .dgram_lookup_addr(&address) else { return true };
        // A symmetrically connected pair is flow-controlled by write memory
        // alone, so its backlog is not consulted. Poll and the send path read
        // the ONE relation, from the same identities.
        let symmetric = crate::unix_sock::dgram_symmetric_pair(peer.peer_id(), Some(local.id()));
        if symmetric { return true; }
        if crate::unix_sock::dgram_peer_writable(peer.queued_bytes(), sndbuf_cap) { return true; }
        // `unix_dgram_peer_wake_me`: register on the peer's wake list at the
        // exact point we decide "not writable", so the peer's drain relays an
        // EPOLLOUT to US. Our own subscribers never see the peer's activity,
        // so without this the writer parks and nothing ever wakes it.
        peer.register_peer_writer(&self.poll_subs);
        false
    }
}
