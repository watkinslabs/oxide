// F161: InetSocket::Drop — last-fd close path. Extracted from
// sock.rs to stay under the 1000-line per-file cap (docs/08§7).
// When the final Arc<InetSocket> drops, tell the peer: TCP emits
// FIN/RST via the TCB; UDP unbinds the port. AF_UNIX peer-EOF
// rides the existing UnixPair / queue Drop in unix_sock.

use crate::sock::{InetSocket, SockKind, drain_loopback, stack};

impl InetSocket {
    /// Linux `sock_close`/`sock_release`: tear down the endpoint at final file
    /// release, independently of inode or transient socket object references.
    /// # C: backend-dependent
    pub fn release_file(&self) {
        use core::sync::atomic::Ordering;
        if self.released.swap(true, Ordering::AcqRel) { return; }
        let stk = stack();
        self.close_mcast_ops();
        self.mcast.release(stk);
        self.release_packet_memberships();
        self.release_packet_fanout();
        self.release_packet_rings();
        let _lifecycle = self.local_port.lock();
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            let linger_on = self.opts.linger_on.load(Ordering::Acquire) != 0;
            let linger_s  = self.opts.linger_s.load(Ordering::Acquire);
            let (seg, src, dst, tos) = {
                let mut c = entry.conn.lock();
                // F194: SO_LINGER on + timeout=0 = abortive close (RST)
                // regardless of conn state. Otherwise the usual FIN/RST
                // pick from drop_close.
                let s = if linger_on && linger_s <= 0 {
                    use crate::tcp_hdr::flags;
                    use crate::tcp_state::TcpState;
                    let rst = c.build_keepalive_probe_with_flag(flags::RST);
                    c.state = TcpState::Closed;
                    Some(rst)
                } else {
                    c.drop_close()
                };
                (s, c.local.ip, c.remote.ip, crate::stack::ecn_tos(&c))
            };
            if let Some(seg_bytes) = seg {
                let _ = stk.send_tcp_entry_segment_in(entry, src, dst, &seg_bytes, tos);
                drain_loopback();
            }
            #[cfg(target_os = "oxide-kernel")]
            entry.rx_waiters.wake_all();
        }
        if let SockKind::TcpListener(listener) = &*self.kind.lock() {
            stk.tcp_unlisten_entry(listener);
        }
        if let Some(bind) = self.tcp_bind.lock().take() {
            stk.tcp_release_bind(&bind);
        }
        match &*self.kind.lock() {
            SockKind::Raw4(endpoint) => stk.unregister_raw4(endpoint),
            SockKind::Raw6(endpoint) => stk.unregister_raw6(endpoint),
            _ => {}
        }
        if matches!(*self.kind.lock(), SockKind::Udp) {
            self.read_shut.store(true, Ordering::Release);
            if let Some(endpoint) = self.udp4.lock().take() {
                stk.unbind_udp_endpoint(&endpoint);
                #[cfg(target_os = "oxide-kernel")]
                endpoint.waiters.wake_all();
            }
            if let Some(endpoint) = self.udp6.lock().take() {
                stk.unbind_udp6_endpoint(&endpoint);
                #[cfg(target_os = "oxide-kernel")]
                endpoint.waiters.wake_all();
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                self.recv_waiters.wake_all();
            }
        }
        // B17 (T11): AF_UNIX peer-EOF. The original Drop comment claimed
        // peer-EOF "rides the existing UnixPair / queue Drop" but there
        // is no Drop on UnixPair, so `close_writer` was only invoked from
        // tests. That left the peer's `is_eof` false forever, so poll
        // never returned POLL_HUP and the surviving task (e.g. sshd-
        // session waiting on its slave) blocked forever — keeping every
        // upstream accept'd TCP socket pinned in CLOSE_WAIT.
        enum UnixRelease {
            Stream(alloc::sync::Arc<crate::UnixPair>, crate::UnixEnd),
            Message(alloc::sync::Arc<crate::UnixMsgPair>, crate::UnixEnd),
            Datagram(alloc::sync::Arc<crate::UnixDgramQueue>),
        }
        let unix_release = {
            let kind = self.kind.lock();
            match &*kind {
                SockKind::Unix(pair, end) => Some(UnixRelease::Stream(pair.clone(), *end)),
                SockKind::UnixMsgPair(pair, end) => Some(UnixRelease::Message(pair.clone(), *end)),
                SockKind::UnixDgram(queue) => Some(UnixRelease::Datagram(queue.clone())),
                _ => None,
            }
        };
        let collect_unix = unix_release.is_some();
        drop(_lifecycle);
        match unix_release {
            Some(UnixRelease::Stream(pair, end)) => pair.release_end(end),
            Some(UnixRelease::Message(pair, end)) => pair.release_end(end),
            Some(UnixRelease::Datagram(queue)) => {
                queue.release();
                if let Some(addr) = queue.bound() {
                    crate::net_ns::unix_registry_for_addr_in(&self.net_namespace, &addr)
                        .dgram_unbind_addr(&addr);
                }
            }
            None => {}
        }
        // Release a bound AF_UNIX stream-listener path so the address is
        // reusable after the socket closes (Linux frees the bind on close).
        // Without this, the bind leaks in UNIX_REGISTRY and a restart-looping
        // daemon (systemd-networkd's varlink listener) hits EADDRINUSE on
        // rebind → "Could not set up manager: Address in use".
        let unix_bound = { self.unix_bound.lock().clone() };
        if let Some(l) = unix_bound {
            crate::net_ns::unix_registry_for_addr_in(&self.net_namespace, &l.addr)
                .unbind_addr(&l.addr);
            l.close();
        }
        if collect_unix { crate::unix_sock::collect_scm_rights(); }
    }
}

impl Drop for InetSocket {
    fn drop(&mut self) { self.release_file(); }
}
