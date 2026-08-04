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
        // B1409: `mcast.release`/`release_packet_memberships` take RTNL,
        // which is illegal to do from softirq/hard-IRQ context (Linux never
        // runs socket teardown from BH — `sock_put`/`sk_free` is always
        // process context). `release_file()` itself can now be reached from
        // there: `sock::packet::deliver()` (AF_PACKET fan-out, inline in the
        // NetRx softirq) holds temporary `Arc<InetSocket>` clones from
        // `Weak::upgrade()`, and dropping the LAST such clone runs this Drop
        // glue on the softirq stack. Extract-and-defer instead of releasing
        // inline; the rest of this function (TCP/UDP/raw/unix teardown)
        // takes no RTNL and is unaffected.
        if sched::preempt::in_interrupt() {
            let mcast_pending = if self.mcast.is_empty() { None } else { Some(self.mcast.clone()) };
            let anycast_pending = if self.anycast.is_empty() { None } else { Some(self.anycast.clone()) };
            let packet_pending = self.packet_memberships.take_pending(self);
            crate::sock_rtnl_defer::defer(mcast_pending, anycast_pending, packet_pending);
        } else {
            self.mcast.release(stk);
            self.anycast.release(stk);
            self.release_packet_memberships();
        }
        self.release_packet_fanout();
        self.release_packet_rings();
        let _lifecycle = self.local_port.lock();
        if let SockKind::TcpConn(entry) = &*self.kind.lock() {
            use crate::sock_opts::sol_socket::{Scalar, flag};
            let linger_on = self.opts.generic.flag(flag::LINGER);
            let linger_s  = self.opts.generic.scalar(Scalar::LingerSeconds);
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
            stk.drain_tcp_fastopen_client(entry);
            if let Some(seg_bytes) = seg {
                let _ = stk.send_tcp_entry_segment_in(entry, src, dst, &seg_bytes, tos);
                drain_loopback();
            }
            #[cfg(target_os = "oxide-kernel")]
            entry.rx_waiters.wake_all();
        }
        // Linux `reuseport_detach_sock`: leaving the bind key leaves the group.
        crate::reuseport::slot::leave(&self.reuseport_group);
        if let SockKind::TcpListener(listener) = &*self.kind.lock() {
            crate::reuseport::slot::set_endpoint_group(&listener.reuseport_group, None);
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
        let unix_release = {
            let kind = self.kind.lock();
            match &*kind {
                SockKind::Unix(pair, end) => Some(UnixRelease::Stream(pair.clone(), *end)),
                SockKind::UnixUnbound(pair, end) => Some(UnixRelease::Stream(pair.clone(), *end)),
                SockKind::UnixMsgPair(pair, end) => Some(UnixRelease::Message(pair.clone(), *end)),
                SockKind::UnixDgram(queue) => Some(UnixRelease::Datagram(queue.clone())),
                _ => None,
            }
        };
        let collect_unix = unix_release.is_some();
        drop(_lifecycle);
        self.release_unix_endpoint(unix_release);
        if collect_unix { crate::unix_sock::collect_scm_rights(); }
    }
}

/// The AF_UNIX endpoint an `InetSocket` owns, taken out under the lifecycle
/// lock so the teardown below runs without it.
enum UnixRelease {
    Stream(alloc::sync::Arc<crate::UnixPair>, crate::UnixEnd),
    Message(alloc::sync::Arc<crate::UnixMsgPair>, crate::UnixEnd),
    Datagram(alloc::sync::Arc<crate::UnixDgramQueue>),
}

impl InetSocket {
    /// Peer-EOF and address release for an AF_UNIX endpoint. Kept out of line:
    /// `release_file` sits on the deepest static syscall path this kernel has,
    /// so the queue and registry locals this teardown needs must not be charged
    /// to every close that is not an AF_UNIX one.
    /// # C: O(queued messages)
    #[inline(never)]
    fn release_unix_endpoint(&self, unix_release: Option<UnixRelease>) {
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
        // rebind -> "Could not set up manager: Address in use".
        let unix_bound = { self.unix_bound.lock().clone() };
        if let Some(l) = unix_bound {
            crate::net_ns::unix_registry_for_addr_in(&self.net_namespace, &l.addr)
                .unbind_addr(&l.addr);
            l.close();
        }
    }
}

impl Drop for InetSocket {
    fn drop(&mut self) { self.release_file(); }
}
