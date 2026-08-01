use super::*;

use super::tcp_tx::TcpTxPolicy;

impl NetStack {
    /// F164: send `data`; bounded by `sndbuf_cap`. Returns Eagain
    /// when full. # C: O(data + N segments)
    pub fn tcp_send(&self, entry: &TcpEntry, data: &[u8], sndbuf_cap: usize, nodelay: bool, cork: bool)
        -> NetResult<usize>
    {
        let (segs, accepted, src, dst, tos) = {
            let mut c = entry.conn.lock();
            // Quotas: send_buf bytes + retx_q bytes both count
            // against SO_SNDBUF (unACKed data total — RFC 1122
            // §4.2.2.1 / Linux sk_wmem_queued).
            let in_flight: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
            let used = c.send_buf.len() + in_flight;
            let avail = sndbuf_cap.saturating_sub(used);
            if avail == 0 && !data.is_empty() { return Err(NetError::Eagain); }
            let accept = ::core::cmp::min(avail, data.len());
            c.send(&data[..accept]);
            let segs = c.output(1500, nodelay, cork);
            (segs, accept, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        let n = segs.len();
        for s in &segs {
            self.send_tcp_segment_in(entry.net_ns(), src, dst, s, tos, entry.bound_iface(),
                TcpTxPolicy::Entry(entry))?;
        }
        // F159: stamp the last N retx_q entries (one per emitted segment)
        // with the actual xmit time.
        stamp_last_sent(entry, n);
        Ok(accepted)
    }

    /// Emit one TCP urgent byte with the URG flag and pointer. # C: O(1) xmit
    pub fn tcp_send_urgent(&self, entry: &TcpEntry, byte: u8) -> NetResult<usize> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            if !c.state.is_established() { return Err(NetError::Epipe); }
            let seg = c.send_urgent(byte);
            (seg, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        self.send_tcp_segment_in(entry.net_ns(), src, dst, &seg, tos, entry.bound_iface(),
            TcpTxPolicy::Entry(entry))?;
        Ok(1)
    }

    /// Application drains up to `max` bytes from the recv buffer.
    /// # C: O(min(max, recv_buf.len()))
    pub fn tcp_recv(&self, entry: &TcpEntry, max: usize) -> Vec<u8> {
        entry.conn.lock().recv(max)
    }

    /// Transactional application receive with optional peek. # C: O(max)
    pub fn tcp_recv_with<R, E>(&self, entry: &TcpEntry, max: usize, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    {
        entry.conn.lock().recv_with(max, peek, copy)
    }

    /// Transactional application receive after a non-consuming logical offset. # C: O(offset + max)
    pub fn tcp_recv_with_offset<R, E>(&self, entry: &TcpEntry, max: usize, peek: bool, offset: usize, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    {
        entry.conn.lock().recv_with_offset(max, peek, offset, copy)
    }

    /// Transactional normal receive with canonical SO_OOBINLINE behavior. # C: O(offset + max)
    pub fn tcp_recv_with_offset_oob<R, E>(&self, entry: &TcpEntry, max: usize, peek: bool,
        offset: usize, inline: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    {
        // Linux `tcp_cleanup_rbuf` (`net/ipv4/tcp.c:1575-1600`): "We send an
        // ACK if we can now advertise a non-zero window which has been raised
        // significantly ... `new_window >= 2 * rcv_window_now`". Without this
        // window-update ACK a receiver that drained a CLOSED window never tells
        // the sender, and — with no persist/probe0 timer on the send side — the
        // connection deadlocks permanently. `poll` correctly reporting the
        // sender un-writable turns that deadlock from a busy spin into a stall,
        // so the update has to exist for the writability predicate to be safe.
        let (result, update) = {
            let mut conn = entry.conn.lock();
            let before = conn.current_rcv_window() as u32;
            let result = conn.recv_with_offset_oob(max, peek, offset, inline, copy);
            let after = conn.current_rcv_window() as u32;
            let raised = after != 0 && after >= before.saturating_mul(2) && after > before;
            let update = if raised && !peek {
                Some((conn.build_segment(crate::tcp_hdr::flags::ACK, &[]),
                      conn.local.ip, conn.remote.ip, ecn_tos(&conn)))
            } else { None };
            (result, update)
        };
        if let Some((seg, src, dst, tos)) = update {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, &seg, tos,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
        result
    }

    /// Copy the pending TCP urgent byte and consume it when the copy succeeds. # C: O(1)
    pub fn tcp_recv_urgent<E>(&self, entry: &TcpEntry, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(), E>)
        -> Result<Option<u8>, E>
    {
        let mut conn = entry.conn.lock();
        let Some((_, byte)) = conn.peek_urgent() else { return Ok(None); };
        copy(&[byte])?;
        if !peek { conn.take_urgent(); }
        Ok(Some(byte))
    }

    /// Graceful close: emit FIN; demux drives the rest. # C: O(1)
    pub fn tcp_close(&self, entry: &TcpEntry) -> NetResult<()> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            let s = c.local_close().map_err(|_| NetError::Eio)?;
            (s, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        self.send_tcp_segment_in(entry.net_ns(), src, dst, &seg, tos, entry.bound_iface(),
            TcpTxPolicy::Entry(entry))
    }

    /// Apply Linux TCP shutdown; pending active open closes without FIN, send shutdown otherwise publishes one FIN.
    /// # C: O(log N) + optional segment xmit
    pub fn tcp_shutdown(&self, entry: &Arc<TcpEntry>, shut_write: bool) -> NetResult<bool> {
        let (segment, cancel_open, src, dst, tos) = {
            let mut conn = entry.conn.lock();
            let cancel_open = conn.state == crate::tcp_state::TcpState::SynSent;
            let segment = if cancel_open || shut_write {
                conn.shutdown_write().map_err(|_| NetError::Eio)?
            } else { None };
            (segment, cancel_open, conn.local.ip, conn.remote.ip, ecn_tos(&conn))
        };
        if cancel_open { self.tcp_disconnect_entry(entry); return Ok(true); }
        if let Some(segment) = segment {
            self.send_tcp_segment_in(entry.net_ns(), src, dst, &segment, tos, entry.bound_iface(),
                TcpTxPolicy::Entry(entry.as_ref()))?;
        }
        Ok(false)
    }

    /// F174: ICMP Destination Unreachable → SO_ERROR on origin sock.
    /// Implementation moved to stack_icmp.rs (1000-line cap).
    /// # C: O(payload)
    pub(crate) fn handle_icmp_error(&self, net_ns: u64, iface: NetIfaceId, offender: Ipv4Addr,
                                    kind: u8, code: u8, payload: &[u8]) {
        crate::stack_icmp::handle_error_in(self, net_ns, iface, offender, kind, code, payload)
    }

    /// F159: RTO scanner. Re-emits expired segs; drops conns past
    /// retry ceilings (SYN=6, data=15). # C: O(N_conns·retx_q).
    pub fn tcp_retx_tick(&self, now_ns: u64) {
        // Snapshot the conn list to keep the tcp_conns lock short.
        let table_sets: Vec<(u64, Arc<super::inet_tables::InetTables>)> = self.inet.lock().iter()
            .map(|(&net_ns, tables)| (net_ns, tables.clone())).collect();
        let table_sets: Vec<(network_namespace::NetworkNamespaceRef,
                             Arc<super::inet_tables::InetTables>)> = table_sets.into_iter()
            .filter_map(|(net_ns, tables)| {
                let owner = if net_ns == 0 { network_namespace::initial() }
                    else { network_namespace::lookup_u64(net_ns)? };
                Some((owner, tables))
            }).collect();
        let mut entries: Vec<(network_namespace::NetworkNamespaceRef,
                              Arc<super::inet_tables::InetTables>, TcpKey, Arc<TcpEntry>)> = Vec::new();
        for (owner, tables) in table_sets {
            let snapshot: Vec<(TcpKey, Arc<TcpEntry>)> = tables.tcp_conns.lock().iter()
                .map(|(key, entry)| (*key, entry.clone())).collect();
            entries.extend(snapshot.into_iter()
                .map(|(key, entry)| (owner.clone(), tables.clone(), key, entry)));
        }
        let mut to_drop: Vec<(Arc<super::inet_tables::InetTables>, TcpKey, Arc<TcpEntry>)>
            = Vec::new();
        // F161: 2*MSL linger before reclaiming a TIME_WAIT 4-tuple
        // (Linux tcp_fin_timeout default 60 s). Closed conns are
        // dropped immediately — no 4-tuple reservation needed once
        // both sides agree the connection is gone.
        const TW_TIMEOUT_NS: u64 = 60_000_000_000;
        for (_owner, tables, key, entry) in entries.iter() {
            // Per-entry: decide retx + drop under the conn lock,
            // collect segments to emit after dropping it.
            let (segs, abort, src, dst) = {
                let mut c = entry.conn.lock();
                // F161: TIME_WAIT timer + Closed-cleanup. Reap any
                // conn that has reached Closed, or has lingered in
                // TimeWait past 2*MSL. Stamp tw_start_ns on first
                // observation if zero.
                if c.state == crate::tcp_state::TcpState::Closed {
                    (Vec::new(), true, c.local.ip, c.remote.ip)
                } else if c.state == crate::tcp_state::TcpState::TimeWait {
                    if c.tw_start_ns == 0 { c.tw_start_ns = now_ns; }
                    if now_ns.saturating_sub(c.tw_start_ns) >= TW_TIMEOUT_NS {
                        c.state = crate::tcp_state::TcpState::Closed;
                        (Vec::new(), true, c.local.ip, c.remote.ip)
                    } else {
                        (Vec::new(), false, c.local.ip, c.remote.ip)
                    }
                } else if c.state == crate::tcp_state::TcpState::FinWait2
                    && c.linger2_expired(
                        if c.tw_start_ns == 0 { now_ns } else { c.tw_start_ns }, now_ns)
                {
                    // `TCP_LINGER2` bounds how long the orphan may wait for
                    // the peer's FIN; past it the connection is torn down
                    // rather than held open indefinitely.
                    if c.tw_start_ns == 0 { c.tw_start_ns = now_ns; }
                    c.state = crate::tcp_state::TcpState::Closed;
                    (Vec::new(), true, c.local.ip, c.remote.ip)
                } else if c.state == crate::tcp_state::TcpState::FinWait2 {
                    if c.tw_start_ns == 0 { c.tw_start_ns = now_ns; }
                    (Vec::new(), false, c.local.ip, c.remote.ip)
                } else if c.repair || c.retx_q.is_empty() {
                    (Vec::new(), false, c.local.ip, c.remote.ip)
                } else {
                    let front_is_syn = (c.retx_q.front().unwrap().flags
                        & crate::tcp_hdr::flags::SYN) != 0;
                    let max = if front_is_syn { c.syn_retries }
                        else { crate::tcp_conn::DATA_RETRIES_DEFAULT };
                    let max_retries = c.retx_q.iter().map(|s| s.retries).max().unwrap_or(0);
                    if max_retries >= max || c.user_timeout_expired(now_ns) {
                        // Give up on this connection. F163: surface as
                        // SO_ERROR = ETIMEDOUT so a getsockopt after
                        // async-connect's EPOLLOUT can report the cause.
                        c.state = crate::tcp_state::TcpState::Closed;
                        c.retx_q.clear();
                        let src = c.local.ip; let dst = c.remote.ip;
                        drop(c);
                        entry.set_error(syscall::errno::Errno::Etimedout as i32);
                        (Vec::new(), true, src, dst)
                    } else {
                        let segs = c.retransmit_due(now_ns);
                        (segs, false, c.local.ip, c.remote.ip)
                    }
                }
            };
            for s in &segs {
                let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, s, 0,
                    entry.bound_iface(), TcpTxPolicy::Entry(entry));
            }
            // A connection withheld by `TCP_DEFER_ACCEPT` whose window has now
            // run out becomes acceptable, so a blocked `accept` has to be
            // woken — nothing else will arrive to do it.
            let expired = {
                let mut c = entry.conn.lock();
                let due = c.defer_deadline_ns != 0 && now_ns >= c.defer_deadline_ns;
                if due { c.defer_deadline_ns = 0; }
                due
            };
            if expired && !entry.accepted.load(::core::sync::atomic::Ordering::Acquire) {
                if let Some(listener) = entry.passive_listener.as_ref()
                    .and_then(alloc::sync::Weak::upgrade)
                { listener.notify_acceptable(); }
            }
            // A ping-pong-mode socket held its acknowledgement back so it
            // could ride the application's reply; once `TCP_DELACK_MAX_US`
            // elapses it goes out on its own.
            let (delack, da_src, da_dst) = {
                let mut c = entry.conn.lock();
                (c.delayed_ack_due(now_ns), c.local.ip, c.remote.ip)
            };
            if let Some(s) = &delack {
                let _ = self.send_tcp_segment_in(entry.net_ns(), da_src, da_dst, s, 0,
                    entry.bound_iface(), TcpTxPolicy::Entry(entry));
            }
            // F193: keepalive probe scheduling. Idle for ka_idle_ns →
            // fire probes at ka_intvl_ns cadence; abort after ka_cnt_max.
            let (ka_seg, ka_abort, ka_src, ka_dst) = {
                let mut c = entry.conn.lock();
                let probe = c.keepalive_due(now_ns);
                let abort_ka = c.ka_count > c.ka_cnt_max;
                if abort_ka {
                    c.state = crate::tcp_state::TcpState::Closed;
                }
                let src = c.local.ip; let dst = c.remote.ip;
                drop(c);
                if abort_ka { entry.set_error(syscall::errno::Errno::Etimedout as i32); }
                (probe, abort_ka, src, dst)
            };
            if let Some(s) = &ka_seg {
                let _ = self.send_tcp_segment_in(entry.net_ns(), ka_src, ka_dst, s, 0,
                    entry.bound_iface(), TcpTxPolicy::Entry(entry));
            }
            if ka_abort {
                entry.release_backlog();
                to_drop.push((tables.clone(), *key, entry.clone()));
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
                continue;
            }
            if abort {
                entry.release_backlog();
                to_drop.push((tables.clone(), *key, entry.clone()));
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            } else if !segs.is_empty() {
                // Wake too — connect waiters might have been parked
                // forever otherwise on a successful retx that revives
                // the handshake.
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
            }
        }
        if !to_drop.is_empty() {
            for (tables, key, entry) in to_drop {
                super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &entry);
            }
        }
    }

    /// TCP demux. Look up an established connection by 4-tuple
    /// first; on miss, look for a matching listener and (on SYN)
    /// instantiate a new connection from it. Drives the matched
    /// TcpConn's `input`; xmit any returned response segment.
    /// # C: O(log N) lookup + O(payload) handler
    pub(crate) fn deliver_tcp_packet(&self, net_ns: u64, iface: NetIfaceId,
                    src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8], packet: &[u8])
        -> NetResult<()>
    {
        if seg.len() < TCP_HDR_MIN_LEN { return Err(NetError::Einval); }
        let hdr = match crate::tcp_hdr::parse_ip(seg, src_ip, dst_ip) {
            Ok(h) => h, Err(_) => return Ok(()),
        };
        let key = TcpKey {
            local_ip: dst_ip, local_port: hdr.dst_port,
            remote_ip: src_ip, remote_port: hdr.src_port,
        };
        let tables = self.inet_tables(net_ns);
        // Established-conn lookup first.
        let entry = {
            let g = tables.tcp_conns.lock();
            g.get(&key).cloned()
        };
        if let Some(entry) = entry {
            if entry.bound_iface().is_some_and(|id| id != iface) { return Ok(()); }
            let observed_state = entry.conn.lock().state;
            let passive_listener = if observed_state == crate::tcp_state::TcpState::SynRecv {
                entry.passive_listener.as_ref().and_then(alloc::sync::Weak::upgrade)
            } else { None };
            let filter = passive_listener.as_ref().map(|listener| &listener.bpf_filter)
                .unwrap_or(&entry.bpf_filter);
            let protocol = match dst_ip {
                IpAddr::V4(_) => crate::addr::eth_p::IPV4,
                IpAddr::V6(_) => crate::addr::eth_p::IPV6,
            };
            if !crate::cgroup_bpf::ingress(&entry.owner, packet, protocol, iface) {
                return Ok(());
            }
            let Some(keep) = crate::bpf_filter::retained_tcp_len(
                filter.verdict_with_context(crate::bpf_filter::FilterContext {
                    packet: seg, protocol, ifindex: Some(iface.raw()),
                    pay_offset: hdr.payload_offset() as u32,
                    hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                        .map_or(0, |dev| dev.hardware_type()),
                }), seg,
            ) else { return Ok(()); };
            let seg = &seg[..keep];
            // F158: wake on either recv_buf growth or terminal state
            let (_pre_len, pre_state, input, _post_len, post_state) = {
                let mut c = entry.conn.lock();
                let pre_len = c.recv_buf.len();
                let pre_state = c.state;
                if pre_state == crate::tcp_state::TcpState::SynRecv {
                    if let Some(listener) = passive_listener.as_ref() {
                        entry.bpf_filter.inherit_from(&listener.bpf_filter);
                    }
                }
                let input = c.input_prevalidated(src_ip, dst_ip, seg);
                (pre_len, pre_state, input, c.recv_buf.len(), c.state)
            };
            let pre_syn = pre_state == crate::tcp_state::TcpState::SynSent;
            let resp = match input {
                Ok(resp) => resp,
                Err(crate::tcp_conn::TcpConnError::Reset) => {
                    let eno = if pre_syn { syscall::errno::Errno::Econnrefused }
                        else { syscall::errno::Errno::Econnreset };
                    entry.set_error(eno as i32);
                    None
                }
                Err(_) => return Err(NetError::Einval),
            };
            if pre_state == crate::tcp_state::TcpState::SynRecv
                && post_state == crate::tcp_state::TcpState::Established
            {
                let Some(listener) = passive_listener else { return Ok(()); };
                // `TCP_DEFER_ACCEPT`: a handshake that completed without data
                // is queued but withheld from `accept` until the client sends
                // something or the window the listener asked for runs out.
                {
                    let mut c = entry.conn.lock();
                    if c.recv_buf.is_empty() {
                        let window = listener.defer_window_secs.load(
                            ::core::sync::atomic::Ordering::Acquire);
                        c.defer_deadline_ns = crate::tcp_conn::defer::deadline_ns(
                            window, crate::tcp_conn::ka_now_ns());
                    }
                }
                if !entry.promote_to_accept_backlog() {
                    entry.release_syn_backlog();
                    entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
                    super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &entry);
                    return Ok(());
                }
                if !listener.enqueue_accepted(entry.clone()) {
                    entry.release_backlog();
                    entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
                    super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &entry);
                    return Ok(());
                }
            }
            // Data on a connection withheld by `TCP_DEFER_ACCEPT` is what the
            // listener was waiting for: the child becomes acceptable now, and
            // the first read on the accepted socket returns these bytes.
            {
                let deferred = {
                    let mut c = entry.conn.lock();
                    let due = c.defer_deadline_ns != 0 && !c.recv_buf.is_empty();
                    if due { c.defer_deadline_ns = 0; }
                    due
                };
                if deferred {
                    if let Some(listener) = entry.passive_listener.as_ref()
                        .and_then(alloc::sync::Weak::upgrade)
                    { listener.notify_acceptable(); }
                }
            }
            if let Some(r) = resp {
                self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &r, 0, entry.bound_iface(),
                    TcpTxPolicy::Entry(&entry))?;
            }
            // F175: post-input output drain. ACK that clears retx_q
            // unblocks Nagle-held sends; pump them out now. Use
            // nodelay=true because the Nagle condition is already
            // expressed by retx_q.is_empty(); calling with true just
            // skips the redundant guard.
            let drain_segs = {
                let mut c = entry.conn.lock();
                let (src, dst, tos) = (c.local.ip, c.remote.ip, ecn_tos(&c));
                let segs = c.output(1500, true, false);
                (segs, src, dst, tos)
            };
            let (segs, src, dst, tos) = drain_segs;
            for s in &segs {
                self.send_tcp_segment_in(net_ns, src, dst, s, tos, entry.bound_iface(),
                    TcpTxPolicy::Entry(&entry))?;
            }
            stamp_last_sent(&entry, segs.len());
            // F159+F181a: wake conn rx + targeted epoll.
            #[cfg(target_os = "oxide-kernel")]
            {
                let _ = post_state;
                super::tcp_rx_trace::deliver(hdr.dst_port, _pre_len, _post_len,
                    entry.rx_waiters.has_waiters());
                entry.rx_waiters.wake_all();
                let slot = entry.poll_subs.lock().clone();
                if let Some(weak) = slot {
                    if let Some(s) = weak.upgrade() { s.notify(); }
                }
            }
            return Ok(());
        }
        // B1618: the passive-open branch lives in its own function so its locals —
        // a whole `TcpConn`, the child filter/PMTU arcs, the reuseport bucket — do not
        // share a frame with the established-connection branch above, which is the one
        // that continues into transmit. Linux splits the same way (`noinline_for_stack`).
        self.deliver_tcp_to_listener(net_ns, iface, src_ip, dst_ip, seg, packet, &hdr, key, &tables)
    }
}
#[cfg(test)]
#[path = "tcp_timer_tests.rs"]
mod timer_tests;
