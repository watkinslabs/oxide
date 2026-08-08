use super::*;

use super::tcp_tx::TcpTxPolicy;

mod send;

impl NetStack {
    /// Emit one TCP urgent byte with the URG flag and pointer. # C: O(1) xmit
    pub fn tcp_send_urgent(&self, entry: &Arc<TcpEntry>, byte: u8) -> NetResult<usize> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            if !c.state.is_established() { return Err(NetError::Epipe); }
            let seg = c.send_urgent(byte);
            (seg, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        let result = self.send_tcp_segment_in(entry.net_ns(), src, dst, &seg, tos,
            entry.bound_iface(), TcpTxPolicy::Entry(entry));
        if result.is_ok() { stamp_last_sent(entry, 1); }
        self.refresh_tcp_timers(entry);
        result?;
        Ok(1)
    }

    /// Application drains up to `max` bytes from the recv buffer.
    /// # C: O(min(max, recv_buf.len))
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
        // Linux `tcp_cleanup_rbuf`: "We send an
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
    pub fn tcp_close(&self, entry: &Arc<TcpEntry>) -> NetResult<()> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            let s = c.local_close().map_err(|_| NetError::Eio)?;
            (s, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        super::tcp_fastopen::drain_client(self, entry, crate::tcp_conn::ka_now_ns());
        let result = self.send_tcp_segment_in(entry.net_ns(), src, dst, &seg, tos,
            entry.bound_iface(), TcpTxPolicy::Entry(entry));
        if result.is_ok() { stamp_last_sent(entry, 1); }
        self.refresh_tcp_timers(entry);
        result?;
        Ok(())
    }

    /// Publish an active Fast Open result produced by socket teardown.
    /// # C: O(log N)
    pub(crate) fn drain_tcp_fastopen_client(&self, entry: &Arc<TcpEntry>) {
        super::tcp_fastopen::drain_client(self, entry, crate::tcp_conn::ka_now_ns());
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
            let result = self.send_tcp_segment_in(entry.net_ns(), src, dst, &segment, tos,
                entry.bound_iface(), TcpTxPolicy::Entry(entry.as_ref()));
            if result.is_ok() { stamp_last_sent(entry, 1); }
            self.refresh_tcp_timers(entry);
            result?;
        }
        self.refresh_tcp_timers(entry);
        Ok(false)
    }

    /// F174: ICMP Destination Unreachable → SO_ERROR on origin sock.
    /// Implementation moved to stack_icmp.rs (1000-line cap).
    /// # C: O(payload)
    pub(crate) fn handle_icmp_error(&self, net_ns: u64, iface: NetIfaceId, offender: Ipv4Addr,
                                    kind: u8, code: u8, payload: &[u8]) {
        crate::stack_icmp::handle_error_in(self, net_ns, iface, offender, kind, code, payload)
    }

    /// Hosted-test snapshot used to drive compatibility timer helpers.
    /// Production callbacks own exactly one connection and never call this.
    /// # C: O(N_conns)
    #[cfg(test)]
    pub(crate) fn tcp_tick_entries(&self) -> Vec<(network_namespace::NetworkNamespaceRef,
        Arc<super::inet_tables::InetTables>, TcpKey, Arc<TcpEntry>)> {
        let table_sets: Vec<(u64, Arc<super::inet_tables::InetTables>)> = self.inet.lock().iter()
            .map(|(&net_ns, entry)| (net_ns, entry.tables.clone())).collect();
        let table_sets: Vec<(network_namespace::NetworkNamespaceRef,
                             Arc<super::inet_tables::InetTables>)> = table_sets.into_iter()
            .filter_map(|(net_ns, tables)| {
                let owner = if net_ns == 0 { network_namespace::initial() }
                    else { network_namespace::lookup_u64(net_ns)? };
                Some((owner, tables))
            }).collect();
        let mut entries = Vec::new();
        for (owner, tables) in table_sets {
            let snapshot: Vec<(TcpKey, Arc<TcpEntry>)> = tables.tcp_conns.lock().iter()
                .map(|(key, entry)| (*key, entry.clone())).collect();
            entries.extend(snapshot.into_iter()
                .map(|(key, entry)| (owner.clone(), tables.clone(), key, entry)));
        }
        entries
    }

    /// TCP demux. Look up an established connection by 4-tuple
    /// first; on miss, look for a matching listener and (on SYN)
    /// instantiate a new connection from it. Drives the matched
    /// TcpConn's `input`; xmit any returned response segment.
    /// # C: O(log N) lookup + O(payload) handler
    #[cfg(test)]
    pub(crate) fn deliver_tcp_packet(&self, net_ns: u64, iface: NetIfaceId,
                    src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8], packet: &[u8])
        -> NetResult<()>
    {
        // A hop limit of the maximum admits every socket, which is what an
        // adapter with no header in hand must supply.
        self.deliver_tcp_packet_hop(net_ns, iface, src_ip, dst_ip, seg, packet, u8::MAX)
    }

    /// Demultiplex one TCP segment, carrying the hop limit its IP header
    /// arrived with so a socket demanding a minimum can refuse it.
    /// # C: O(log N + payload)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn deliver_tcp_packet_hop(&self, net_ns: u64, iface: NetIfaceId,
                    src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8], packet: &[u8], hop: u8)
        -> NetResult<()>
    {
        let ipv6 = matches!(dst_ip, IpAddr::V6(_));
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
            // The generalized hop-limit check runs before the segment reaches
            // the state machine, and drops silently.
            if entry.min_hop.refuses(hop, ipv6) { return Ok(()); }
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
            // The listener-side check a segment for a half-open request passes
            // before any state machine sees it: a deferring listener drops the
            // bare acknowledgement, so the request stays in SYN-RECV and the
            // peer's handshake is left unconfirmed.
            if let Some(listener) = passive_listener.as_ref() {
                if super::tcp_reqsk::defers_segment(&entry, listener, &hdr, seg) {
                    return Ok(());
                }
            }
            // F158: wake on either recv_buf growth or terminal state
            let (_pre_len, pre_state, input, _post_len, post_state, fastopen_child, urgent) = {
                let mut c = entry.conn.lock();
                let pre_len = c.recv_buf.len;
                let pre_state = c.state;
                let pre_urg = c.peek_urgent();
                let fastopen_child = c.fastopen_child;
                if pre_state == crate::tcp_state::TcpState::SynRecv {
                    if let Some(listener) = passive_listener.as_ref() {
                        entry.bpf_filter.inherit_from(&listener.bpf_filter);
                    }
                }
                let input = c.input_prevalidated(src_ip, dst_ip, seg);
                let urgent = crate::sock::oob_notify::urgent_arrived(pre_urg, c.peek_urgent());
                (pre_len, pre_state, input, c.recv_buf.len, c.state, fastopen_child, urgent)
            };
            // Tell the world about a new urgent pointer (Linux
            // `sk_send_sigurg` from the urgent-pointer check): an
            // unconditional `SIGURG` to the receiving description's `f_owner`.
            // The `F_SETSIG` half rides the readiness wake below, whose mask
            // now carries `POLL_PRI`, and is not raised here.
            if urgent { crate::sock::oob_notify::sk_send_sigurg(entry.owner_file()); }
            super::tcp_fastopen::drain_client(self, &entry, crate::tcp_conn::ka_now_ns());
            let pre_syn = pre_state == crate::tcp_state::TcpState::SynSent;
            let resp = match input {
                Ok(resp) => resp,
                Err(crate::tcp_conn::TcpConnError::Reset) => {
                    let eno = if pre_syn { syscall::errno::Errno::Econnrefused }
                        else { syscall::errno::Errno::Econnreset };
                    if matches!(pre_state, crate::tcp_state::TcpState::SynSent
                        | crate::tcp_state::TcpState::SynRecv)
                    {
                        crate::mib::bump(net_ns, crate::mib::Mib::TcpAttemptFails);
                    } else if matches!(pre_state, crate::tcp_state::TcpState::Established
                        | crate::tcp_state::TcpState::CloseWait)
                    {
                        crate::mib::bump(net_ns, crate::mib::Mib::TcpEstabResets);
                    }
                    entry.set_error(eno as i32);
                    // A fast-open connection the peer reset is what a forged
                    // source address produces, so its charge against the
                    // listener's bound outlives it.
                    entry.release_fastopen_qlen(true);
                    None
                }
                Err(_) => return Err(NetError::Einval),
            };
            if pre_state == crate::tcp_state::TcpState::SynRecv
                && post_state == crate::tcp_state::TcpState::Established
                && fastopen_child
            {
                // The handshake is finished, so the charge this child held
                // against its listener's fast-open bound is given back. It is
                // already in the accept queue and must not be published twice.
                entry.release_fastopen_qlen(false);
            } else if pre_state == crate::tcp_state::TcpState::SynRecv
                && post_state == crate::tcp_state::TcpState::Established
            {
                let Some(listener) = passive_listener else { return Ok(()); };
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
            if let Some(r) = resp {
                if let Err(error) = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &r, 0,
                    entry.bound_iface(), TcpTxPolicy::Entry(&entry))
                {
                    self.refresh_tcp_timers(&entry);
                    return Err(error);
                }
            }
            // F175: post-input output drain. ACK that clears retx_q
            // unblocks Nagle-held sends; pump them out now. Use
            // nodelay=true because the Nagle condition is already
            // expressed by retx_q.is_empty(); calling with true just
            // skips the redundant guard.
            let drain_segs = {
                let mut c = entry.conn.lock();
                let (src, dst, tos) = (c.local.ip, c.remote.ip, ecn_tos(&c));
                let max_pacing_rate = entry.max_pacing_rate.load(::core::sync::atomic::Ordering::Acquire);
                let now_ns = crate::tcp_conn::ka_now_ns();
                let segs = if c.pacing_ready_at(now_ns, max_pacing_rate) {
                    c.output_limit(1500, true, false,
                        if max_pacing_rate == u64::MAX { usize::MAX } else { 1 })
                } else { Vec::new() };
                (segs, src, dst, tos, max_pacing_rate, now_ns)
            };
            let (segs, src, dst, tos, max_pacing_rate, now_ns) = drain_segs;
            for s in &segs {
                if let Err(error) = self.send_tcp_segment_in(net_ns, src, dst, s, tos,
                    entry.bound_iface(), TcpTxPolicy::Entry(&entry))
                {
                    self.refresh_tcp_timers(&entry);
                    return Err(error);
                }
            }
            stamp_last_sent(&entry, segs.len());
            if !segs.is_empty() {
                let bytes = entry.conn.lock().retx_q.back().map_or(0, |seg| seg.payload.len());
                entry.conn.lock().note_paced_output_at(now_ns, bytes, max_pacing_rate);
            }
            self.refresh_tcp_timers(&entry);
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
        self.deliver_tcp_to_listener(net_ns, iface, src_ip, dst_ip, seg, packet, &hdr, key,
            &tables, hop, ipv6)
    }
}
#[cfg(test)]
#[path = "tcp_timer_tests.rs"]
mod timer_tests;
#[cfg(test)]
#[path = "tcp_urgent_tests.rs"]
mod urgent_tests;
