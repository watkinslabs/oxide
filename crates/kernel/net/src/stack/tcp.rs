use super::*;

use super::tcp_tx::TcpTxPolicy;

impl NetStack {
    /// Open an active TCP connection from `local` to `remote`.
    /// Emits the SYN, parks the half-open conn in the demux table.
    /// Caller (`sock::connect`) parks on `entry.rx_waiters` for the
    /// SYN-ACK; `tcp_retx_tick` handles SYN retransmission on RTO.
    /// # C: O(log N) demux insert + 1 segment xmit
    pub fn tcp_connect(&self, local_ip: Ipv4Addr, local_port: u16,
                        remote_ip: Ipv4Addr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_ip(
            IpAddr::V4(local_ip), local_port,
            IpAddr::V4(remote_ip), remote_port,
        )
    }

    /// F180b: address-family-aware active open (v4+v6). # C: O(log N).
    pub fn tcp_connect_ip(&self, local_ip: IpAddr, local_port: u16,
                           remote_ip: IpAddr, remote_port: u16)
        -> NetResult<Arc<TcpEntry>>
    {
        self.tcp_connect_ip_bound(local_ip, local_port, remote_ip, remote_port, None,
            Arc::new(crate::SocketError::new()))
    }

    /// Remove a connected TCP entry from the demux table. # C: O(log N)
    pub fn tcp_disconnect_entry(&self, entry: &Arc<TcpEntry>) {
        let key = {
            let c = entry.conn.lock();
            TcpKey {
                local_ip: c.local.ip, local_port: c.local.port,
                remote_ip: c.remote.ip, remote_port: c.remote.port,
            }
        };
        let tables = self.inet_tables(entry.net_ns());
        super::tcp_listener::remove_tcp_entry_exact(&tables, &key, entry);
        if let Some(bind) = entry.bind.as_ref() {
            bind.role.store(TCP_BIND_BOUND, ::core::sync::atomic::Ordering::Release);
        }
    }

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
        entry.conn.lock().recv_with_offset_oob(max, peek, offset, inline, copy)
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
                } else if c.retx_q.is_empty() {
                    (Vec::new(), false, c.local.ip, c.remote.ip)
                } else {
                    let front_is_syn = (c.retx_q.front().unwrap().flags
                        & crate::tcp_hdr::flags::SYN) != 0;
                    let max = if front_is_syn { 6 } else { 15 };
                    let max_retries = c.retx_q.iter().map(|s| s.retries).max().unwrap_or(0);
                    if max_retries >= max {
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
    pub(crate) fn deliver_tcp(&self, net_ns: u64, iface: NetIfaceId,
                    src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8])
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
        // Listener path: only SYNs spawn new conns.
        if (hdr.flags & tcp_flags::SYN) == 0 { return Ok(()); }
        let bucket = {
            let g = tables.tcp_listens.lock();
            super::tcp_listener::lookup_listen_bucket(&g, dst_ip, hdr.dst_port)
        };
        let Some(bucket) = bucket else { return Ok(()); };
        // F192: SO_REUSEPORT hash distribute by 4-tuple. Single-entry
        // bucket -> idx 0.
        let idx = super::tcp_listener::select_reuseport_listener(
            src_ip, hdr.src_port, hdr.dst_port, bucket.len());
        let mut listener = None;
        for off in 0..bucket.len() {
            let cand = bucket[(idx + off) % bucket.len()].clone();
            if cand.bound_iface().is_none_or(|id| id == iface) {
                listener = Some(cand);
                break;
            }
        }
        let Some(listener) = listener else { return Ok(()); };
        let protocol = match dst_ip {
            IpAddr::V4(_) => crate::addr::eth_p::IPV4,
            IpAddr::V6(_) => crate::addr::eth_p::IPV6,
        };
        let Some(keep) = crate::bpf_filter::retained_tcp_len(
            listener.bpf_filter.verdict_with_context(crate::bpf_filter::FilterContext {
                packet: seg, protocol, ifindex: Some(iface.raw()),
                pay_offset: hdr.payload_offset() as u32,
                hatype: self.ifaces.lookup_in_ns(iface, net_ns)
                    .map_or(0, |dev| dev.hardware_type()),
            }), seg,
        ) else { return Ok(()); };
        let seg = &seg[..keep];
        // F180b: synthesise a per-conn local endpoint that pins the
        // wildcard listener to the actual delivery dst — so outbound
        // segments carry a real src, not 0.0.0.0/::.
        let mut local_ep = listener.local;
        if local_ep.ip == IpAddr::V4(Ipv4Addr::ANY) || local_ep.ip == IpAddr::V6(Ipv6Addr::ANY) {
            local_ep.ip = dst_ip;
        }
        // F192: enforce listen backlog. Drop the SYN on the floor
        // when accept_q is already at cap — peer retries naturally
        // via SYN retx.
        if !listener.reserve_backlog() { return Ok(()); }
        let mut new_conn = TcpConn::new_listener(local_ep);
        // F184: SYN-ACK we're about to build advertises our MSS too.
        let bound = listener.bound_iface();
        let ip_mode = listener.ip_mtu_discover.load(
            ::core::sync::atomic::Ordering::Acquire);
        let ipv6_mode = listener.ipv6_mtu_discover.load(
            ::core::sync::atomic::Ordering::Acquire);
        new_conn.own_mss = self.mss_for_dst_on_iface_pmtu_modes_in(
            net_ns, src_ip, bound, ip_mode, ipv6_mode);
        let resp = match new_conn.input_prevalidated(src_ip, dst_ip, seg) {
            Ok(resp) => resp,
            Err(_) => {
                listener.syn_backlog_used.fetch_sub(1, ::core::sync::atomic::Ordering::AcqRel);
                return Err(NetError::Einval);
            }
        };
        let child_filter = Arc::new(crate::bpf_filter::SocketFilter::inherited(
            &listener.bpf_filter));
        let child_ip_pmtu = Arc::new(::core::sync::atomic::AtomicI32::new(
            listener.ip_mtu_discover.load(::core::sync::atomic::Ordering::Acquire)));
        let child_ipv6_pmtu = Arc::new(::core::sync::atomic::AtomicI32::new(
            listener.ipv6_mtu_discover.load(::core::sync::atomic::Ordering::Acquire)));
        let new_entry = Arc::new(TcpEntry::new_bound_with_filter_listener(
            new_conn, Arc::new(crate::SocketError::new()), Some(listener.bind.clone()), child_filter,
            child_ip_pmtu, child_ipv6_pmtu,
            Some(Arc::downgrade(&listener)),
        ));
        if !super::tcp_listener::publish_passive_child(&tables, &listener, key, &new_entry) {
            return Ok(());
        }
        if let Some(r) = resp {
            if let Err(error) = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &r, 0, bound,
                TcpTxPolicy::Listener(&listener))
            {
                super::tcp_listener::remove_tcp_entry_exact(&tables, &key, &new_entry);
                new_entry.release_backlog();
                new_entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tcp_timer_tests.rs"]
mod timer_tests;
