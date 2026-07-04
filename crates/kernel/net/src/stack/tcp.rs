use super::*;

impl NetStack {
    /// Open v4 listener at (ip,port). Eaddrinuse if taken or TIME_WAIT
    /// conflict (unless SO_REUSEADDR). # C: O(log N + N_conns).
    pub fn tcp_listen(&self, local_ip: Ipv4Addr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip(IpAddr::V4(local_ip), local_port, reuseaddr)
    }

    /// F180b: address-family-aware listen (v4 + v6). # C: O(log N).
    pub fn tcp_listen_ip(&self, local_ip: IpAddr, local_port: u16, reuseaddr: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        self.tcp_listen_ip_with(local_ip, local_port, reuseaddr, false)
    }

    /// F192: SO_REUSEPORT-aware listen. When `reuseport=true`, a
    /// duplicate (ip,port) registration appends to the per-key Vec
    /// instead of failing; deliver_tcp hash-distributes SYNs across
    /// the bucket by 4-tuple. # C: O(log N).
    pub fn tcp_listen_ip_with(&self, local_ip: IpAddr, local_port: u16,
                                reuseaddr: bool, reuseport: bool)
        -> NetResult<Arc<TcpListenEntry>>
    {
        let key = TcpListenKey { local_ip, local_port };
        let mut g = self.tcp_listens.lock();
        if g.contains_key(&key) && !reuseport { return Err(NetError::Eaddrinuse); }
        if !reuseaddr {
            let conns = self.tcp_conns.lock();
            let any_v4 = IpAddr::V4(Ipv4Addr::ANY);
            let any_v6 = IpAddr::V6(crate::addr::Ipv6Addr::ANY);
            let conflict = conns.iter().any(|(k, e)| {
                k.local_port == local_port
                    && (k.local_ip == local_ip
                        || local_ip == any_v4 || local_ip == any_v6)
                    && e.conn.lock().state == crate::tcp_state::TcpState::TimeWait
            });
            if conflict { return Err(NetError::Eaddrinuse); }
        }
        let entry = Arc::new(TcpListenEntry::new(
            Endpoint { ip: local_ip, port: local_port },
        ));
        g.entry(key).or_default().push(entry.clone());
        Ok(entry)
    }

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
        self.tcp_connect_ip_bound(local_ip, local_port, remote_ip, remote_port, None)
    }

    /// Pop one accepted connection from listener's backlog. # C: O(1)
    pub fn tcp_accept(&self, listener: &TcpListenEntry) -> Option<Arc<TcpEntry>> {
        listener.accept_q.lock().pop_front()
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
            self.send_l4_over_ip_tos_bound(src, dst, IpProto::Tcp, s, tos, entry.bound_iface())?;
        }
        // F159: stamp the last N retx_q entries (one per emitted segment)
        // with the actual xmit time.
        stamp_last_sent(entry, n);
        Ok(accepted)
    }

    /// Application drains up to `max` bytes from the recv buffer.
    /// # C: O(min(max, recv_buf.len()))
    pub fn tcp_recv(&self, entry: &TcpEntry, max: usize) -> Vec<u8> {
        entry.conn.lock().recv(max)
    }

    /// Graceful close: emit FIN; demux drives the rest. # C: O(1)
    pub fn tcp_close(&self, entry: &TcpEntry) -> NetResult<()> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            let s = c.local_close().map_err(|_| NetError::Eio)?;
            (s, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        self.send_l4_over_ip_tos_bound(src, dst, IpProto::Tcp, &seg, tos, entry.bound_iface())
    }

    /// F174: ICMP Destination Unreachable → SO_ERROR on origin sock.
    /// Implementation moved to stack_icmp.rs (1000-line cap).
    /// # C: O(payload)
    pub(crate) fn handle_dest_unreach(&self, code: u8, payload: &[u8]) {
        crate::stack_icmp::handle_dest_unreach(self, code, payload)
    }

    /// F159: RTO scanner. Re-emits expired segs; drops conns past
    /// retry ceilings (SYN=6, data=15). # C: O(N_conns·retx_q).
    pub fn tcp_retx_tick(&self, now_ns: u64) {
        // Snapshot the conn list to keep the tcp_conns lock short.
        let entries: Vec<(TcpKey, Arc<TcpEntry>)> = {
            let g = self.tcp_conns.lock();
            g.iter().map(|(k, v)| (*k, v.clone())).collect()
        };
        let mut to_drop: Vec<TcpKey> = Vec::new();
        // F161: 2*MSL linger before reclaiming a TIME_WAIT 4-tuple
        // (Linux tcp_fin_timeout default 60 s). Closed conns are
        // dropped immediately — no 4-tuple reservation needed once
        // both sides agree the connection is gone.
        const TW_TIMEOUT_NS: u64 = 60_000_000_000;
        for (key, entry) in entries.iter() {
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
                        if c.error_eno == 0 {
                            c.error_eno = syscall::errno::Errno::Etimedout as i32;
                        }
                        c.state = crate::tcp_state::TcpState::Closed;
                        c.retx_q.clear();
                        (Vec::new(), true, c.local.ip, c.remote.ip)
                    } else {
                        let segs = c.retransmit_due(now_ns);
                        (segs, false, c.local.ip, c.remote.ip)
                    }
                }
            };
            for s in &segs {
                let _ = self.send_l4_over_ip_bound(src, dst, IpProto::Tcp, s, entry.bound_iface());
            }
            // F193: keepalive probe scheduling. Idle for ka_idle_ns →
            // fire probes at ka_intvl_ns cadence; abort after ka_cnt_max.
            let (ka_seg, ka_abort, ka_src, ka_dst) = {
                let mut c = entry.conn.lock();
                let probe = c.keepalive_due(now_ns);
                let abort_ka = c.ka_count > c.ka_cnt_max;
                if abort_ka && c.error_eno == 0 {
                    c.error_eno = syscall::errno::Errno::Etimedout as i32;
                    c.state = crate::tcp_state::TcpState::Closed;
                }
                (probe, abort_ka, c.local.ip, c.remote.ip)
            };
            if let Some(s) = &ka_seg {
                let _ = self.send_l4_over_ip_bound(ka_src, ka_dst, IpProto::Tcp, s, entry.bound_iface());
            }
            if ka_abort {
                to_drop.push(*key);
                #[cfg(target_os = "oxide-kernel")]
                entry.rx_waiters.wake_all();
                continue;
            }
            if abort {
                to_drop.push(*key);
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
            let mut g = self.tcp_conns.lock();
            for k in to_drop { g.remove(&k); }
        }
    }

    /// TCP demux. Look up an established connection by 4-tuple
    /// first; on miss, look for a matching listener and (on SYN)
    /// instantiate a new connection from it. Drives the matched
    /// TcpConn's `input`; xmit any returned response segment.
    /// # C: O(log N) lookup + O(payload) handler
    pub(crate) fn deliver_tcp(&self, iface: NetIfaceId,
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
        // Established-conn lookup first.
        let entry = {
            let g = self.tcp_conns.lock();
            g.get(&key).cloned()
        };
        if let Some(entry) = entry {
            if entry.bound_iface().is_some_and(|id| id != iface) { return Ok(()); }
            // F158: wake on either recv_buf growth or terminal state
            let (_pre_len, _pre_state) = {
                let c = entry.conn.lock();
                (c.recv_buf.len(), c.state)
            };
            let resp = entry.conn.lock().input(src_ip, dst_ip, seg)
                .map_err(|_| NetError::Einval)?;
            let (_post_len, _post_state) = {
                let c = entry.conn.lock();
                (c.recv_buf.len(), c.state)
            };
            if let Some(r) = resp {
                self.send_l4_over_ip_bound(dst_ip, src_ip, IpProto::Tcp, &r, entry.bound_iface())?;
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
                self.send_l4_over_ip_tos_bound(src, dst, IpProto::Tcp, s, tos, entry.bound_iface())?;
            }
            stamp_last_sent(&entry, segs.len());
            // F159+F181a: wake conn rx + targeted epoll.
            #[cfg(target_os = "oxide-kernel")]
            {
                let _ = (_pre_len, _post_len, _post_state);
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
        let lkey = TcpListenKey { local_ip: dst_ip, local_port: hdr.dst_port };
        let any_for_family = match dst_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::ANY),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::ANY),
        };
        let bucket = {
            let g = self.tcp_listens.lock();
            g.get(&lkey).cloned()
                .or_else(|| g.get(&TcpListenKey { local_ip: any_for_family, local_port: hdr.dst_port }).cloned())
        };
        let bucket = match bucket { Some(b) if !b.is_empty() => b, _ => return Ok(()) };
        // F192: SO_REUSEPORT hash distribute by 4-tuple. Single-entry
        // bucket → idx 0.
        let idx = if bucket.len() == 1 { 0 } else {
            let mut h: u32 = 0;
            let v4_oct;
            let v6_arr;
            let bytes: &[u8] = match src_ip {
                IpAddr::V4(a) => { v4_oct = a.octets(); &v4_oct[..] }
                IpAddr::V6(a) => { v6_arr = a.0;         &v6_arr[..] }
            };
            for b in bytes { h = h.wrapping_mul(31).wrapping_add(*b as u32); }
            h = h.wrapping_add(hdr.src_port as u32).wrapping_add(hdr.dst_port as u32);
            (h as usize) % bucket.len()
        };
        let mut listener = None;
        for off in 0..bucket.len() {
            let cand = bucket[(idx + off) % bucket.len()].clone();
            if cand.bound_iface().is_none_or(|id| id == iface) {
                listener = Some(cand);
                break;
            }
        }
        let Some(listener) = listener else { return Ok(()); };
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
        {
            let q = listener.accept_q.lock();
            let cap = listener.backlog.load(::core::sync::atomic::Ordering::Acquire);
            if q.len() >= cap { return Ok(()); }
        }
        let mut new_conn = TcpConn::new_listener(local_ep);
        // F184: SYN-ACK we're about to build advertises our MSS too.
        let bound = listener.bound_iface();
        new_conn.own_mss = self.mss_for_dst_on_iface(src_ip, bound);
        let resp = new_conn.input(src_ip, dst_ip, seg)
            .map_err(|_| NetError::Einval)?;
        let new_entry = Arc::new(TcpEntry::new(new_conn));
        new_entry.set_bound_iface(bound);
        self.tcp_conns.lock().insert(key, new_entry.clone());
        listener.accept_q.lock().push_back(new_entry);
        if let Some(r) = resp {
            self.send_l4_over_ip_bound(dst_ip, src_ip, IpProto::Tcp, &r, bound)?;
        }
        // F160: wake any blocking accept() parked on this listener.
        #[cfg(target_os = "oxide-kernel")]
        {
            listener.accept_waiters.wake_all();
            // F181a: targeted epoll wake for the listener fd.
            let slot = listener.poll_subs.lock().clone();
            if let Some(weak) = slot {
                if let Some(s) = weak.upgrade() { s.notify(); }
            }
        }
        Ok(())
    }
}
