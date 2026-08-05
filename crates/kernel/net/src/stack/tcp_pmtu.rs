use super::*;

const IPV4_TCP_OVERHEAD: u32 = 40;

fn seq_before(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) < 0 }

fn seq_after(a: u32, b: u32) -> bool { seq_before(b, a) }

/// The MSS a learned path MTU leaves this connection, once the sticky option
/// area it prepends to every segment is charged. # C: O(1)
fn ipv4_tcp_mss(path_mtu: u32, ext_hdr_len: u16) -> u16 {
    crate::tcp_ext_hdr::subtract_ext_hdr(
        path_mtu.saturating_sub(IPV4_TCP_OVERHEAD).min(u16::MAX as u32) as u16,
        ext_hdr_len)
}

impl TcpEntry {
    /// Validate a frag-needed quote against sent sequence space. # C: O(1)
    pub(crate) fn accepts_frag_needed(&self, quoted_seq: u32) -> bool {
        let c = self.conn.lock();
        c.state != crate::tcp_state::TcpState::Closed
            && !seq_before(quoted_seq, c.snd_una) && !seq_after(quoted_seq, c.snd_nxt)
    }

    /// True when Linux permits this socket to update route PMTU state. # C: O(1)
    pub(crate) fn accepts_pmtu_update(&self) -> bool {
        let mode = self.ip_mtu_discover.load(::core::sync::atomic::Ordering::Acquire);
        crate::uapi::ip_pmtudisc_accepts_pmtu(mode)
    }

    /// True when Linux TCP responds to frag-needed by reducing its MSS. # C: O(1)
    pub(crate) fn reduces_mss_for_frag_needed(&self) -> bool {
        let mode = self.ip_mtu_discover.load(::core::sync::atomic::Ordering::Acquire);
        matches!(mode, crate::uapi::IP_PMTUDISC_WANT
            | crate::uapi::IP_PMTUDISC_DO | crate::uapi::IP_PMTUDISC_PROBE)
    }
}

impl TcpConn {
    fn resegment_for_pmtu(&mut self, mss: u16, now_ns: u64) -> Vec<Vec<u8>> {
        let current = if self.own_mss == 0 { crate::tcp_conn::OWN_MSS_DEFAULT } else { self.own_mss };
        if mss >= current { return Vec::new(); }
        self.own_mss = mss;
        let mut old = ::core::mem::take(&mut self.retx_q);
        let mut retransmit = Vec::new();
        while let Some(segment) = old.pop_front() {
            if segment.payload.len() <= mss as usize {
                self.retx_q.push_back(segment);
                continue;
            }
            let chunks = segment.payload.len().div_ceil(mss as usize);
            let mut offset = 0usize;
            for index in 0..chunks {
                let take = ::core::cmp::min(mss as usize, segment.payload.len() - offset);
                let first = index == 0;
                let last = index + 1 == chunks;
                let mut flags = segment.flags;
                if !first { flags &= !(crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::CWR); }
                if !last { flags &= !(crate::tcp_hdr::flags::FIN | crate::tcp_hdr::flags::PSH); }
                let syn_offset = if !first && segment.flags & crate::tcp_hdr::flags::SYN != 0 { 1 } else { 0 };
                let piece = crate::tcp_conn::UnackedSegment {
                    seq: segment.seq.wrapping_add(offset as u32).wrapping_add(syn_offset),
                    flags,
                    payload: segment.payload[offset..offset + take].to_vec(),
                    last_sent_ns: now_ns,
                    delivered_at_send: segment.delivered_at_send,
                    delivered_mstamp_ns: segment.delivered_mstamp_ns,
                    first_sent_ns: segment.first_sent_ns,
                    delivery_app_limited: segment.delivery_app_limited,
                    retries: segment.retries,
                    sacked: segment.sacked,
                };
                if !piece.sacked { retransmit.push(piece.clone()); }
                self.retx_q.push_back(piece);
                offset += take;
            }
        }
        retransmit.iter().map(|segment| self.build_retx(segment)).collect()
    }
}

impl NetStack {
    /// Find an exact TCP origin that accepts a quoted frag-needed sequence. # C: O(log N)
    pub(crate) fn tcp_frag_needed_entry_in(&self, net_ns: u64, key: TcpKey,
                                            quoted_seq: u32) -> Option<Arc<TcpEntry>> {
        let entry = self.inet_tables(net_ns).tcp_conns.lock().get(&key).cloned()?;
        entry.accepts_frag_needed(quoted_seq).then_some(entry)
    }

    /// Re-derive the MSS a live connection sends at, after the sticky option
    /// area it prepends to every segment changed size. Nothing is
    /// resegmented here: the reference recomputes the cached MSS at the same
    /// point and lets the send path apply it to the next segment.
    /// # C: O(route lookup)
    pub fn tcp_sync_mss(&self, entry: &TcpEntry) {
        use ::core::sync::atomic::Ordering;
        let ext = crate::tcp_ext_hdr::ext_hdr_len(entry.ip_opts.options().as_ref());
        let ip_mode = entry.ip_mtu_discover.load(Ordering::Acquire);
        let ipv6_mode = entry.ipv6_mtu_discover.load(Ordering::Acquire);
        let dst = entry.conn.lock().remote.ip;
        let path_mtu = self.tcp_path_mtu_in(
            entry.net_ns(), dst, entry.bound_iface(), ip_mode, ipv6_mode).unwrap_or(0);
        let mss = crate::tcp_ext_hdr::mss_minus_ext_hdr(
            self.mss_for_dst_on_iface_pmtu_modes_in(
                entry.net_ns(), dst, entry.bound_iface(), ip_mode, ipv6_mode), ext);
        let mut conn = entry.conn.lock();
        if mss != 0 { conn.own_mss = mss; }
        conn.path_mtu = path_mtu;
    }

    /// Apply learned IPv4 PMTU and immediately retransmit resegmented data. # C: O(retx_q + xmit)
    pub(crate) fn tcp_mtu_reduced(&self, entry: &TcpEntry, path_mtu: u32) {
        if !entry.reduces_mss_for_frag_needed() { return; }
        let (segments, src, dst, tos) = {
            let mut c = entry.conn.lock();
            c.path_mtu = path_mtu;
            let segments = c.resegment_for_pmtu(
                ipv4_tcp_mss(path_mtu, crate::tcp_ext_hdr::ext_hdr_len(
                    entry.ip_opts.options().as_ref())),
                super::monotonic_ns_safe());
            (segments, c.local.ip, c.remote.ip, super::ecn_tos(&c))
        };
        for segment in segments {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, &segment, tos,
                entry.bound_iface(), super::tcp_tx::TcpTxPolicy::Entry(entry));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::core::sync::atomic::{AtomicI32, Ordering};

    fn entry(snd_una: u32, snd_nxt: u32, mode: i32) -> TcpEntry {
        let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40_000 };
        let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port: 443 };
        let mut conn = TcpConn::new_client(local, remote, snd_una);
        conn.state = crate::tcp_state::TcpState::Established;
        conn.snd_una = snd_una;
        conn.snd_nxt = snd_nxt;
        TcpEntry::new_bound_with_filter_pmtu(conn, Arc::new(crate::SocketError::new()), None,
            Arc::new(crate::bpf_filter::SocketFilter::new()), Arc::new(AtomicI32::new(mode)))
    }

    #[test]
    fn frag_needed_sequence_window_uses_wrapping_tcp_order() {
        let entry = entry(u32::MAX - 4, 3, crate::uapi::IP_PMTUDISC_WANT);
        assert!(entry.accepts_frag_needed(u32::MAX - 4));
        assert!(entry.accepts_frag_needed(0));
        assert!(entry.accepts_frag_needed(3));
        assert!(!entry.accepts_frag_needed(u32::MAX - 5));
        assert!(!entry.accepts_frag_needed(4));
        entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
        assert!(!entry.accepts_frag_needed(0));
    }

    #[test]
    fn valid_frag_needed_sequence_is_accepted_for_every_pmtu_mode() {
        let entry = entry(10, 20, crate::uapi::IP_PMTUDISC_DONT);
        for mode in crate::uapi::IP_PMTUDISC_DONT..=crate::uapi::IP_PMTUDISC_OMIT {
            entry.ip_mtu_discover.store(mode, Ordering::Release);
            assert!(entry.accepts_frag_needed(15), "mode={mode}");
        }
    }

    #[test]
    fn route_pmtu_update_is_bypassed_by_interface_and_omit_modes() {
        let entry = entry(10, 20, crate::uapi::IP_PMTUDISC_DONT);
        for mode in crate::uapi::IP_PMTUDISC_DONT..=crate::uapi::IP_PMTUDISC_OMIT {
            entry.ip_mtu_discover.store(mode, Ordering::Release);
            assert_eq!(entry.accepts_pmtu_update(), !matches!(mode,
                crate::uapi::IP_PMTUDISC_INTERFACE | crate::uapi::IP_PMTUDISC_OMIT),
                "mode={mode}");
        }
    }

    #[test]
    fn mss_reduction_is_limited_to_want_do_and_probe() {
        let entry = entry(10, 20, crate::uapi::IP_PMTUDISC_DONT);
        for mode in crate::uapi::IP_PMTUDISC_DONT..=crate::uapi::IP_PMTUDISC_OMIT {
            entry.ip_mtu_discover.store(mode, Ordering::Release);
            assert_eq!(entry.reduces_mss_for_frag_needed(), matches!(mode,
                crate::uapi::IP_PMTUDISC_WANT | crate::uapi::IP_PMTUDISC_DO
                    | crate::uapi::IP_PMTUDISC_PROBE), "mode={mode}");
        }
    }

    #[test]
    fn mtu_reduction_resegments_queue_without_socket_error_or_close() {
        let entry = entry(1_000, 1_240, crate::uapi::IP_PMTUDISC_DO);
        {
            let mut c = entry.conn.lock();
            c.state = crate::tcp_state::TcpState::Established;
            c.own_mss = 1_460;
            c.retx_q.push_back(crate::tcp_conn::UnackedSegment {
                seq: 1_000, flags: crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::PSH,
                payload: alloc::vec![7; 240], last_sent_ns: 11, delivered_at_send: 0,
                delivered_mstamp_ns: 0, first_sent_ns: 0, delivery_app_limited: false, retries: 2, sacked: false,
            });
            let retransmit = c.resegment_for_pmtu(100, 99);
            assert_eq!(retransmit.len(), 3);
            assert_eq!(c.retx_q.iter().map(|s| s.payload.len()).collect::<Vec<_>>(),
                alloc::vec![100, 100, 40]);
            assert_eq!(c.retx_q.iter().map(|s| s.seq).collect::<Vec<_>>(),
                alloc::vec![1_000, 1_100, 1_200]);
            assert!(c.retx_q.iter().all(|s| s.last_sent_ns == 99 && s.retries == 2));
            assert_eq!(c.retx_q[0].flags & crate::tcp_hdr::flags::PSH, 0);
            assert_ne!(c.retx_q[2].flags & crate::tcp_hdr::flags::PSH, 0);
            assert_eq!(c.own_mss, 100);
            assert_eq!(c.state, crate::tcp_state::TcpState::Established);
        }
        assert!(!entry.error.has());
    }

    #[test]
    fn pmtu_retransmissions_preserve_negotiated_timestamps_and_sequence() {
        let local = Endpoint { ip: IpAddr::V4(Ipv4Addr::LOOPBACK), port: 40_000 };
        let remote = Endpoint { ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port: 443 };
        let mut c = TcpConn::new_client(local, remote, 1_000);
        let mut peer = TcpConn::new_listener(remote);
        let syn = c.active_open().unwrap();
        let synack = peer.input(local.ip, remote.ip, &syn).unwrap().unwrap();
        let _ = c.input(remote.ip, local.ip, &synack).unwrap();
        assert!(c.ts_enabled);
        let expected_tsecr = c.ts_recent;
        let first_seq = c.snd_nxt;
        c.snd_nxt = c.snd_nxt.wrapping_add(240);
        c.own_mss = 1_460;
        c.retx_q.push_back(crate::tcp_conn::UnackedSegment {
            seq: first_seq, flags: crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::PSH,
            payload: alloc::vec![7; 240], last_sent_ns: 11, delivered_at_send: 0,
            delivered_mstamp_ns: 0, first_sent_ns: 0, delivery_app_limited: false, retries: 2, sacked: false,
        });

        let retransmit = c.resegment_for_pmtu(100, 99);

        assert_eq!(retransmit.len(), 3);
        for (segment, seq) in retransmit.iter().zip(
            [first_seq, first_seq.wrapping_add(100), first_seq.wrapping_add(200)]) {
            let hdr = crate::tcp_hdr::parse_prevalidated(segment).unwrap();
            assert_eq!(hdr.seq, seq);
            assert_eq!(hdr.data_offset, 8);
            assert_eq!(crate::tcp_hdr::parse_ts_option(segment).map(|(_, tsecr)| tsecr),
                Some(expected_tsecr));
        }
    }

    #[test]
    fn stack_mtu_response_is_noop_when_mode_disables_mss_reduction() {
        let stack = NetStack::new();
        for mode in [crate::uapi::IP_PMTUDISC_DONT, crate::uapi::IP_PMTUDISC_INTERFACE,
                     crate::uapi::IP_PMTUDISC_OMIT] {
            let entry = entry(1_000, 1_240, mode);
            entry.conn.lock().own_mss = 1_460;
            stack.tcp_mtu_reduced(&entry, 140);
            assert_eq!(entry.conn.lock().own_mss, 1_460, "mode={mode}");
            assert!(!entry.error.has(), "mode={mode}");
        }
    }

    #[test]
    fn tcp_output_honors_local_path_mss() {
        let entry = entry(1_000, 1_000, crate::uapi::IP_PMTUDISC_WANT);
        let mut c = entry.conn.lock();
        c.state = crate::tcp_state::TcpState::Established;
        c.own_mss = 100;
        c.send(&alloc::vec![1; 240]);
        let segments = c.output(1_500, true, false);
        assert_eq!(segments.iter().map(|segment| segment.len()).collect::<Vec<_>>(),
            alloc::vec![120, 120, 60]);
    }

    #[test]
    fn stack_mtu_reduction_immediately_transmits_resegmented_data() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = NetStack::new();
        let (iface, loopback) = stack.register_loopback();
        let remote = Ipv4Addr::new(192, 0, 2, 1);
        stack.routes.add(crate::RouteEntry::main(
            remote, 32, iface, None, Some(Ipv4Addr::LOOPBACK)));
        let entry = entry(1_000, 1_240, crate::uapi::IP_PMTUDISC_WANT);
        {
            let mut c = entry.conn.lock();
            c.state = crate::tcp_state::TcpState::Established;
            c.own_mss = 1_460;
            c.retx_q.push_back(crate::tcp_conn::UnackedSegment {
                seq: 1_000, flags: crate::tcp_hdr::flags::ACK | crate::tcp_hdr::flags::PSH,
                payload: alloc::vec![7; 240], last_sent_ns: 11, delivered_at_send: 0,
                delivered_mstamp_ns: 0, first_sent_ns: 0, delivery_app_limited: false, retries: 0, sacked: false,
            });
        }

        stack.tcp_mtu_reduced(&entry, 140);

        assert!(loopback.rx_pop().is_some());
        assert!(loopback.rx_pop().is_some());
        assert!(loopback.rx_pop().is_some());
        assert!(loopback.rx_pop().is_none());
        assert_eq!(entry.conn.lock().state, crate::tcp_state::TcpState::Established);
        assert_eq!(entry.conn.lock().path_mtu, 140);
        assert!(!entry.error.has());
    }
}
