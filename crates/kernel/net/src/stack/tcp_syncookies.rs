// The two halves of a stateless passive open, wired to the delivery path.
//
// Emit: a SYN the listener has no room for (or, at `tcp_syncookies=2`, any SYN
// at all) is answered from a connection built on the heap, transmitted, and
// dropped. Nothing is published into the connection table, no backlog slot is
// taken and no timer is armed — a flood of forged SYNs therefore costs this
// listener no memory whatsoever, which is the entire defence.
//
// Validate: an acknowledgement that matches no connection but does match a
// listener is not necessarily stray. If the listener overflowed recently and
// the segment's sequence numbers decode to a cookie this host minted, then a
// handshake really did complete and the child that proves it is built now.
//
// Both halves read the ONE stored `net.ipv4.tcp_syncookies` (`syncookies`);
// neither keeps a second copy of that state.

use super::*;
use super::tcp_tx::TcpTxPolicy;
use crate::syncookies::{self, Rebuild, Request};

/// The MSS a SYN with no MSS option is taken to have announced.
const PEER_MSS_DEFAULT: u16 = 536;

impl NetStack {
    /// Answer a SYN with a cookie and remember nothing about it.
    ///
    /// The connection this builds exists only to produce the SYN-ACK: it is
    /// dropped on return, so the acknowledgement that comes back will find no
    /// connection and be rebuilt from the cookie alone.
    /// # C: O(segment)
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn send_syn_cookie(&self, net_ns: u64, listener: &Arc<TcpListenEntry>,
        local_ep: Endpoint, src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8],
        hdr: &crate::tcp_hdr::TcpHdr, ipv6: bool, own_mss: u16, path_mtu: u32,
        metrics: crate::route_metrics::RouteMetrics) -> NetResult<()>
    {
        let now = crate::tcp_conn::ka_now_ns();
        // The listener's willingness to believe a cookie starts here: it is
        // only ever willing while it is minting them.
        listener.note_synq_overflow(now);
        let peer_mss = crate::tcp_hdr::parse_mss_option(seg).unwrap_or(PEER_MSS_DEFAULT);
        // Hashed over the arriving packet's own source and destination, in its
        // own order — the acknowledgement carries the same pair the same way
        // round, which is what lets the cookie be recomputed without state.
        let (isn, mss) = syncookies::init_sequence(src_ip, dst_ip, hdr.src_port, hdr.dst_port,
            hdr.seq, now, ipv6, peer_mss);
        let mut conn = alloc::boxed::Box::new(TcpConn::new_listener(local_ep));
        conn.own_mss = own_mss;
        conn.path_mtu = path_mtu;
        conn.apply_route_metrics(metrics);
        conn.set_syncookie(Request { isn, mss });
        let resp = conn.input_prevalidated_with_options(src_ip, dst_ip, seg,
            crate::sysctl::tcp_option_permissions_in(net_ns)).map_err(|_| NetError::Einval)?;
        let Some(segment) = resp else { return Ok(()); };
        self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0, listener.bound_iface(),
            TcpTxPolicy::Listener(listener))?;
        crate::mib::bump_tcp_ext(net_ns, crate::mib::TcpExt::SyncookiesSent);
        Ok(())
    }

    /// What a bare acknowledgement arriving at a listener proves, if anything.
    ///
    /// `None` covers every ordinary reason a segment reaches a listener with
    /// no connection behind it — a stray acknowledgement, a scan, a cookie
    /// this host did not mint or minted too long ago. It is never an error:
    /// the reference answers all of them with silence.
    /// # C: O(segment)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_syn_cookie(&self, net_ns: u64, listener: &TcpListenEntry,
        src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8], hdr: &crate::tcp_hdr::TcpHdr,
        ipv6: bool, route_metrics: crate::route_metrics::RouteMetrics) -> Option<Rebuild>
    {
        let now = crate::tcp_conn::ka_now_ns();
        if listener.no_recent_synq_overflow(now) { return None; }
        let Some(mss) = syncookies::validate(src_ip, dst_ip, hdr.src_port, hdr.dst_port,
            hdr.seq, hdr.ack, now, ipv6)
        else {
            crate::mib::bump_tcp_ext(net_ns, crate::mib::TcpExt::SyncookiesFailed);
            return None;
        };
        crate::mib::bump_tcp_ext(net_ns, crate::mib::TcpExt::SyncookiesRecv);
        // The options were smuggled through the SYN-ACK's own timestamp, so
        // they come back in the echo with this connection's offset still on
        // them; the offset is recomputed from the same keyed construction the
        // vanished SYN-ACK used.
        let ts = crate::tcp_hdr::parse_ts_option(seg);
        let ts_off = crate::secure_seq::secure_tcp_ts_off(
            dst_ip, src_ip, hdr.dst_port, hdr.src_port);
        let mut opts = syncookies::tsopt::decode(ts.is_some(),
            ts.map_or(0, |(_, tsecr)| tsecr.wrapping_sub(ts_off)),
            crate::sysctl::tcp_option_permissions_in(net_ns))?;
        if !cookie_ecn_ok(crate::sysctl::tcp_ecn_in(net_ns), route_metrics.features) {
            opts.ecn_ok = false;
        }
        Some(Rebuild {
            isn: hdr.ack.wrapping_sub(1),
            peer_isn: hdr.seq.wrapping_sub(1),
            mss,
            opts,
            ts_recent: ts.map_or(0, |(tsval, _)| tsval),
            ts_off,
            window: hdr.window,
        })
    }

    /// Materialise the connection a valid cookie proves should exist, and hand
    /// it to the program.
    ///
    /// The child is put into the state the forgotten SYN would have left and
    /// then fed the very acknowledgement that carried the cookie, so the
    /// handshake completes down the one path every other passive open uses —
    /// including an acknowledgement that arrives carrying data.
    /// # C: O(segment)
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_from_syn_cookie(&self, net_ns: u64, iface: NetIfaceId, src_ip: IpAddr,
        dst_ip: IpAddr, seg: &[u8], packet: &[u8], key: TcpKey,
        tables: &super::inet_tables::InetTables, ipv6: bool, local_ep: Endpoint, own_mss: u16,
        path_mtu: u32, metrics: crate::route_metrics::RouteMetrics,
        listener: &Arc<TcpListenEntry>, req: &Rebuild) -> NetResult<()>
    {
        let hdr = match crate::tcp_hdr::parse_prevalidated(seg) { Ok(h) => h, Err(_) => return Ok(()) };
        let entry = super::tcp_listener_deliver::build_passive_child(
            local_ep, own_mss, path_mtu, metrics, packet, listener,
            listener.bound_iface(), iface, ipv6);
        {
            let mut conn = entry.conn.lock();
            // The SYN this connection came from was answered and dropped, so
            // there is nothing for `TCP_SAVE_SYN` to hand back — recording the
            // acknowledgement in its place would report a segment that is not
            // a SYN.
            conn.syn_bytes = None;
            conn.open_from_cookie(src_ip, hdr.src_port, req);
        }
        // The cookie child never held a SYN-RECV slot; it takes an accept slot
        // directly, and a listener whose accept queue is full drops it exactly
        // as it drops a completed ordinary handshake.
        if !entry.adopt_cookie_accept_backlog() {
            entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
            return Ok(());
        }
        let resp = match entry.conn.lock().input_prevalidated(src_ip, dst_ip, seg) {
            Ok(resp) => resp,
            Err(_) => { entry.release_backlog(); return Ok(()); }
        };
        if entry.conn.lock().state != crate::tcp_state::TcpState::Established {
            entry.release_backlog();
            entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
            return Ok(());
        }
        if !super::tcp_listener::publish_passive_child(tables, listener, key, &entry) {
            return Ok(());
        }
        if !listener.enqueue_accepted(entry.clone()) {
            entry.release_backlog();
            entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
            super::tcp_listener::remove_tcp_entry_exact(tables, &key, &entry);
            return Ok(());
        }
        crate::mib::bump(net_ns, crate::mib::Mib::TcpPassiveOpens);
        if let Some(segment) = resp {
            if let Err(error) = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                listener.bound_iface(), TcpTxPolicy::Entry(&entry))
            {
                self.refresh_tcp_timers(&entry);
                return Err(error);
            }
            super::stamp_last_sent(&entry, 1);
        }
        self.activate_tcp_timers(&entry);
        Ok(())
    }
}

fn cookie_ecn_ok(tcp_ecn: i64, route_features: u32) -> bool {
    tcp_ecn != 0 || route_features & crate::route_metrics::RTAX_FEATURE_ECN != 0
}

#[cfg(test)]
mod tests {
    use super::cookie_ecn_ok;
    use crate::route_metrics::RTAX_FEATURE_ECN;

    #[test]
    fn cookie_ecn_requires_policy_or_route_feature() {
        assert!(!cookie_ecn_ok(0, 0));
        assert!(cookie_ecn_ok(0, RTAX_FEATURE_ECN));
        assert!(cookie_ecn_ok(2, 0));
    }
}
