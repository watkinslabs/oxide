// The listener half of the request sock: the check every segment arriving for
// a half-open passive connection passes, the timer that retransmits its
// SYN-ACK, counts the deferring period and abandons a request nobody answered,
// and the promotion that turns a request into the connection `accept` hands
// over.
//
// A segment matching a request never reaches the connection state machine.
// The request has no connection to run one against: it is answered by a
// request-only check that either drops it, retransmits the SYN-ACK, leaves the
// request half-open, or creates the child and REPLACES the request in the
// table. That is what keeps a half-open a few hundred bytes instead of a whole
// transport control block.
//
// The request queue and the accept queue are separate populations. A request
// lives in the connection table holding a SYN backlog slot; only a request
// that completes takes an accept backlog slot and is published.
// `TCP_DEFER_ACCEPT` therefore never puts anything in the accept queue that
// `accept` may not have: the deferral holds the connection back at the request
// stage, where the peer can still see the handshake is unfinished.

use super::*;
use super::tcp_tx::TcpTxPolicy;
use crate::tcp_conn::{reqsk, synrecv};

/// Whether this segment leaves the request half-open instead of completing it.
/// A deferring listener drops the bare acknowledgement and records that the
/// peer sent one, so the SYN-ACK timer knows the connection is alive and only
/// the data is missing. # C: O(1)
pub(crate) fn defers_segment(req: &TcpReq, listener: &TcpListenEntry,
                             hdr: &crate::tcp_hdr::TcpHdr, seg: &[u8]) -> bool
{
    let defer_accept = listener.defer_accept.load(::core::sync::atomic::Ordering::Acquire);
    if defer_accept == 0 { return false; }
    let bare = reqsk::bare_ack(hdr.flags, seg.len().saturating_sub(hdr.payload_offset()));
    // Only the acknowledgement that would have completed the handshake is a
    // bare ACK worth deferring; anything else is left to the request check.
    if hdr.ack != req.snd_nxt() { return false; }
    let mut rsk = req.rsk.lock();
    if !rsk.defers_bare_ack(defer_accept, bare) { return false; }
    rsk.acked = true;
    true
}

/// A request's own SYN-ACK retransmit ceiling. `TCP_SYNCNT` on the listening
/// socket names it; otherwise the stack's own. # C: O(1)
fn synack_retries(listener: &TcpListenEntry) -> u8 {
    match listener.synack_retries.load(::core::sync::atomic::Ordering::Acquire) {
        0 => reqsk::SYNACK_RETRIES_DEFAULT,
        v => v,
    }
}

/// Per-namespace interval converted at the decision site from the ABI's
/// millisecond unit to the packet clock's nanoseconds. # C: O(log N)
fn invalid_ratelimit_ns(net_ns: u64) -> u64 {
    const NS_PER_MS: u64 = 1_000_000;
    let ms = crate::sysctl::value_in(net_ns, crate::net_ns::NetSysctlKey::TcpInvalidRatelimit)
        .unwrap_or(reqsk::INVALID_RATELIMIT_DEFAULT_MS as i64).max(0) as u64;
    ms.saturating_mul(NS_PER_MS)
}

fn admit_request_answer(net_ns: u64, req: &TcpReq, now_ns: u64,
                        data_without_syn: bool) -> bool {
    if reqsk::admit_oow_answer(&req.last_oow_ack_ns,
        now_ns, invalid_ratelimit_ns(net_ns), data_without_syn) { return true; }
    crate::mib::bump_tcp_ext(net_ns, crate::mib::TcpExt::TcpAckSkippedSynRecv);
    false
}

impl NetStack {
    /// Hosted compatibility helper: fire each request through the same
    /// per-request callback production uses.
    /// # C: O(N_conns)
    #[cfg(test)]
    pub(crate) fn tcp_reqsk_tick_at(&self, now_ns: u64) {
        for (tables, key, req) in self.tcp_tick_requests() {
            self.tcp_reqsk_timer(&tables, &key, &req, now_ns);
        }
    }

    /// Fire one passive request's SYN-ACK timer. Listener-owned counters
    /// provide queue pressure in O(1), so this path never scans unrelated
    /// sockets.
    /// # C: O(log N + one segment xmit)
    pub(crate) fn tcp_reqsk_timer(&self, tables: &super::inet_tables::InetTables,
        key: &TcpKey, req: &Arc<TcpReq>, now_ns: u64)
    {
        let Some(listener) = req.listener() else {
            if req.rsk.lock().armed() { drop_request(tables, key, req); }
            return;
        };
        let ceiling = reqsk::synack_retries_under_pressure(
            synack_retries(&listener),
            listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire),
            listener.backlog.load(::core::sync::atomic::Ordering::Acquire),
            listener.syn_backlog_young.load(::core::sync::atomic::Ordering::Acquire));
        let defer_accept = listener.defer_accept.load(
            ::core::sync::atomic::Ordering::Acquire);
        let resend = {
            let rsk = req.rsk.lock();
            if !rsk.due(now_ns) { return; }
            drop(rsk);
            req.release_syn_backlog_young();
            let mut rsk = req.rsk.lock();
            let recalc = rsk.recalc(ceiling, defer_accept);
            // A request always has a SYN-ACK to send, because it is rebuilt
            // from the negotiation rather than replayed from a queue.
            if !reqsk::reschedules(recalc, recalc.resend, rsk.acked) {
                crate::mib::bump(req.net_ns(), crate::mib::Mib::TcpAttemptFails);
                None
            } else {
                // A request runs under the stack's retransmit ceiling: nothing
                // can have named another, because no socket owns it yet.
                rsk.on_timeout(now_ns, crate::tcp_conn::RTO_MAX_DEFAULT_NS);
                if recalc.resend { rsk.num_retrans = rsk.num_retrans.saturating_add(1); }
                Some(recalc.resend)
            }
        };
        let Some(resend) = resend else {
            drop_request(tables, key, req);
            return;
        };
        if resend {
            let segment = req.synack();
            let _ = self.send_tcp_segment_in(req.net_ns(), req.local.ip, req.remote.ip,
                &segment, 0, req.bound_iface(), TcpTxPolicy::Listener(&listener));
        }
    }

    /// The same SYN-ACK timer, for the one passive open that is a connection
    /// before its handshake ends: a fast open whose SYN carried data was put
    /// in the accept queue at the SYN, so it is a full socket in SYN-RECV and
    /// its SYN-ACK is retransmitted from the queue that holds it. The
    /// retransmit and deferral POLICY is the shared one; only where the
    /// segment comes from differs.
    /// # C: O(log N + one segment xmit)
    pub(crate) fn tcp_synack_timer_sock(&self, tables: &super::inet_tables::InetTables,
        key: &TcpKey, entry: &Arc<TcpEntry>, now_ns: u64)
    {
        let Some(listener) = entry.passive_listener.as_ref()
            .and_then(alloc::sync::Weak::upgrade)
        else {
            let mut c = entry.conn.lock();
            if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.armed() { return; }
            c.state = crate::tcp_state::TcpState::Closed;
            drop(c);
            entry.release_backlog();
            super::tcp_listener::remove_tcp_entry_exact(tables, key, entry);
            entry.close_and_wake();
            return;
        };
        let ceiling = reqsk::synack_retries_under_pressure(
            synack_retries(&listener),
            listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire),
            listener.backlog.load(::core::sync::atomic::Ordering::Acquire),
            listener.syn_backlog_young.load(::core::sync::atomic::Ordering::Acquire));
        let defer_accept = listener.defer_accept.load(
            ::core::sync::atomic::Ordering::Acquire);
        let outcome = {
            let mut c = entry.conn.lock();
            if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.due(now_ns) { return; }
            entry.release_syn_backlog_young();
            let recalc = c.rsk.recalc(ceiling, defer_accept);
            let synack = if recalc.resend {
                c.retx_q.front().map(|segment| c.build_retx(segment))
            } else { None };
            if !reqsk::reschedules(recalc, synack.is_some(), c.rsk.acked) {
                crate::mib::bump(entry.net_ns(), crate::mib::Mib::TcpAttemptFails);
                c.state = crate::tcp_state::TcpState::Closed;
                None
            } else {
                let rto_max = c.rto_max_ns;
                c.rsk.on_timeout(now_ns, rto_max);
                if synack.is_some() {
                    if let Some(front) = c.retx_q.front_mut() {
                        front.retries = front.retries.saturating_add(1);
                        front.last_sent_ns = now_ns;
                    }
                }
                Some((synack, c.local.ip, c.remote.ip))
            }
        };
        let Some((synack, src, dst)) = outcome else {
            entry.release_backlog();
            super::tcp_listener::remove_tcp_entry_exact(tables, key, entry);
            entry.close_and_wake();
            return;
        };
        if let Some(segment) = &synack {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, 0,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
    }

    /// Abandon a half-open request from outside the timer, which is what a
    /// hard path error against it means. # C: O(log N)
    pub(crate) fn drop_tcp_request(&self, net_ns: u64, req: &Arc<TcpReq>) {
        let tables = self.inet_tables(net_ns);
        drop_request(&tables, &req.key(), req);
    }

    /// The request-only check one arriving segment passes. A request owns no
    /// connection, so nothing here runs a state machine: the segment either
    /// re-solicits the SYN-ACK, ends the request, leaves it half-open, or
    /// creates the child that replaces it.
    /// # C: O(log N + segment)
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn deliver_tcp_to_request_at(&self, net_ns: u64, src_ip: IpAddr, dst_ip: IpAddr,
        seg: &[u8], hdr: &crate::tcp_hdr::TcpHdr, key: TcpKey,
        tables: &super::inet_tables::InetTables, req: &Arc<TcpReq>, now_ns: u64) -> NetResult<()>
    {
        let Some(listener) = req.listener() else {
            drop_request(tables, &key, req);
            return Ok(());
        };
        let payload_len = seg.len().saturating_sub(hdr.payload_offset());
        let verdict = synrecv::request_segment(hdr.flags, hdr.seq, hdr.ack, payload_len,
            req.isn(), req.peer_isn(), req.rcv_wnd as u32);
        match verdict {
            // A peer that lost the SYN-ACK retransmits its SYN. The request is
            // kept and the same SYN-ACK goes out again; creating a second
            // request would take another backlog slot for one connection.
            synrecv::ReqVerdict::ResendSynack => {
                if !admit_request_answer(net_ns, req, now_ns, false) { return Ok(()); }
                let segment = req.synack();
                let result = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                    req.bound_iface(), TcpTxPolicy::Listener(&listener));
                if result.is_ok() {
                    req.rsk.lock().arm(now_ns, crate::tcp_conn::RTO_MAX_DEFAULT_NS);
                    super::tcp_timer::arm_req(req);
                }
                result
            }
            // The segment acknowledged something this side never sent. The
            // request is left exactly as it was — a segment that failed this
            // test says nothing about the connection whose 4-tuple it wore.
            synrecv::ReqVerdict::Reset => {
                let end = synrecv::end_seq(hdr.seq, payload_len, hdr.flags);
                let segment = req.open_conn().build_rst_reply(hdr.flags, hdr.ack, end);
                self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                    req.bound_iface(), TcpTxPolicy::Listener(&listener))
            }
            synrecv::ReqVerdict::AckAndDrop => {
                let data_without_syn = payload_len != 0 && hdr.flags & tcp_flags::SYN == 0;
                if !admit_request_answer(net_ns, req, now_ns, data_without_syn) { return Ok(()); }
                let segment = req.open_conn().build_segment(tcp_flags::ACK, &[]);
                self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                    req.bound_iface(), TcpTxPolicy::Listener(&listener))
            }
            synrecv::ReqVerdict::Drop => Ok(()),
            // Nothing is recorded against a socket, because no socket exists
            // yet to record it against.
            synrecv::ReqVerdict::EndRequest { reset } => {
                crate::mib::bump(net_ns, crate::mib::Mib::TcpAttemptFails);
                drop_request(tables, &key, req);
                if !reset { return Ok(()); }
                let end = synrecv::end_seq(hdr.seq, payload_len, hdr.flags);
                let segment = req.open_conn().build_rst_reply(hdr.flags, hdr.ack, end);
                self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                    req.bound_iface(), TcpTxPolicy::Listener(&listener))
            }
            synrecv::ReqVerdict::Complete => {
                if defers_segment(req, &listener, hdr, seg) { return Ok(()); }
                self.promote_request(net_ns, src_ip, dst_ip, seg, key, tables, req, &listener)
            }
        }
    }

    /// Turn a request into the connection `accept` hands over. The child is
    /// opened from the request's recorded negotiation and then fed the very
    /// acknowledgement that completed the handshake, so a third segment
    /// carrying data is delivered down the one path every passive open uses.
    /// # C: O(segment)
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn promote_request(&self, net_ns: u64, src_ip: IpAddr, dst_ip: IpAddr, seg: &[u8],
        key: TcpKey, tables: &super::inet_tables::InetTables, req: &Arc<TcpReq>,
        listener: &Arc<TcpListenEntry>) -> NetResult<()>
    {
        let entry = super::tcp_listener_deliver::build_passive_child(req.local, req.own_mss,
            req.path_mtu.load(::core::sync::atomic::Ordering::Acquire), req.metrics, &[],
            listener, req.iface, req.ipv6);
        {
            let mut conn = entry.conn.lock();
            // What the SYN carried — the saved packet and its network-header
            // fields — belongs to the child, not the acknowledgement that
            // finished the handshake.
            conn.syn_bytes = req.syn_bytes.clone();
            conn.rcv_iif = req.rcv_iif;
            conn.rcv_ttl = req.rcv_ttl;
            conn.rcv_tos = req.rcv_tos;
            conn.open_from_cookie(req.remote.ip, req.remote.port, &req.negotiated);
        }
        // The child's mark is the request's, so a write to the listening
        // socket's option while the handshake ran does not reach it.
        entry.mark.store(req.mark, ::core::sync::atomic::Ordering::Release);
        // The accept slot is taken before the request's SYN slot is given
        // back, so a listener whose accept queue is full leaves the request
        // exactly as it was.
        if !entry.adopt_cookie_accept_backlog() {
            entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
            // The peer believes this connection is established. A listener
            // that merely has not drained its accept queue yet is a transient
            // condition: the request stays half-open, its SYN-ACK
            // retransmits, and the acknowledgement that arrives after the
            // program calls accept completes the handshake normally. Only a
            // namespace that asked for the reset, or a listener going away,
            // ends it.
            let overflow = crate::listen_queue::accept_overflow(
                crate::sysctl::tcp_abort_on_overflow_in(net_ns));
            if !listener.is_closed()
                && overflow == crate::listen_queue::AcceptOverflow::RetainRequest
            {
                return Ok(());
            }
            let rst = req.open_conn().drop_close();
            drop_request(tables, &key, req);
            if let Some(segment) = rst {
                let _ = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                    req.bound_iface(), TcpTxPolicy::Listener(listener));
            }
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
        if !super::tcp_listener::replace_request_with_child(tables, &key, req, &entry) {
            entry.release_backlog();
            entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
            return Ok(());
        }
        req.release_syn_backlog();
        super::tcp_metrics::seed_from_cache(&entry);
        if !listener.enqueue_accepted(entry.clone()) {
            entry.release_backlog();
            entry.conn.lock().state = crate::tcp_state::TcpState::Closed;
            super::tcp_listener::remove_tcp_entry_exact(tables, &key, &entry);
            return Ok(());
        }
        crate::mib::bump(net_ns, crate::mib::Mib::TcpPassiveOpens);
        if let Some(segment) = resp {
            if let Err(error) = self.send_tcp_segment_in(net_ns, dst_ip, src_ip, &segment, 0,
                entry.bound_iface(), TcpTxPolicy::Entry(&entry))
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

/// Unhook a request nobody will complete. # C: O(log N)
fn drop_request(tables: &super::inet_tables::InetTables, key: &TcpKey, req: &Arc<TcpReq>) {
    req.release_syn_backlog();
    super::tcp_listener::remove_tcp_request_exact(tables, key, req);
}
