// The listener half of the request sock: the check every segment arriving for
// a half-open passive connection passes, and the timer that retransmits its
// SYN-ACK, counts the deferring period and abandons a request nobody answered.
//
// The request queue and the accept queue are separate populations. A request
// lives in the connection table in SYN-RECV holding a SYN backlog slot; only a
// request that completes is promoted to an accept backlog slot and published.
// `TCP_DEFER_ACCEPT` therefore never puts anything in the accept queue that
// `accept` may not have: the deferral holds the connection back at the request
// stage, where the peer can still see the handshake is unfinished.

use super::*;
use super::tcp_tx::TcpTxPolicy;
use crate::tcp_conn::reqsk;

/// Whether this segment leaves the request half-open instead of completing it.
/// A deferring listener drops the bare acknowledgement and records that the
/// peer sent one, so the SYN-ACK timer knows the connection is alive and only
/// the data is missing. # C: O(1)
pub(crate) fn defers_segment(entry: &TcpEntry, listener: &TcpListenEntry,
                             hdr: &crate::tcp_hdr::TcpHdr, seg: &[u8]) -> bool
{
    let defer_accept = listener.defer_accept.load(::core::sync::atomic::Ordering::Acquire);
    if defer_accept == 0 { return false; }
    let bare = reqsk::bare_ack(hdr.flags, seg.len().saturating_sub(hdr.payload_offset()));
    let mut c = entry.conn.lock();
    if c.state != crate::tcp_state::TcpState::SynRecv { return false; }
    // A fast-open child was published at its SYN. Linux completes that child
    // before applying TCP_DEFER_ACCEPT's bare-ACK rule to ordinary requests.
    if c.fastopen_child { return false; }
    // Only the acknowledgement that would have completed the handshake is a
    // bare ACK worth deferring; anything else is left to the state machine.
    if hdr.ack != c.snd_nxt { return false; }
    if !c.rsk.defers_bare_ack(defer_accept, bare) { return false; }
    c.rsk.acked = true;
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

/// The listener a passive child belongs to, while it is still a request. # C: O(1)
fn request_listener(entry: &TcpEntry) -> Option<Arc<TcpListenEntry>> {
    entry.passive_listener.as_ref().and_then(alloc::sync::Weak::upgrade)
}

impl NetStack {
    /// Hosted compatibility helper: fire each request through the same
    /// per-socket callback production uses.
    /// # C: O(N_conns)
    #[cfg(test)]
    pub(crate) fn tcp_reqsk_tick_at(&self, now_ns: u64) {
        let entries = self.tcp_tick_entries();
        for (_, tables, key, entry) in entries {
            self.tcp_reqsk_timer(&tables, &key, &entry, now_ns);
        }
    }

    /// Fire one passive request's write timer. Listener-owned counters provide
    /// queue pressure in O(1), so this path never scans unrelated sockets.
    /// # C: O(log N + one segment xmit)
    pub(crate) fn tcp_reqsk_timer(&self, tables: &super::inet_tables::InetTables,
        key: &TcpKey, entry: &Arc<TcpEntry>, now_ns: u64)
    {
        let Some(listener) = request_listener(entry) else {
            let mut c = entry.conn.lock();
            if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.armed() { return; }
            c.state = crate::tcp_state::TcpState::Closed;
            drop(c);
            drop_request(tables, key, entry);
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
            if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.due(now_ns) {
                return;
            }
            entry.release_syn_backlog_young();
            let recalc = c.rsk.recalc(ceiling, defer_accept);
            let synack = if recalc.resend {
                c.retx_q.front().map(|segment| c.build_retx(segment))
            } else { None };
            if !reqsk::reschedules(recalc, synack.is_some(), c.rsk.acked) {
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
            drop_request(tables, key, entry);
            return;
        };
        if let Some(segment) = &synack {
            let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, 0,
                entry.bound_iface(), TcpTxPolicy::Entry(entry));
        }
    }
}

/// Unhook a request nobody will complete. # C: O(log N)
fn drop_request(tables: &super::inet_tables::InetTables, key: &TcpKey,
                entry: &Arc<TcpEntry>)
{
    entry.release_backlog();
    super::tcp_listener::remove_tcp_entry_exact(tables, key, entry);
    entry.close_and_wake();
}
