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

/// One connection as a timer pass sees it: its namespace, its tables, its key
/// and the entry itself.
pub(crate) type TickEntry = (network_namespace::NetworkNamespaceRef,
                             Arc<super::inet_tables::InetTables>, TcpKey, Arc<TcpEntry>);

/// The listener a passive child belongs to, while it is still a request. # C: O(1)
fn request_listener(entry: &TcpEntry) -> Option<Arc<TcpListenEntry>> {
    entry.passive_listener.as_ref().and_then(alloc::sync::Weak::upgrade)
}

/// Requests on each listener that have not timed out yet — the young half the
/// pressure rule protects. Keyed by listener identity, since one tick sees
/// every namespace's requests at once. # C: O(N_conns)
fn young_per_listener(entries: &[TickEntry]) -> Vec<(usize, usize)> {
    let mut young: Vec<(usize, usize)> = Vec::new();
    for (_, _, _, entry) in entries {
        let Some(listener) = request_listener(entry) else { continue; };
        let c = entry.conn.lock();
        if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.armed() { continue; }
        if c.rsk.num_timeout != 0 { continue; }
        drop(c);
        let id = Arc::as_ptr(&listener) as usize;
        match young.iter_mut().find(|(key, _)| *key == id) {
            Some((_, count)) => *count += 1,
            None => young.push((id, 1)),
        }
    }
    young
}

impl NetStack {
    /// Fire every request timer that has come due: retransmit the SYN-ACK
    /// unless a deferring listener is waiting for data instead, count the
    /// firing, and abandon the request once it has run out of both.
    /// # C: O(N_conns)
    /// Fire every request timer due at `now_ns`, taking the snapshot itself.
    /// # C: O(N_conns)
    #[cfg(test)]
    pub(crate) fn tcp_reqsk_tick_at(&self, now_ns: u64) {
        let entries = self.tcp_tick_entries();
        self.tcp_reqsk_tick(&entries, now_ns);
    }

    pub(crate) fn tcp_reqsk_tick(&self, entries: &[TickEntry], now_ns: u64) {
        let young = young_per_listener(entries);
        for (_owner, tables, key, entry) in entries {
            let Some(listener) = request_listener(entry) else {
                // The listener is gone, so nothing can ever accept this
                // request; it is dropped rather than left half-open forever.
                let mut c = entry.conn.lock();
                if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.armed() { continue; }
                c.state = crate::tcp_state::TcpState::Closed;
                drop(c);
                drop_request(tables, key, entry);
                continue;
            };
            let young_here = young.iter()
                .find(|(id, _)| *id == Arc::as_ptr(&listener) as usize)
                .map_or(0, |(_, count)| *count);
            let ceiling = reqsk::synack_retries_under_pressure(
                synack_retries(&listener),
                listener.syn_backlog_used.load(::core::sync::atomic::Ordering::Acquire),
                listener.backlog.load(::core::sync::atomic::Ordering::Acquire),
                young_here);
            let defer_accept = listener.defer_accept.load(
                ::core::sync::atomic::Ordering::Acquire);
            let outcome = {
                let mut c = entry.conn.lock();
                if c.state != crate::tcp_state::TcpState::SynRecv || !c.rsk.due(now_ns) {
                    continue;
                }
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
                continue;
            };
            if let Some(segment) = &synack {
                let _ = self.send_tcp_segment_in(entry.net_ns(), src, dst, segment, 0,
                    entry.bound_iface(), TcpTxPolicy::Entry(entry));
            }
        }
    }
}

/// Unhook a request nobody will complete. # C: O(log N)
fn drop_request(tables: &Arc<super::inet_tables::InetTables>, key: &TcpKey,
                entry: &Arc<TcpEntry>)
{
    entry.release_backlog();
    super::tcp_listener::remove_tcp_entry_exact(tables, key, entry);
    entry.close_and_wake();
}
