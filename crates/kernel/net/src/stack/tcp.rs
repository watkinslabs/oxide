use super::*;

use super::tcp_tx::TcpTxPolicy;

mod send;
mod receive;

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
        // Linux serializes process-context socket readers with lock_sock();
        // the connection spinlock is only the short state/NET_RX lock.
        let _gate = unsafe { entry.recv_gate.lock() };
        entry.conn.lock().recv(max)
    }

    /// Transactional application receive with optional peek. # C: O(max)
    pub fn tcp_recv_with<R, E>(&self, entry: &TcpEntry, max: usize, peek: bool, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    {
        self.tcp_recv_with_offset_oob(entry, max, peek, 0, true, copy)
    }

    /// Transactional application receive after a non-consuming logical offset. # C: O(offset + max)
    pub fn tcp_recv_with_offset<R, E>(&self, entry: &TcpEntry, max: usize, peek: bool, offset: usize, copy: impl FnOnce(&[u8]) -> Result<(R, usize), E>)
        -> Result<Option<R>, E>
    {
        self.tcp_recv_with_offset_oob(entry, max, peek, offset, true, copy)
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
        let _gate = unsafe { entry.recv_gate.lock() };
        let (result, update) = {
            let before = entry.conn.lock().current_rcv_window() as u32;
            let snapshot = {
                let conn = entry.conn.lock();
                conn.snapshot_recv_with_offset_oob(max, offset, inline)
            };
            let Some(snapshot) = snapshot else { return Ok(None); };
            let (result, commit) = copy(&snapshot.bytes)?;
            {
                let mut conn = entry.conn.lock();
                conn.commit_recv_snapshot(&snapshot, commit, peek, inline);
            }
            let mut conn = entry.conn.lock();
            let after = conn.current_rcv_window() as u32;
            let raised = after != 0 && after >= before.saturating_mul(2) && after > before;
            let update = if raised && !peek {
                Some((conn.build_segment(crate::tcp_hdr::flags::ACK, &[]),
                      conn.local.ip, conn.remote.ip, ecn_tos(&conn)))
            } else { None };
            (Ok(Some(result)), update)
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
        // Linux's lock_sock() serializes process-context receive operations,
        // while the transport state lock is held only for the snapshot and
        // commit. The user copy may fault and schedule.
        let _gate = unsafe { entry.recv_gate.lock() };
        let Some((seq, byte)) = ({ entry.conn.lock().peek_urgent() }) else {
            return Ok(None);
        };
        copy(&[byte])?;
        if !peek { entry.conn.lock().take_urgent_if(seq); }
        Ok(Some(byte))
    }

    /// Graceful close: emit FIN; demux drives the rest. # C: O(1)
    pub fn tcp_close(&self, entry: &Arc<TcpEntry>) -> NetResult<()> {
        let (seg, src, dst, tos) = {
            let mut c = entry.conn.lock();
            let s = c.local_close().map_err(|_| NetError::Eio)?;
            (s, c.local.ip, c.remote.ip, ecn_tos(&c))
        };
        let now_ns = crate::tcp_conn::ka_now_ns();
        super::tcp_fastopen::drain_client(self, entry, now_ns);
        // What this connection measured about the path outlives it.
        super::tcp_metrics::record_to_cache(entry, now_ns);
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
                .filter_map(|(key, slot)| Some((*key, slot.sock()?.clone()))).collect();
            entries.extend(snapshot.into_iter()
                .map(|(key, entry)| (owner.clone(), tables.clone(), key, entry)));
        }
        entries
    }

    /// Hosted-test snapshot of the half-open requests every namespace holds.
    /// # C: O(N_conns)
    #[cfg(test)]
    pub(crate) fn tcp_tick_requests(&self)
        -> Vec<(Arc<super::inet_tables::InetTables>, TcpKey, Arc<super::TcpReq>)>
    {
        let tables: Vec<Arc<super::inet_tables::InetTables>> = self.inet.lock().values()
            .map(|entry| entry.tables.clone()).collect();
        let mut out = Vec::new();
        for table in tables {
            let snapshot: Vec<(TcpKey, Arc<super::TcpReq>)> = table.tcp_conns.lock().iter()
                .filter_map(|(key, slot)| Some((*key, slot.req()?.clone()))).collect();
            out.extend(snapshot.into_iter().map(|(key, req)| (table.clone(), key, req)));
        }
        out
    }

}
#[cfg(test)]
#[path = "tcp/tests/timer.rs"]
mod timer_tests;
#[cfg(test)]
#[path = "tcp/tests/urgent.rs"]
mod urgent_tests;
