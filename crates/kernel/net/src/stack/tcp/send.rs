// TCP application-send admission and canonical pacing output.

use super::*;

impl NetStack {
    /// F164: send `data`; bounded by `sndbuf_cap`. Returns Eagain. # C: O(data + N segments)
    pub fn tcp_send(&self, entry: &Arc<TcpEntry>, data: &[u8], sndbuf_cap: usize, nodelay: bool, cork: bool)
        -> NetResult<usize>
    {
        let (segs, accepted, src, dst, tos, max_pacing_rate, now_ns) = {
            let mut c = entry.conn.lock();
            let in_flight: usize = c.retx_q.iter().map(|s| s.payload.len()).sum();
            let avail = sndbuf_cap.saturating_sub(c.send_buf.len() + in_flight);
            if avail == 0 && !data.is_empty() {
                c.note_sndbuf_limited_at(crate::tcp_conn::ka_now_ns());
                return Err(NetError::Eagain);
            }
            let accepted = ::core::cmp::min(avail, data.len());
            c.send(&data[..accepted]);
            let max_pacing_rate = entry.max_pacing_rate.load(::core::sync::atomic::Ordering::Acquire);
            let now_ns = crate::tcp_conn::ka_now_ns();
            let segs = if c.pacing_ready_at(now_ns, max_pacing_rate) {
                c.output_limit(1500, nodelay, cork,
                    if max_pacing_rate == u64::MAX { usize::MAX } else { 1 })
            } else { Vec::new() };
            c.refresh_chrono_at(now_ns);
            (segs, accepted, c.local.ip, c.remote.ip, ecn_tos(&c), max_pacing_rate, now_ns)
        };
        for s in &segs {
            if let Err(error) = self.send_tcp_segment_in(entry.net_ns(), src, dst, s, tos,
                entry.bound_iface(), TcpTxPolicy::Entry(entry))
            {
                self.refresh_tcp_timers(entry);
                return Err(error);
            }
        }
        stamp_last_sent(entry, segs.len());
        if !segs.is_empty() {
            let bytes = entry.conn.lock().retx_q.back().map_or(0, |seg| seg.payload.len());
            entry.conn.lock().note_paced_output_at(now_ns, bytes, max_pacing_rate);
        }
        self.refresh_tcp_timers(entry);
        Ok(accepted)
    }
}
