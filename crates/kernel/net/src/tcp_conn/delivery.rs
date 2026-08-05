//! ACK-derived TCP delivery-rate sampling.

use crate::tcp_conn::TcpConn;

impl TcpConn {
    /// Snapshot delivery state after queue entries reach the transmit owner. # C: O(n)
    pub(crate) fn note_delivery_sent_at(&mut self, start: usize, now_ns: u64) {
        let delivered_mstamp_ns = if self.telemetry.delivered_mstamp_ns == 0 { now_ns } else { self.telemetry.delivered_mstamp_ns };
        let app_limited = self.send_buf.is_empty();
        for segment in self.retx_q.iter_mut().skip(start) {
            segment.delivered_at_send = self.telemetry.delivered;
            segment.delivered_mstamp_ns = delivered_mstamp_ns;
            segment.first_sent_ns = now_ns;
            segment.delivery_app_limited = app_limited;
        }
    }

    /// Account cumulatively acknowledged data and retain the newest rate sample. # C: O(n)
    pub(crate) fn note_delivery_acked_at(&mut self, ack: u32, now_ns: u64) {
        if now_ns == 0 { return; }
        let mut delivered = 0u32;
        let mut sample = None;
        for segment in &self.retx_q {
            let len = segment.payload.len() as u32 + u32::from((segment.flags & (crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::FIN)) != 0);
            let acked = ack.wrapping_sub(segment.seq);
            if acked == 0 || (acked & 0x8000_0000) != 0 || acked < len { break; }
            if !segment.payload.is_empty() {
                delivered = delivered.saturating_add(1);
                if segment.delivered_mstamp_ns != 0 { sample = Some((segment.delivered_at_send,
                    segment.delivered_mstamp_ns, segment.first_sent_ns, segment.delivery_app_limited)); }
            }
        }
        if delivered == 0 { return; }
        self.telemetry.delivered = self.telemetry.delivered.saturating_add(delivered);
        self.telemetry.delivered_mstamp_ns = now_ns;
        let Some((prior_delivered, prior_mstamp_ns, first_sent_ns, app_limited)) = sample else { return };
        let ack_phase = now_ns.saturating_sub(prior_mstamp_ns);
        let send_phase = now_ns.saturating_sub(first_sent_ns);
        let interval_ns = core::cmp::max(ack_phase, send_phase);
        if interval_ns == 0 { return; }
        self.telemetry.rate_delivered = self.telemetry.delivered.saturating_sub(prior_delivered);
        self.telemetry.rate_interval_ns = interval_ns;
        self.telemetry.rate_app_limited = app_limited;
    }
}

#[cfg(test)]
mod tests {
    use crate::addr::{IpAddr, Ipv4Addr};
    use crate::tcp_conn::{Endpoint, TcpConn};
    use crate::tcp_state::TcpState;

    #[test]
    fn acknowledged_data_uses_its_transmit_snapshot_for_the_rate_sample() {
        let ip = IpAddr::V4(Ipv4Addr::LOOPBACK);
        let endpoint = |port| Endpoint { ip, port };
        let mut conn = TcpConn::new_client(endpoint(40_000), endpoint(80), 1);
        conn.state = TcpState::Established;
        conn.send(b"delivery");
        assert_eq!(conn.output(1_500, true, false).len(), 1);
        conn.note_delivery_sent_at(0, 1_000_000);
        conn.note_delivery_acked_at(conn.snd_nxt, 3_000_000);
        assert_eq!(conn.telemetry.delivered, 1);
        assert_eq!(conn.telemetry.rate_delivered, 1);
        assert_eq!(conn.telemetry.rate_interval_ns, 2_000_000);
        assert!(conn.telemetry.rate_app_limited);
    }
}
