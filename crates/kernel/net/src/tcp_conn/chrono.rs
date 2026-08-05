//! TCP send-state duration accounting.

use crate::tcp_conn::{TcpChrono, TcpConn};

impl TcpConn {
    fn set_chrono_at(&mut self, next: TcpChrono, now_ns: u64) {
        if self.telemetry.chrono == next || now_ns == 0 { return; }
        let elapsed = now_ns.saturating_sub(self.telemetry.chrono_start_ns);
        match self.telemetry.chrono {
            TcpChrono::None => {}
            TcpChrono::Busy => self.telemetry.busy_time_ns = self.telemetry.busy_time_ns.saturating_add(elapsed),
            TcpChrono::RwndLimited => self.telemetry.rwnd_limited_ns = self.telemetry.rwnd_limited_ns.saturating_add(elapsed),
            TcpChrono::SndbufLimited => self.telemetry.sndbuf_limited_ns = self.telemetry.sndbuf_limited_ns.saturating_add(elapsed),
        }
        self.telemetry.chrono = next;
        self.telemetry.chrono_start_ns = now_ns;
    }

    /// Refresh the active chronograph from the canonical TCP send queues. # C: O(n)
    pub(crate) fn refresh_chrono_at(&mut self, now_ns: u64) {
        let in_flight = self.retx_q.iter().map(|segment| segment.payload.len() as u32).sum::<u32>();
        let next = if self.send_buf.is_empty() && self.retx_q.is_empty() { TcpChrono::None }
        else if !self.send_buf.is_empty() && self.snd_wnd <= in_flight { TcpChrono::RwndLimited }
        else { TcpChrono::Busy };
        self.set_chrono_at(next, now_ns);
    }

    /// Record a write that cannot enter the caller-configured send buffer. # C: O(1)
    pub(crate) fn note_sndbuf_limited_at(&mut self, now_ns: u64) {
        self.set_chrono_at(TcpChrono::SndbufLimited, now_ns);
    }

    /// Include the unfinished active interval in TCP_INFO's duration snapshot. # C: O(1)
    pub fn chrono_totals_at(&self, now_ns: u64) -> (u64, u64, u64) {
        let elapsed = if now_ns == 0 { 0 } else { now_ns.saturating_sub(self.telemetry.chrono_start_ns) };
        match self.telemetry.chrono {
            TcpChrono::None => (self.telemetry.busy_time_ns, self.telemetry.rwnd_limited_ns, self.telemetry.sndbuf_limited_ns),
            TcpChrono::Busy => (self.telemetry.busy_time_ns.saturating_add(elapsed), self.telemetry.rwnd_limited_ns, self.telemetry.sndbuf_limited_ns),
            TcpChrono::RwndLimited => (self.telemetry.busy_time_ns, self.telemetry.rwnd_limited_ns.saturating_add(elapsed), self.telemetry.sndbuf_limited_ns),
            TcpChrono::SndbufLimited => (self.telemetry.busy_time_ns, self.telemetry.rwnd_limited_ns, self.telemetry.sndbuf_limited_ns.saturating_add(elapsed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::addr::{IpAddr, Ipv4Addr};
    use crate::tcp_conn::{Endpoint, TcpChrono, TcpConn};
    use crate::tcp_state::TcpState;

    #[test]
    fn chronograph_moves_between_real_send_queue_limits() {
        let ip = IpAddr::V4(Ipv4Addr::LOOPBACK);
        let endpoint = |port| Endpoint { ip, port };
        let mut conn = TcpConn::new_client(endpoint(40_000), endpoint(80), 1);
        conn.state = TcpState::Established;
        conn.send(b"blocked");
        conn.snd_wnd = 0;
        conn.refresh_chrono_at(10);
        assert_eq!(conn.telemetry.chrono, TcpChrono::RwndLimited);
        conn.note_sndbuf_limited_at(20);
        assert_eq!(conn.chrono_totals_at(25), (0, 10, 5));
    }
}
