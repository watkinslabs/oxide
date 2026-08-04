//! Clock helpers used by TCP timestamps / keepalive.

/// F182: monotonic millisecond clock for TSval per RFC 7323 §5.4.
/// # C: O(1)
pub fn ka_now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

/// F182: monotonic ms clock for TSval.
/// # C: O(1)
pub fn tcp_now_ms() -> u32 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; return (hal_x86_64::X86TimerOps::monotonic_ns().0 / 1_000_000) as u32; }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; return (hal_aarch64::ArmTimerOps::monotonic_ns().0 / 1_000_000) as u32; }
    #[allow(unreachable_code)]
    0
}

impl crate::tcp_conn::TcpConn {
    /// Record receive-side activity at the point a validated TCP header enters the TCB. # C: O(1)
    pub(crate) fn note_info_receive_at(&mut self, now_ns: u64, flags: u8, payload_len: usize) {
        self.last_rx_ns = now_ns;
        if (flags & crate::tcp_hdr::flags::ACK) != 0 { self.last_ack_recv_ns = now_ns; }
        if payload_len != 0 {
            let prior = self.last_data_recv_ns;
            self.last_data_recv_ns = now_ns;
            self.note_delack_data_at(now_ns, prior);
        }
    }

    /// Update the delayed-ACK arrival interval from validated receive activity. # C: O(1)
    fn note_delack_data_at(&mut self, now_ns: u64, prior_ns: u64) {
        use crate::tcp_conn::DELACK_ATO_MIN_NS;
        if self.delack_ato_ns == 0 {
            self.delack_ato_ns = DELACK_ATO_MIN_NS;
            return;
        }
        let gap = now_ns.saturating_sub(prior_ns);
        if gap <= DELACK_ATO_MIN_NS / 2 {
            self.delack_ato_ns = self.delack_ato_ns / 2 + DELACK_ATO_MIN_NS / 2;
        } else if gap < self.delack_ato_ns {
            self.delack_ato_ns = (self.delack_ato_ns / 2 + gap).min(self.rto_ns);
        }
    }

    /// Delayed-ACK interval currently visible to the TCP ABI. # C: O(1)
    pub fn delack_ato_ns(&self) -> u64 {
        let ato = if self.delack_ato_ns == 0 { self.delack_max_ns } else { self.delack_ato_ns };
        ato.min(self.delack_max_ns)
    }

    /// Record a successfully emitted sequence-consuming TCP segment. # C: O(1)
    pub(crate) fn note_info_data_sent_at(&mut self, now_ns: u64) {
        self.last_data_sent_ns = now_ns;
    }
}

#[cfg(test)]
mod tests {
    fn conn() -> crate::tcp_conn::TcpConn {
        let ip = crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::LOOPBACK);
        let endpoint = |port| crate::tcp_conn::Endpoint { ip, port };
        crate::tcp_conn::TcpConn::new_client(endpoint(40_000), endpoint(80), 1)
    }

    #[test]
    fn activity_clocks_distinguish_data_from_ack_activity() {
        let mut c = conn();
        c.note_info_receive_at(11, crate::tcp_hdr::flags::ACK, 0);
        assert_eq!(c.last_ack_recv_ns, 11);
        assert_eq!(c.last_data_recv_ns, 0);
        c.note_info_receive_at(12, 0, 3);
        assert_eq!(c.last_ack_recv_ns, 11);
        assert_eq!(c.last_data_recv_ns, 12);
        assert_eq!(c.delack_ato_ns, crate::tcp_conn::DELACK_ATO_MIN_NS);
        c.note_info_data_sent_at(13);
        assert_eq!(c.last_data_sent_ns, 13);
    }

    #[test]
    fn delayed_ack_interval_tracks_arrival_spacing_and_its_ceiling() {
        let mut c = conn();
        c.note_info_receive_at(10, 0, 1);
        c.delack_ato_ns = 60_000_000;
        c.note_info_receive_at(25_000_010, 0, 1);
        assert_eq!(c.delack_ato_ns, 55_000_000);
        c.delack_max_ns = 20_000_000;
        assert_eq!(c.delack_ato_ns(), 20_000_000);
    }
}
