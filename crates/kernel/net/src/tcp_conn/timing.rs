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

    /// Sample receiver RTT after contiguous data reaches one advertised window. # C: O(1)
    pub(crate) fn note_rcv_rtt_at(&mut self, now_ns: u64) {
        if self.rcv_rtt_stamp_ns != 0 {
            let passed = self.rcv_nxt.wrapping_sub(self.rcv_rtt_seq);
            if (passed & 0x8000_0000) != 0 { return; }
            let sample = now_ns.saturating_sub(self.rcv_rtt_stamp_ns).max(1);
            if self.rcv_rtt_ns == 0 || sample < self.rcv_rtt_ns {
                self.rcv_rtt_ns = sample;
            }
        }
        self.rcv_rtt_seq = self.rcv_nxt.wrapping_add(self.advertised_rcv_wnd());
        self.rcv_rtt_stamp_ns = now_ns;
    }

    /// Sample bytes copied to the application across one receiver RTT. # C: O(1)
    pub(crate) fn note_rcv_space_at(&mut self, now_ns: u64) {
        if self.rcv_space_stamp_ns == 0 {
            self.rcv_space_stamp_ns = now_ns;
            self.rcv_space_read_seq = self.rcv_read_seq;
            return;
        }
        if self.rcv_rtt_ns == 0 || now_ns.saturating_sub(self.rcv_space_stamp_ns) < self.rcv_rtt_ns {
            return;
        }
        let copied = self.rcv_read_seq.wrapping_sub(self.rcv_space_read_seq);
        let queued = self.rcv_nxt.wrapping_sub(self.rcv_read_seq);
        self.rcv_space = copied.saturating_sub(queued);
        self.rcv_space_read_seq = self.rcv_read_seq;
        self.rcv_space_stamp_ns = now_ns;
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

    #[test]
    fn pacing_deadline_is_owned_by_the_transport_and_honors_the_live_cap() {
        let mut c = conn();
        c.cwnd = 1_000;
        c.ssthresh = 500;
        c.srtt_ns = 1_000;
        assert!(c.pacing_ready_at(10, 100));
        assert_eq!(c.telemetry.pacing_rate, 100);
        c.note_paced_output_at(10, 100, 100);
        assert_eq!(c.telemetry.pacing_next_ns, 1_000_000_010);
        assert!(!c.pacing_ready_at(1_000_000_009, 100));
        assert!(c.pacing_ready_at(1_000_000_010, 100));
        c.note_paced_output_at(1_000_000_010, 100, 100);
        assert!(c.pacing_ready_at(1_000_000_011, u64::MAX));
        assert_eq!(c.telemetry.pacing_next_ns, 0);
    }

    #[test]
    fn receiver_rtt_is_measured_over_the_advertised_window() {
        let mut c = conn();
        c.rcv_nxt = 1_000;
        c.rcv_buf_cap = 100;
        c.window_clamp = 100;
        c.note_rcv_rtt_at(10);
        assert_eq!(c.rcv_rtt_seq, 1_100);
        c.rcv_nxt = 1_099;
        c.note_rcv_rtt_at(20);
        assert_eq!(c.rcv_rtt_ns, 0);
        c.rcv_nxt = 1_100;
        c.note_rcv_rtt_at(30);
        assert_eq!(c.rcv_rtt_ns, 20);
    }

    #[test]
    fn receiver_space_tracks_bytes_copied_over_the_receiver_rtt() {
        let mut c = conn();
        c.rcv_rtt_ns = 10;
        c.rcv_read_seq = 1_000;
        c.note_rcv_space_at(1);
        c.rcv_read_seq = 1_080;
        c.rcv_nxt = 1_100;
        c.note_rcv_space_at(11);
        assert_eq!(c.rcv_space, 60);
    }
}
