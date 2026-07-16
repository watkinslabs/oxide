//! Lifecycle and control-plane helpers for `TcpConn`.

use alloc::vec::Vec;

use crate::tcp_conn::{TcpConn, TcpConnError};
use crate::tcp_state::{TcpEvent, TcpState};
use crate::tcp_conn::types::OWN_MSS_DEFAULT;
use crate::tcp_hdr::flags;

impl TcpConn {
    /// Build a brand-new client TCB. State starts CLOSED; caller
    /// then calls `active_open` to emit the initial SYN.
    /// # C: O(1)
    pub fn new_client(local: crate::tcp_conn::Endpoint, remote: crate::tcp_conn::Endpoint, isn: u32) -> Self {
        Self {
            local,
            remote,
            state: TcpState::Closed,
            snd_una: isn,
            snd_nxt: isn,
            rcv_nxt: 0,
            rcv_read_seq: 0,
            window: 65535,
            send_buf: alloc::collections::VecDeque::new(),
            recv_buf: alloc::collections::VecDeque::new(),
            urgent: None,
            retx_q:   alloc::collections::VecDeque::new(),
            srtt_ns:  0,
            rttvar_ns: 0,
            rto_ns:   1_000_000_000,
            tw_start_ns: 0,
            peer_mss: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            snd_wnd: 65535,
            ooo_buf: alloc::collections::BTreeMap::new(),
            ts_enabled: false,
            ts_recent:  0,
            own_mss:    0,
            cwnd:       10 * (OWN_MSS_DEFAULT as u32),
            ssthresh:   u32::MAX,
            dup_acks:   0,
            rcv_buf_cap: 65_536,
            rcv_buf_max: 4 * 1024 * 1024,
            rcv_peak:    0,
            cubic_w_max:    0,
            cubic_epoch_ms: 0,
            cubic_k_ms:     0,
            ecn_enabled: false,
            send_ece:    false,
            send_cwr:    false,
            ecn_last_reduce_ms: 0,
            ka_enabled:  false,
            ka_idle_ns:  7_200_000_000_000,
            ka_intvl_ns:    75_000_000_000,
            ka_cnt_max:  9,
            ka_count:    0,
            last_rx_ns:  0,
            next_ka_ns:  0,
        }
    }

    /// Build a brand-new listener TCB. State starts LISTEN.
    /// # C: O(1)
    pub fn new_listener(local: crate::tcp_conn::Endpoint) -> Self {
        Self {
            local,
            remote: crate::tcp_conn::Endpoint { ip: crate::addr::IpAddr::V4(crate::addr::Ipv4Addr::ANY), port: 0 },
            state: TcpState::Listen,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            rcv_read_seq: 0,
            window: 65535,
            send_buf: alloc::collections::VecDeque::new(),
            recv_buf: alloc::collections::VecDeque::new(),
            urgent: None,
            retx_q:   alloc::collections::VecDeque::new(),
            srtt_ns:  0,
            rttvar_ns: 0,
            rto_ns:   1_000_000_000,
            tw_start_ns: 0,
            peer_mss: 0,
            snd_wscale: 0,
            rcv_wscale: 0,
            snd_wnd: 65535,
            ooo_buf: alloc::collections::BTreeMap::new(),
            ts_enabled: false,
            ts_recent:  0,
            own_mss:    0,
            cwnd:       10 * (OWN_MSS_DEFAULT as u32),
            ssthresh:   u32::MAX,
            dup_acks:   0,
            rcv_buf_cap: 65_536,
            rcv_buf_max: 4 * 1024 * 1024,
            rcv_peak:    0,
            cubic_w_max:    0,
            cubic_epoch_ms: 0,
            cubic_k_ms:     0,
            ecn_enabled: false,
            send_ece:    false,
            send_cwr:    false,
            ecn_last_reduce_ms: 0,
            ka_enabled:  false,
            ka_idle_ns:  7_200_000_000_000,
            ka_intvl_ns:    75_000_000_000,
            ka_cnt_max:  9,
            ka_count:    0,
            last_rx_ns:  0,
            next_ka_ns:  0,
        }
    }

    /// F161: graceful close (RST mid-handshake / FIN Established).
    /// # C: O(1)
    pub fn drop_close(&mut self) -> Option<Vec<u8>> {
        match self.state {
            TcpState::SynSent | TcpState::SynRecv => {
                let seg = self.build_segment(flags::RST, &[]);
                self.state = TcpState::Closed;
                Some(seg)
            }
            TcpState::Established | TcpState::CloseWait => self.local_close().ok(),
            _ => None,
        }
    }

    /// Local close: emit FIN, transition out of ESTABLISHED.
    /// # C: O(1)
    pub fn local_close(&mut self) -> Result<Vec<u8>, TcpConnError> {
        let evt = match self.state {
            TcpState::Established => TcpEvent::LocalClose,
            TcpState::CloseWait   => TcpEvent::LocalClose,
            _ => return Err(TcpConnError::BadState),
        };
        let new_state = crate::tcp_state::transition(self.state, evt).ok_or(TcpConnError::BadState)?;
        let seg = self.build_segment(flags::FIN | flags::ACK, &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = new_state;
        Ok(seg)
    }

    /// F193: keepalive scheduler — delegate to tcp_cc. # C: O(1)
    pub fn keepalive_due(&mut self, now_ns: u64) -> Option<Vec<u8>> {
        crate::tcp_cc::keepalive_due(self, now_ns)
    }

    /// F193: build a 0-byte probe at seq=snd_una-1. # C: O(1)
    pub(crate) fn build_keepalive_probe(&mut self) -> Vec<u8> {
        self.build_keepalive_probe_with_flag(flags::ACK)
    }

    /// F194: 0-byte segment at seq=snd_una-1 with caller flags.
    /// Used by SO_LINGER abortive close to emit RST. # C: O(1)
    pub fn build_keepalive_probe_with_flag(&mut self, flag_bits: u8) -> Vec<u8> {
        let saved = self.snd_nxt;
        self.snd_nxt = self.snd_una.wrapping_sub(1);
        let seg = self.build_segment(flag_bits, &[]);
        self.snd_nxt = saved;
        seg
    }

    /// F185+F187: CC API delegates to tcp_cc module. # C: O(1)
    pub fn cc_on_ack(&mut self, acked: u32, payload_len: u32) {
        crate::tcp_cc::on_ack(self, acked, payload_len)
    }

    /// F187: RTO loss event. # C: O(1)
    pub fn cc_on_rto(&mut self) {
        crate::tcp_cc::on_rto(self)
    }

    /// F187: test hook for cubic integer-cuberoot helper. # C: O(log x)
    #[cfg(test)]
    pub fn icbrt_test(x: u64) -> u64 {
        crate::tcp_cc::icbrt(x)
    }

    /// F186: advertised window = free recv-buf bytes, shifted right by snd_wscale.
    /// # C: O(1)
    pub fn current_rcv_window(&self) -> u16 {
        let free = (self.rcv_buf_cap as usize).saturating_sub(self.recv_buf.len()) as u32;
        let scaled = free >> self.snd_wscale;
        if scaled > u16::MAX as u32 { u16::MAX } else { scaled as u16 }
    }

    /// F186: grow advertised receive window when observed peak exceeds half cap.
    /// # C: O(1)
    pub fn rcv_autotune(&mut self) {
        let len = self.recv_buf.len() as u32;
        if len > self.rcv_peak {
            self.rcv_peak = len;
        }
        if self.rcv_peak > self.rcv_buf_cap / 2 && self.rcv_buf_cap < self.rcv_buf_max {
            self.rcv_buf_cap = core::cmp::min(self.rcv_buf_cap.saturating_mul(2), self.rcv_buf_max);
            self.rcv_peak = 0;
        }
    }
}
