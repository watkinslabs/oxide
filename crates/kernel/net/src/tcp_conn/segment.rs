//! Segment construction helpers.

use alloc::vec::Vec;

use crate::tcp_conn::{TcpConn, UnackedSegment};
use crate::tcp_conn::{segment_opts, syn_opts::SynOptions};
use crate::tcp_hdr::{TcpHdr, TCP_HDR_MIN_LEN, flags};

impl TcpConn {
    pub(crate) fn build_retx(&self, s: &UnackedSegment) -> alloc::vec::Vec<u8> {
        if s.flags & flags::SYN != 0 {
            return self.build_syn_with_opts_at(s.seq, s.flags);
        }
        let urg_ptr = if s.flags & flags::URG != 0 { 1 } else { 0 };
        self.build_segment_at(s.seq, s.flags, &s.payload, urg_ptr)
    }

    pub fn build_segment(&mut self, mut flag_bits: u8, payload: &[u8]) -> Vec<u8> {
        if self.ecn_enabled {
            if self.send_cwr && !payload.is_empty() {
                flag_bits |= flags::CWR;
                self.send_cwr = false;
            }
            if self.send_ece && (flag_bits & flags::ACK) != 0 {
                flag_bits |= flags::ECE;
            }
        }
        self.build_segment_at(self.snd_nxt, flag_bits, payload, 0)
    }

    pub(crate) fn build_urgent_segment(&mut self, payload: &[u8]) -> Vec<u8> {
        self.build_segment_at(self.snd_nxt, flags::PSH | flags::ACK | flags::URG, payload, 1)
    }

    fn build_segment_at(&self, seq: u32, flag_bits: u8, payload: &[u8], urg_ptr: u16) -> Vec<u8> {
        let timestamp = self.ts_enabled.then(|| (
            crate::tcp_conn::tcp_now_ms().wrapping_add(self.ts_off), self.ts_recent));
        let option_len = segment_opts::SegmentOptions { timestamp, sacks: &[] }.encoded_len();
        let options = segment_opts::append(timestamp, &[], payload);
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + options.len()];
        buf[TCP_HDR_MIN_LEN..].copy_from_slice(&options);
        let mut h = TcpHdr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: self.rcv_nxt,
            data_offset: (TCP_HDR_MIN_LEN + option_len) as u8 / 4,
            flags: flag_bits,
            window: self.current_rcv_window(),
            checksum: 0,
            urg_ptr,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }

    pub(super) fn build_syn_with_opts(&self, flag_bits: u8) -> Vec<u8> {
        self.build_syn_with_opts_at(self.snd_nxt, flag_bits)
    }

    /// Options this handshake segment carries. An opening SYN offers
    /// everything this side supports; a SYN-ACK may only echo what the peer's
    /// SYN offered, because an option the peer never asked for would be read
    /// as this side unilaterally turning a feature on. # C: O(1)
    pub(crate) fn syn_options(&self, flag_bits: u8) -> SynOptions {
        let synack = (flag_bits & flags::ACK) != 0;
        let mss = if self.own_mss != 0 { self.own_mss } else { super::OWN_MSS_DEFAULT };
        SynOptions {
            mss: Some(mss),
            timestamp: (!synack || self.ts_enabled).then(|| (
                crate::tcp_conn::tcp_now_ms().wrapping_add(self.ts_off), self.ts_recent)),
            sack_perm: !synack || self.sack_ok,
            wscale: (!synack || self.wscale_ok).then_some(self.snd_wscale),
            // Whatever the fast-open decision left for this handshake: a
            // freshly minted cookie for a client that asked, one under the
            // current key for a client whose cookie verified under the
            // retired one, or nothing at all.
            fastopen: self.fastopen_opt,
        }
    }

    pub(super) fn build_syn_with_opts_at(&self, seq: u32, flag_bits: u8) -> Vec<u8> {
        self.build_syn_with_data(seq, flag_bits, &[])
    }

    /// A handshake segment carrying `payload`. Only an opening SYN doing a
    /// fast open ever carries one; every retransmission of it goes out empty,
    /// because the retransmit queue holds the data as its own entry.
    /// # C: O(options + payload)
    pub(crate) fn build_syn_with_data(&self, seq: u32, flag_bits: u8, payload: &[u8]) -> Vec<u8> {
        let opts = self.syn_options(flag_bits);
        let opts_len = opts.encoded_len();
        let mut buf = alloc::vec![0u8; TCP_HDR_MIN_LEN + opts_len + payload.len()];
        opts.encode(&mut buf[TCP_HDR_MIN_LEN..TCP_HDR_MIN_LEN + opts_len]);
        buf[TCP_HDR_MIN_LEN + opts_len..].copy_from_slice(payload);
        let mut h = TcpHdr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: self.rcv_nxt,
            data_offset: opts.data_offset(),
            flags: flag_bits,
            window: self.current_rcv_window(),
            checksum: 0,
            urg_ptr: 0,
        };
        h.build_into_ip(self.local.ip, self.remote.ip, &mut buf);
        buf
    }
}
