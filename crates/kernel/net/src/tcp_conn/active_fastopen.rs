// The client half of fast open on the connection itself: emitting a SYN that
// carries data, and reading what the answer says about it.
//
// The decision that produced the option and the payload is not here — it is
// `crate::tcp_fastopen::client`, ungated, so every rung is a `cargo test`
// away. This file is the mechanism the decision drives.
//
// The retransmit queue holds the SYN and its data as two entries, exactly as
// one wire segment carried them: the SYN alone at the opening sequence
// number, the data at the next. That split is what makes the fallback work.
// A SYN-ACK that acknowledges only the SYN pops the first entry and leaves
// the second, so the bytes go out again on the ordinary path once the
// connection is established, and the program never learns that its fast open
// did not take. A retransmitted SYN goes out bare and alone: bare because the
// option is cleared once the first one is built, alone because nothing behind
// the head of the queue may be sent before the handshake finishes.

use alloc::vec::Vec;

use crate::tcp_conn::fastopen::Cookie;
use crate::tcp_conn::{TcpConn, TcpConnError, UnackedSegment};
use crate::tcp_hdr::flags;
use crate::tcp_state::{TcpEvent, TcpState};

impl TcpConn {
    /// Client active open whose SYN carries `option` and as much of `data` as
    /// fits beside the handshake's own options. Returns the segment and how
    /// many bytes of `data` rode it — zero is an ordinary open, and the
    /// caller still owes those bytes to the stream.
    /// # C: O(bytes carried)
    pub fn active_open_fastopen(&mut self, option: Option<Cookie>, data: &[u8])
        -> Result<(Vec<u8>, usize), TcpConnError>
    {
        let new_state = crate::tcp_state::transition(self.state, TcpEvent::ActiveOpen)
            .ok_or(TcpConnError::BadState)?;
        let seq_start = self.snd_nxt;
        self.snd_wscale = crate::tcp_conn::OWN_WSCALE;
        self.fastopen_opt = option;
        self.syn_fastopen = option.is_some();
        self.syn_fastopen_exp = option.map(|c| c.exp).unwrap_or(false);
        // A request in place of a cookie is the ladder saying it had none to
        // present, which is the one reason a program can read back.
        if option.map(|c| c.is_request()).unwrap_or(false) {
            self.fastopen_client_fail = crate::tcp_fastopen::TFO_COOKIE_UNAVAILABLE;
        }
        let flag_bits = flags::SYN | flags::ECE | flags::CWR;
        let carried = core::cmp::min(data.len(), self.syn_data_room(flag_bits));
        let seg = self.build_syn_with_data(seq_start, flag_bits, &data[..carried]);
        // Excluded from every retry: the option is what a middlebox on this
        // path may have objected to.
        self.fastopen_opt = None;
        self.syn_data = carried > 0;
        self.snd_nxt = seq_start.wrapping_add(1).wrapping_add(carried as u32);
        self.state = new_state;
        self.retx_q.push_back(UnackedSegment {
            seq: seq_start, flags: flags::SYN, payload: Vec::new(),
            last_sent_ns: 0, retries: 0, sacked: false,
        });
        if carried > 0 {
            self.retx_q.push_back(UnackedSegment {
                seq: seq_start.wrapping_add(1),
                flags: flags::ACK | flags::PSH,
                payload: data[..carried].to_vec(),
                last_sent_ns: 0, retries: 0, sacked: false,
            });
        }
        Ok((seg, carried))
    }

    /// Bytes of program data an opening SYN has room for beside the
    /// handshake's own options. The connection's own MSS is the ceiling
    /// because no peer has advertised one yet. # C: O(1)
    fn syn_data_room(&self, flag_bits: u8) -> usize {
        let mss = if self.own_mss != 0 { self.own_mss } else { crate::tcp_conn::OWN_MSS_DEFAULT };
        (mss as usize).saturating_sub(self.syn_options(flag_bits).encoded_len())
    }

    /// Read the SYN-ACK answering an active open that tried to fast open, and
    /// leave what it taught for the layer that owns the namespace's cookie
    /// cache. Answers whose SYN never mentioned fast open teach nothing and
    /// leave nothing. # C: O(option bytes)
    pub(crate) fn learn_from_synack(&mut self, seg: &[u8], ack: u32, syn_seq: u32) {
        if !(self.syn_fastopen || self.syn_data) { return; }
        let cookie = match crate::tcp_conn::fastopen::parse(seg, true) {
            crate::tcp_conn::fastopen::FastOpen::Cookie(c) => Some(c),
            _ => None,
        };
        // The acknowledgement covers the data only if it reaches past the
        // sequence number the SYN itself consumed.
        let past_syn = ack.wrapping_sub(syn_seq.wrapping_add(1));
        let data_acked = self.syn_data && past_syn != 0 && (past_syn & 0x8000_0000) == 0;
        let learned = crate::tcp_fastopen::learn(&crate::tcp_fastopen::Synack {
            syn_fastopen: self.syn_fastopen,
            syn_fastopen_exp: self.syn_fastopen_exp,
            syn_data: self.syn_data,
            total_retrans: self.retx_q.front().map(|s| s.retries).unwrap_or(0),
            cookie,
            data_acked,
        });
        self.syn_data_acked = learned.data_acked;
        if learned.client_fail != crate::tcp_fastopen::TFO_STATUS_NONE {
            self.fastopen_client_fail = learned.client_fail;
        }
        self.fastopen_learned = Some(learned);
    }

    /// Whether this connection's retransmit history names its path a
    /// blackhole for fast open. `expired` is whether it has run out of
    /// retransmit budget altogether. # C: O(1)
    pub fn fastopen_blackholed(&self, expired: bool) -> bool {
        let timeouts = self.retx_q.front().map(|s| s.retries).unwrap_or(0);
        crate::tcp_fastopen::detect(self.syn_fastopen, self.syn_data, self.syn_data_acked,
            timeouts, expired)
    }

    /// A reset arriving out of order on a fast-opened connection that has
    /// received nothing is the shape a middlebox interfering with fast open
    /// produces, not the shape a peer refusing the connection does.
    /// # C: O(1)
    pub fn fastopen_reset_is_blackhole(&self) -> bool {
        self.syn_fastopen && self.state == TcpState::Established && self.data_segs_in == 0
    }
}

#[cfg(test)]
#[path = "active_fastopen_tests.rs"]
mod tests;
