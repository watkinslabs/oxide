// Opening a connection from a cookie nobody stored a request for.
//
// The ordinary passive open reaches SYN-RECV by processing a SYN. This one
// never saw the SYN — it was answered and forgotten a minute or less ago — so
// the state that SYN would have left is reconstructed from what the returning
// acknowledgement proves, and the acknowledgement itself is then fed to the
// state machine exactly as it would have been. That keeps one path through
// the handshake completion, including a third acknowledgement that carries
// data, rather than a second one that would drift.
//
// No target gate: this is where the reconstruction is decided, so it lives
// where `cargo test` compiles it (`docs/53§4`).

use crate::syncookies::Rebuild;
use crate::tcp_conn::TcpConn;
use crate::tcp_state::TcpState;

impl TcpConn {
    /// The cookie this passive open is being answered with, if it is one at
    /// all. An MSS of zero is not a legal announcement, so it is what names an
    /// ordinary passive open. # C: O(1)
    pub fn syncookie(&self) -> Option<crate::syncookies::Request> {
        (self.syncookie_mss != 0).then_some(crate::syncookies::Request {
            isn: self.syncookie_isn, mss: self.syncookie_mss })
    }

    /// Answer this passive open with a cookie rather than a stored request.
    /// # C: O(1)
    pub fn set_syncookie(&mut self, req: crate::syncookies::Request) {
        self.syncookie_isn = req.isn;
        self.syncookie_mss = req.mss;
    }

    /// Put this connection into the state the forgotten SYN would have left,
    /// so the acknowledgement that carried the cookie back can complete the
    /// handshake against it.
    ///
    /// `src_ip` is the peer's address as the acknowledgement carried it. The
    /// sequence numbers are the ones the vanished SYN-ACK established: this
    /// side sent the cookie and one sequence for the SYN flag, and the peer's
    /// stream starts one past its own initial sequence number. # C: O(1)
    pub fn open_from_cookie(&mut self, src_ip: crate::addr::IpAddr, port: u16, req: &Rebuild) {
        self.remote = crate::tcp_conn::Endpoint { ip: src_ip, port };
        self.rcv_nxt = req.peer_isn.wrapping_add(1);
        self.rcv_read_seq = self.rcv_nxt;
        self.snd_una = req.isn;
        self.snd_nxt = req.isn.wrapping_add(1);
        self.peer_mss = req.mss;
        if req.opts.tstamp_ok {
            self.ts_enabled = true;
            self.ts_recent = req.ts_recent;
            self.ts_off = req.ts_off;
        }
        if let Some(scale) = req.opts.wscale {
            self.wscale_ok = true;
            self.rcv_wscale = scale;
            self.snd_wscale = crate::tcp_conn::OWN_WSCALE;
        }
        self.sack_ok = req.opts.sack_ok;
        self.ecn_enabled = req.opts.ecn_ok;
        self.snd_wnd = (req.window as u32) << self.rcv_wscale;
        // The request stage is over before it began: there is no SYN-ACK to
        // retransmit and no request timer to run, because nothing was ever
        // held to time out.
        self.state = TcpState::SynRecv;
        self.rsk = crate::tcp_conn::reqsk::ReqSock::default();
    }
}

#[cfg(test)]
#[path = "syncookie_tests.rs"]
mod tests;
