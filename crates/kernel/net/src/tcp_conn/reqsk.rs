// The request sock a listener keeps for a half-open passive connection: the
// SYN-RECV minisock that exists between the SYN and the accept queue. A request
// is not a connection — it owns no receive buffer, is invisible to `accept`,
// and is driven by a retransmit timer of its own rather than by the data
// retransmit path.
//
// `TCP_DEFER_ACCEPT` is a property of this state, not of a completed child. A
// deferring listener drops the peer's bare acknowledgement instead of
// completing the handshake, so the request stays half-open and its SYN-ACK
// timer keeps running; the peer's own socket therefore shows a handshake still
// in progress rather than an established connection nobody can accept. The
// request becomes a connection only when a segment carries data, or when the
// acknowledgement solicited at the end of the deferring period arrives.

use crate::tcp_hdr::flags;

/// SYN-ACK retransmits a request survives before it is abandoned, when the
/// listening socket named no `TCP_SYNCNT` of its own.
pub const SYNACK_RETRIES_DEFAULT: u8 = 5;

/// Floor the queue-pressure rule may shorten the retransmit ceiling to.
pub const SYNACK_RETRIES_MIN: u8 = 2;

/// Request queue length, doubled, above which the pressure rule engages,
/// regardless of how small a backlog the listener asked for.
pub const PRESSURE_QLEN_MIN: usize = 8;

/// Timer the first SYN-ACK retransmit waits, doubled once per timeout since.
/// It is the same initial timeout `TCP_DEFER_ACCEPT` converts its seconds
/// against, which is what makes a firing the unit the deferral counts in.
pub const TIMEOUT_INIT_NS: u64 = 1_000_000_000;

/// What one firing of a request's timer does.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Recalc {
    /// The request has run out of patience and is dropped.
    pub expire: bool,
    /// This firing retransmits the SYN-ACK.
    pub resend: bool,
}

/// Retransmit and deferral accounting for one half-open passive connection.
/// An active open never carries one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReqSock {
    /// Timer firings this request has survived. It measures the deferring
    /// period in the units `TCP_DEFER_ACCEPT` stores, and doubles the timer.
    pub num_timeout: u8,
    /// The peer acknowledged the SYN-ACK with nothing to deliver. The
    /// handshake is complete from the peer's side; only the data a deferring
    /// listener is waiting for is still owed.
    pub acked: bool,
    /// When the timer next fires. `0` = unarmed, which is every connection
    /// that is not a request.
    pub expires_ns: u64,
}

impl ReqSock {
    /// Timer this request waits before its next firing: the initial timeout
    /// doubled once per timeout survived, capped at the retransmit ceiling.
    /// # C: O(1)
    pub fn timeout_ns(&self, rto_max_ns: u64) -> u64 {
        let doubled = TIMEOUT_INIT_NS.checked_shl(self.num_timeout as u32).unwrap_or(u64::MAX);
        core::cmp::min(doubled, rto_max_ns)
    }

    /// Arm the timer from `now_ns` without counting a firing. # C: O(1)
    pub fn arm(&mut self, now_ns: u64, rto_max_ns: u64) {
        self.expires_ns = now_ns.saturating_add(self.timeout_ns(rto_max_ns)).max(1);
    }

    /// # C: O(1)
    pub fn armed(&self) -> bool { self.expires_ns != 0 }

    /// # C: O(1)
    pub fn due(&self, now_ns: u64) -> bool { self.armed() && now_ns >= self.expires_ns }

    /// Count one firing and re-arm on the doubled timer. # C: O(1)
    pub fn on_timeout(&mut self, now_ns: u64, rto_max_ns: u64) {
        self.num_timeout = self.num_timeout.saturating_add(1);
        self.arm(now_ns, rto_max_ns);
    }

    /// Whether a bare acknowledgement leaves this request half-open. A
    /// deferring listener wants data, so the acknowledgement that would
    /// otherwise complete the handshake is dropped and the peer is left to
    /// finish the connection later. # C: O(1)
    pub fn defers_bare_ack(&self, defer_accept: u8, bare: bool) -> bool {
        bare && self.num_timeout < defer_accept
    }

    /// Whether this firing abandons the request, and whether it retransmits.
    /// # C: O(1)
    pub fn recalc(&self, max_synack_retries: u8, defer_accept: u8) -> Recalc {
        if defer_accept == 0 {
            return Recalc { expire: self.num_timeout >= max_synack_retries, resend: true };
        }
        Recalc {
            // An acknowledged request outlives the retransmit ceiling until
            // the deferring period it was granted has run out.
            expire: self.num_timeout >= max_synack_retries
                && (!self.acked || self.num_timeout >= defer_accept),
            // Nothing is retransmitted while the period runs and the peer has
            // already acknowledged: the request is waiting for data, not for
            // an acknowledgement. One last SYN-ACK goes out as the period ends
            // to solicit the acknowledgement that completes the connection.
            resend: !self.acked || self.num_timeout.saturating_add(1) >= defer_accept,
        }
    }
}

/// Whether the segment acknowledging a SYN-ACK carries nothing a server could
/// be handed: no payload, and no flag that advances the sequence past the SYN.
/// # C: O(1)
pub fn bare_ack(seg_flags: u8, payload_len: usize) -> bool {
    (seg_flags & flags::ACK) != 0
        && (seg_flags & (flags::SYN | flags::FIN | flags::RST)) == 0
        && payload_len == 0
}

/// Whether the timer re-arms rather than dropping the request. A retransmit
/// that could not be sent abandons the request unless the peer had already
/// acknowledged, in which case there is nothing left to retransmit for.
/// # C: O(1)
pub fn reschedules(recalc: Recalc, synack_sent: bool, acked: bool) -> bool {
    !recalc.expire && (!recalc.resend || synack_sent || acked)
}

/// Retransmit ceiling a request runs under once the request queue is more than
/// half the listener's backlog: old requests are given up on rather than
/// letting them crowd out the young ones, which is what separates a loaded
/// server from a flood. `young` counts requests that have not timed out yet.
/// # C: O(retransmits)
pub fn synack_retries_under_pressure(configured: u8, qlen: usize, backlog: usize, young: usize)
    -> u8
{
    if qlen.saturating_mul(2) <= core::cmp::max(PRESSURE_QLEN_MIN, backlog) { return configured; }
    let mut retries = configured;
    let mut doubled = young.saturating_mul(2);
    while retries > SYNACK_RETRIES_MIN {
        if qlen < doubled { break; }
        retries -= 1;
        doubled = doubled.saturating_mul(2);
    }
    retries
}

#[cfg(test)]
#[path = "reqsk_tests.rs"]
mod tests;
