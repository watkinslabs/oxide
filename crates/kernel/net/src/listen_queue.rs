// The two queues behind one `listen(2)` backlog, and what overflows them.
//
// A listening socket keeps two populations, not one: requests whose handshake
// is still in flight (the SYN queue) and completed children waiting for
// `accept(2)` (the accept queue). Both are bounded by the SAME number — the
// backlog the caller passed, after the namespace ceiling. `tcp_max_syn_backlog`
// does NOT size the SYN queue; it survives only as the bound on the reserve
// this file's [`admit_unproven_request`] keeps for peers already known good.
//
// What this closes, and why each rung is here:
//
//   * Both fullness predicates are `>`, not `>=`. A backlog of `n` therefore
//     holds `n + 1`. That is not an off-by-one to be tidied away: it is why
//     `listen(fd, 0)` accepts one connection rather than none, which is a
//     documented shape real servers rely on. Refusing at `n` breaks it.
//
//   * A SYN arriving at a listener whose ACCEPT queue is already full is
//     dropped at the SYN, before any request is allocated. Without that rung a
//     listener whose program has stopped calling `accept` still completes
//     handshakes it can never hand over.
//
//   * When the accept queue is full at the third acknowledgement, the request
//     is KEPT, not destroyed. The peer believes the connection is established;
//     destroying our side turns a transient backlog into a connection that
//     hangs until the peer's own retransmits time out. Holding the request
//     lets the SYN-ACK retransmit, and the program draining its queue a moment
//     later completes the handshake normally. `tcp_abort_on_overflow` is what
//     asks for the other behaviour — an immediate reset, telling the peer at
//     once instead of leaving it to retry.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away in silence (`docs/53§4`).

/// `net.ipv4.tcp_max_syn_backlog`. The reference derives its default from the
/// established-hash size and floors it at this value; a listener bounded by a
/// map rather than a fixed hash takes the floor. # C: n/a
pub const DEFAULT_MAX_SYN_BACKLOG: i64 = 128;

/// `net.ipv4.tcp_abort_on_overflow`. Off: hold the request and let the
/// handshake retry. # C: n/a
pub const DEFAULT_ABORT_ON_OVERFLOW: i64 = 0;

/// Whether a listener's SYN queue can take no further request.
///
/// The bound is the listen backlog, NOT `tcp_max_syn_backlog` — the SYN queue
/// stopped having a size of its own, and the accept backlog became the bound
/// on both populations. Sizing it from `tcp_max_syn_backlog` would give a
/// listener a half-open capacity unrelated to the number it asked for.
/// # C: O(1)
pub fn syn_queue_is_full(qlen: usize, max_ack_backlog: usize) -> bool {
    qlen > max_ack_backlog
}

/// Whether a listener's accept queue can take no further completed child.
///
/// `>` for the same reason as [`syn_queue_is_full`]: a backlog of `n` holds
/// `n + 1`, so a zero backlog still admits one connection. # C: O(1)
pub fn accept_queue_is_full(qlen: usize, max_ack_backlog: usize) -> bool {
    qlen > max_ack_backlog
}

/// Whether a request from a peer this host cannot vouch for may take a SYN
/// queue slot.
///
/// The last quarter of `tcp_max_syn_backlog` is held back for peers a previous
/// connection already proved reachable, so that a flood of forged SYNs from
/// addresses this host has never completed a handshake with cannot crowd out
/// the ones it has. The reserve exists only where cookies are off: with
/// cookies the listener has a stateless answer for the overflow and needs no
/// reserve at all.
///
/// `peer_proven` is the caller's cached knowledge of that peer. A host with no
/// cache answers `false` for everyone, which is also what the reference does
/// for a peer it has never spoken to. # C: O(1)
pub fn admit_unproven_request(qlen: usize, max_syn_backlog: i64, syncookies_on: bool,
                              peer_proven: bool) -> bool
{
    if syncookies_on || peer_proven { return true; }
    if max_syn_backlog <= 0 { return true; }
    // Signed on purpose: a queue longer than the bound makes the remaining
    // room negative, which must compare as "less than a quarter", not wrap.
    let remaining = max_syn_backlog - qlen as i64;
    remaining >= max_syn_backlog / 4
}

/// Whether a previous connection to this peer proved it reachable.
///
/// The reference answers this from a per-destination metrics cache populated
/// when a connection to that address closes. This host keeps no such cache, so
/// it can vouch for nobody — which is also the answer the reference gives for
/// every peer on a host whose cache is empty, and the answer it gives forever
/// when the cache is compiled out. The reserve in [`admit_unproven_request`]
/// is therefore held against every peer here rather than only unknown ones.
///
/// One named place on purpose: when the destination metrics cache exists, this
/// is the single call that consults it, and nothing else needs to change.
/// # C: O(1)
pub fn peer_is_proven(_net_ns: u64, _peer: crate::addr::IpAddr) -> bool { false }

/// What a listener does with a completed handshake it has no accept-queue room
/// for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptOverflow {
    /// Keep the request half-open and say nothing. The SYN-ACK retransmits,
    /// and a program that drains its queue completes the handshake on a later
    /// acknowledgement. The peer is not told, because nothing is yet wrong.
    RetainRequest,
    /// Reset at once. The peer learns immediately that the connection it
    /// believes established does not exist here.
    Reset,
}

/// Read `net.ipv4.tcp_abort_on_overflow`. # C: O(1)
pub fn accept_overflow(abort_on_overflow: i64) -> AcceptOverflow {
    if abort_on_overflow != 0 { AcceptOverflow::Reset } else { AcceptOverflow::RetainRequest }
}

#[cfg(test)]
#[path = "listen_queue/tests.rs"]
mod tests;
