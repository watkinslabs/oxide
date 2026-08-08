// AF_UNIX write-readiness predicate:
//
//     static int unix_writable(const struct sock *sk, unsigned char state)
//     {
//         return state != TCP_LISTEN &&
//             (refcount_read(&sk->sk_wmem_alloc) << 2) <= READ_ONCE(sk->sk_sndbuf);
//     }
//
// A quarter-of-sndbuf watermark, NOT "any space at all". `sk_wmem_alloc` is
// charged to the SENDER and stays charged until the receiver frees the skb, so
// it measures exactly what this kernel calls "bytes queued in the direction
// this end writes". `unix_poll` (stream/seqpacket) consults nothing else — no
// peer state at all; `unix_dgram_poll` adds the connected-peer backlog test
// separately (see `dgram_peer_writable`).
//
// Ungated on purpose (`docs/53`): the decision lives here and is unit-tested,
// while the `poll_mask` callers stay thin.

/// Linux `unix_writable`'s watermark for a non-listening AF_UNIX socket.
/// `queued` = bytes this end has outstanding in its write direction,
/// `sndbuf` = the send cap the send path enforces (`SO_SNDBUF`, floored at
/// `TCP_SNDBUF_DEFAULT`), so poll and `sendmsg` read the same number.
/// # C: O(1)
pub fn unix_writable(queued: usize, sndbuf: usize) -> bool {
    // `queued <= sndbuf / 4` is `(queued << 2) <= sndbuf` over the integers,
    // without the shift's overflow. A saturating multiply is NOT equivalent:
    // it pins the product at `usize::MAX`, which compares equal to a
    // `usize::MAX` cap and reports a hopelessly full queue as writable —
    // fail-open, i.e. the spin this predicate exists to stop.
    queued <= sndbuf / 4
}

/// Applied to
/// the byte-charged destination queue this kernel uses: a connected datagram
/// sender is not writable once the peer's receive queue cannot take more.
/// Only `unix_dgram_poll` uses it, and only when a peer is connected AND the
/// association is not symmetric (`unix_peer(other) != sk`), which is why the
/// socketpair-backed `UnixMsgPair` never consults it.
/// # C: O(1)
pub fn dgram_peer_writable(peer_queued: usize, sndbuf: usize) -> bool {
    peer_queued < sndbuf
}

// A connected datagram peer is a SOCKET, so every test against it is an
// identity comparison, never an address one: two names can resolve to one
// receive queue, and a name can outlive the socket that published it, so an
// address-keyed stand-in both under- and over-reports the relation.
//
// The two tests below are one relation read twice:
//
//   symmetric  ⇔  the destination's connected peer IS the sender
//   may-send   ⇔  the destination has no connected peer at all, OR symmetric
//
// Identities are the destination's and the sender's stable receive-queue ids.
// `None` for the sender means it owns no receive queue at all — a socket
// nothing can connect to, hence never symmetric, hence allowed to address only
// an unconnected destination.

/// The destination is connected back to the sender: a symmetrically connected
/// pair, which is what a datagram `socketpair` produces.
///
/// Gates the receive-queue-full flow control on BOTH the send and the poll
/// side — such a pair is bounded by the sender's own write memory instead, and
/// applying the backlog test to one side alone is what reports a writer
/// "writable" and then hands it EAGAIN forever.
/// # C: O(1)
pub fn dgram_symmetric_pair(dest_peer: Option<u64>, sender: Option<u64>) -> bool {
    match (dest_peer, sender) {
        (Some(back), Some(mine)) => back == mine,
        _ => false,
    }
}

/// Whether this sender may address this destination at all. A datagram socket
/// connected to a third party accepts traffic from that party alone; anyone
/// else is refused with EPERM, both when connecting to it and on every
/// individual send.
/// # C: O(1)
pub fn dgram_may_send(dest_peer: Option<u64>, sender: Option<u64>) -> bool {
    dest_peer.is_none() || dgram_symmetric_pair(dest_peer, sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queue_is_writable() {
        assert!(unix_writable(0, 16384));
    }

    #[test]
    fn quarter_watermark_is_the_boundary() {
        // `(queued << 2) <= sndbuf` — exactly a quarter still counts.
        assert!(unix_writable(4096, 16384));
        assert!(!unix_writable(4097, 16384));
    }

    #[test]
    fn full_send_buffer_is_not_writable() {
        // The state a non-blocking writer reaches right before EAGAIN: poll
        // must clear POLLOUT here or the writer spins.
        assert!(!unix_writable(16384, 16384));
    }

    #[test]
    fn zero_sndbuf_only_admits_an_empty_queue() {
        assert!(unix_writable(0, 0));
        assert!(!unix_writable(1, 0));
    }

    #[test]
    fn huge_queue_does_not_overflow_into_writable() {
        assert!(!unix_writable(usize::MAX, usize::MAX));
    }

    #[test]
    fn peer_backlog_clears_only_at_capacity() {
        assert!(dgram_peer_writable(0, 16384));
        assert!(dgram_peer_writable(16383, 16384));
        assert!(!dgram_peer_writable(16384, 16384));
    }

    // Queue identities; the values are arbitrary but distinct.
    const SENDER: u64 = 7;
    const DEST: u64 = 8;
    const THIRD: u64 = 9;

    #[test]
    fn unconnected_destination_accepts_anyone() {
        assert!(dgram_may_send(None, Some(SENDER)));
        assert!(dgram_may_send(None, None));
        assert!(!dgram_symmetric_pair(None, Some(SENDER)));
    }

    #[test]
    fn destination_connected_to_a_third_party_refuses_the_sender() {
        assert!(!dgram_may_send(Some(THIRD), Some(SENDER)));
    }

    #[test]
    fn destination_connected_back_to_the_sender_is_symmetric_and_allowed() {
        assert!(dgram_symmetric_pair(Some(SENDER), Some(SENDER)));
        assert!(dgram_may_send(Some(SENDER), Some(SENDER)));
    }

    #[test]
    fn a_sender_without_a_receive_queue_is_never_the_destinations_peer() {
        // Nothing can be connected to a socket that publishes no queue, so a
        // connected destination refuses it and it is never symmetric.
        assert!(!dgram_symmetric_pair(Some(DEST), None));
        assert!(!dgram_may_send(Some(DEST), None));
    }

    #[test]
    fn identity_not_address_decides_symmetry() {
        // The sender bound no address, yet the destination's stored peer is
        // its queue: symmetric. An address-keyed comparison has nothing to
        // compare here and would miss it.
        assert!(dgram_symmetric_pair(Some(SENDER), Some(SENDER)));
        // Distinct queues never become symmetric however their names compare.
        assert!(!dgram_symmetric_pair(Some(DEST), Some(SENDER)));
    }
}
