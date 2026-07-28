// AF_UNIX write-readiness predicate — Linux `unix_writable`
// (`net/unix/af_unix.c:591-595`):
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

/// Linux `unix_recvq_full_lockless` (`net/unix/af_unix.c:288-291`) applied to
/// the byte-charged destination queue this kernel uses: a connected datagram
/// sender is not writable once the peer's receive queue cannot take more.
/// Only `unix_dgram_poll` uses it, and only when a peer is connected AND the
/// association is not symmetric (`unix_peer(other) != sk`), which is why the
/// socketpair-backed `UnixMsgPair` never consults it.
/// # C: O(1)
pub fn dgram_peer_writable(peer_queued: usize, sndbuf: usize) -> bool {
    peer_queued < sndbuf
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
}
