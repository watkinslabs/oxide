// TCP write-readiness predicate — Linux `__sk_stream_is_writeable`
// (`include/net/sock.h:1428-1432`), the exact test `tcp_poll` gates
// `EPOLLOUT | EPOLLWRNORM` on (`net/ipv4/tcp.c:600-616`):
//
//     static inline int sk_stream_min_wspace(const struct sock *sk)
//     { return READ_ONCE(sk->sk_wmem_queued) >> 1; }
//     static inline int sk_stream_wspace(const struct sock *sk)
//     { return READ_ONCE(sk->sk_sndbuf) - READ_ONCE(sk->sk_wmem_queued); }
//     static inline bool __sk_stream_memory_free(const struct sock *sk, int wake)
//     { if (READ_ONCE(sk->sk_wmem_queued) >= READ_ONCE(sk->sk_sndbuf)) return false; ... }
//     static inline bool __sk_stream_is_writeable(const struct sock *sk, int wake)
//     { return sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) &&
//              __sk_stream_memory_free(sk, wake); }
//
// It is a RELATIVE watermark, not `sndbuf >> 1`: free space must be at least
// half of what is already queued, so writability holds while `wmem_queued` is
// under ~2/3 of `sndbuf`. `tcp_stream_memory_free`'s `tcp_notsent_lowat` arm is
// a no-op at the default `tcp_notsent_lowat = UINT_MAX`, and this kernel has no
// `TCP_NOTSENT_LOWAT`, so the two tests above are the whole predicate.
//
// Ungated on purpose (`docs/53`): the arithmetic lives here with its unit
// tests; `TcpEntry::poll_mask` only supplies the two numbers.

/// `__sk_stream_is_writeable` over this kernel's send accounting: `queued` =
/// unsent `send_buf` plus unacknowledged retransmit-queue payload
/// (Linux `sk_wmem_queued`), `sndbuf` = the `SO_SNDBUF` cap `tcp_send`
/// enforces.
/// # C: O(1)
pub fn tcp_is_writeable(queued: usize, sndbuf: usize) -> bool {
    // `sk_stream_memory_free`: a queue at or over the cap is never writable,
    // and checking it first keeps the subtraction below non-negative.
    if queued >= sndbuf { return false; }
    let wspace = sndbuf - queued;
    wspace >= queued / 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_send_queue_is_writeable() {
        assert!(tcp_is_writeable(0, 16384));
    }

    #[test]
    fn two_thirds_is_the_watermark() {
        // wspace >= queued>>1  ⟺  queued <= (2/3)·sndbuf.
        assert!(tcp_is_writeable(10_000, 16384));   // wspace 6384 >= 5000
        assert!(!tcp_is_writeable(11_000, 16384));  // wspace 5384 <  5500
    }

    #[test]
    fn full_send_buffer_is_not_writeable() {
        // Where a non-blocking writer sits when `tcp_send` starts returning
        // EAGAIN. POLLOUT must be clear or the writer spins instead of parking.
        assert!(!tcp_is_writeable(16384, 16384));
    }

    #[test]
    fn over_full_does_not_underflow() {
        assert!(!tcp_is_writeable(usize::MAX, 16384));
    }

    #[test]
    fn watermark_is_relative_not_half_the_buffer() {
        // Exactly half the buffer queued is still writeable — the naive
        // `queued < sndbuf/2` reading of `tcp_poll` would say otherwise.
        assert!(tcp_is_writeable(8192, 16384));
    }

    #[test]
    fn zero_sndbuf_is_never_writeable() {
        assert!(!tcp_is_writeable(0, 0));
    }
}
