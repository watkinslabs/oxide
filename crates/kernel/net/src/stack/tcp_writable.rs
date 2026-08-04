// TCP write-readiness predicate gates `EPOLLOUT | EPOLLWRNORM`:
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
// under ~2/3 of `sndbuf`. `TCP_NOTSENT_LOWAT` adds a second, absolute test on
// top: a socket that named one is unwritable while more than that many bytes
// are still queued but not yet sent, which is a no-op at the default.
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

/// `tcp_stream_memory_free`: the `TCP_NOTSENT_LOWAT` arm, an absolute cap on
/// bytes the application has queued but the sender has not put on the wire.
/// A socket that named a low watermark stays unwritable until the unsent
/// backlog falls under it, which is what lets a writer keep exactly that much
/// data buffered instead of filling the whole send buffer.
/// # C: O(1)
pub fn tcp_stream_memory_free(notsent: usize, lowat: u32) -> bool {
    if lowat == u32::MAX { return true; }
    notsent < lowat as usize
}

/// The whole write-readiness predicate: the relative watermark and the
/// unsent-bytes cap must both hold. # C: O(1)
pub fn tcp_writeable_with_lowat(queued: usize, sndbuf: usize, notsent: usize, lowat: u32)
    -> bool
{
    tcp_is_writeable(queued, sndbuf) && tcp_stream_memory_free(notsent, lowat)
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

    #[test]
    fn the_default_low_watermark_never_withholds_writability() {
        assert!(tcp_writeable_with_lowat(0, 16384, 16_000_000, u32::MAX));
    }

    #[test]
    fn a_named_low_watermark_withholds_writability_until_the_backlog_drains() {
        // The relative watermark alone would call this writable; the absolute
        // unsent cap is what keeps the writer parked.
        assert!(tcp_is_writeable(2048, 16384));
        assert!(!tcp_writeable_with_lowat(2048, 16384, 2048, 1024));
        assert!(tcp_writeable_with_lowat(2048, 16384, 1023, 1024));
    }

    #[test]
    fn the_low_watermark_is_exclusive_at_its_own_value() {
        assert!(!tcp_stream_memory_free(1024, 1024));
        assert!(tcp_stream_memory_free(1023, 1024));
    }
}
