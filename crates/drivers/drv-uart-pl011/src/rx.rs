//! PL011 RX interrupt service loop — the arch-independent, host-tested half.
//!
//! Two properties are load-bearing and were both wrong when the console could
//! be typed at but only answered the first burst:
//!
//! 1. **Drain the FIFO empty, not a fixed small count.** A drain that stops
//!    while bytes remain leaves the line asserted with data the tty never sees.
//! 2. **Never explicitly clear the RX / RX-timeout interrupt.** Both are
//!    cleared by the hardware as a side effect of emptying the FIFO. Writing
//!    them to the clear register after the drain destroys the indication for
//!    bytes that arrived *during* the drain — the FIFO then holds data with no
//!    interrupt left to report it, and the line stops delivering input
//!    permanently. Instead re-read the masked interrupt status and take
//!    another pass while it is still asserted.
//!
//! Both are why this module exists as pure logic over closures: the ordering
//! is the contract, and it is verified in `tests` against a FIFO model that
//! refills mid-drain.

/// Bytes drained per pass. One pass is expected to empty the FIFO; the cap
/// only bounds a pathological device that keeps producing.
pub const FIFO_DRAIN_LIMIT: u32 = 256;
/// Re-check passes per interrupt before giving up and returning (the line
/// stays asserted, so the next interrupt resumes).
pub const ISR_PASS_LIMIT: u32 = 256;

/// Service one PL011 RX interrupt.
///
/// `read_byte` yields the next FIFO byte, or `None` once RXFE is set.
/// `rx_pending` reports the masked RX / RX-timeout interrupt status after a
/// drain. `dlv` receives every byte in FIFO order. Returns the byte count.
/// # C: O(bytes pending)
pub fn service_rx(
    mut read_byte: impl FnMut() -> Option<u8>,
    mut rx_pending: impl FnMut() -> bool,
    mut dlv: impl FnMut(u8),
) -> u32 {
    let mut total = 0u32;
    let mut passes = 0u32;
    loop {
        let mut taken = 0u32;
        while taken < FIFO_DRAIN_LIMIT {
            match read_byte() {
                Some(b) => { dlv(b); taken += 1; }
                None => break,
            }
        }
        total += taken;
        passes += 1;
        if passes >= ISR_PASS_LIMIT || !rx_pending() { return total; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    /// FIFO model: at most `depth` bytes visible at a time, topped up from a
    /// backlog as space frees — the behaviour of a host-fed serial chardev.
    /// `hold_until` withholds the backlog for that many reads, which is how a
    /// test places an arrival *during* the drain rather than before it.
    struct Fifo {
        visible: alloc::vec::Vec<u8>,
        backlog: alloc::vec::Vec<u8>,
        depth: usize,
        reads: usize,
        hold_until: usize,
    }

    impl Fifo {
        fn new(all: &[u8], depth: usize, hold_until: usize) -> Self {
            let n = all.len().min(depth);
            Fifo {
                visible: all[..n].to_vec(),
                backlog: all[n..].to_vec(),
                depth,
                reads: 0,
                hold_until,
            }
        }
        fn read(&mut self) -> Option<u8> {
            self.reads += 1;
            let b = if self.visible.is_empty() { None } else { Some(self.visible.remove(0)) };
            self.refill();
            b
        }
        fn refill(&mut self) {
            if self.reads < self.hold_until { return; }
            while !self.backlog.is_empty() && self.visible.len() < self.depth {
                self.visible.push(self.backlog.remove(0));
            }
        }
        /// RXIS/RTIS are asserted while the FIFO is non-empty; emptying it is
        /// what clears them in hardware.
        fn pending(&self) -> bool { !self.visible.is_empty() }
    }

    fn run(all: &[u8], depth: usize, hold_until: usize) -> alloc::vec::Vec<u8> {
        let fifo = RefCell::new(Fifo::new(all, depth, hold_until));
        let got = RefCell::new(alloc::vec::Vec::new());
        service_rx(
            || fifo.borrow_mut().read(),
            || { let f = fifo.borrow(); let p = f.pending(); drop(f); p },
            |b| got.borrow_mut().push(b),
        );
        got.into_inner()
    }

    /// A burst that fits the FIFO arrives whole.
    #[test]
    fn short_burst_is_delivered_in_order() {
        let msg = b"hi\r";
        assert_eq!(run(msg, 16, 0), msg.to_vec());
    }

    /// A typed line longer than the FIFO must still arrive whole. Draining a
    /// fixed 16 bytes and stopping truncated exactly at the FIFO depth — the
    /// console echoed the first 16 characters of a typed command and dropped
    /// the rest.
    #[test]
    fn burst_longer_than_the_fifo_is_not_truncated() {
        let msg = b"echo SHELL_ALIVE_MARKER\r";
        assert!(msg.len() > 16);
        assert_eq!(run(msg, 16, 0), msg.to_vec());
    }

    /// Bytes that land in the FIFO *during* the drain are picked up by the
    /// re-check pass. This is the case an explicit post-drain interrupt clear
    /// used to lose: the indication for these bytes was cleared after they
    /// arrived, so nothing ever reported them and the line went permanently
    /// silent.
    #[test]
    fn bytes_arriving_mid_drain_are_still_delivered() {
        let msg = b"echo SHELL_ALIVE_MARKER\r";
        // 16 = the last read of the first FIFO-full, i.e. the backlog appears
        // exactly at the moment the old code would have written the clear.
        for hold_until in [8usize, 15, 16, 17] {
            assert_eq!(run(msg, 16, hold_until), msg.to_vec(), "hold_until {hold_until}");
        }
    }

    /// An empty FIFO costs exactly one pass and delivers nothing.
    #[test]
    fn empty_fifo_delivers_nothing() {
        assert!(run(b"", 16, 0).is_empty());
    }

    /// A device that never stops asserting cannot spin the handler forever.
    #[test]
    fn a_stuck_line_is_bounded_by_the_pass_limit() {
        let n = RefCell::new(0u32);
        let got = RefCell::new(0u32);
        service_rx(
            || { let mut c = n.borrow_mut(); *c += 1; Some(b'x') },
            || true,
            |_| { *got.borrow_mut() += 1; },
        );
        assert_eq!(*got.borrow(), FIFO_DRAIN_LIMIT * ISR_PASS_LIMIT);
    }
}
