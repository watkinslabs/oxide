//! Allocation-free 8250 transmit queue and interrupt state.
//!
//! Linux serial core copies ordinary writes into `port->state->port.xmit_fifo`,
//! enables `UART_IER_THRI` on the empty-to-nonempty transition, and lets
//! `serial8250_tx_chars()` move at most `tx_loadsz` bytes into the hardware
//! FIFO per interrupt.  Keep that policy independent of port I/O so its
//! ordering and interrupt transitions are host-testable.

pub(crate) const IER_RX_DATA: u8 = 1 << 0;
pub(crate) const IER_TX_EMPTY: u8 = 1 << 1;
pub(crate) const TX_FIFO_DEPTH: usize = 16;
pub(crate) const TX_RING_CAPACITY: usize = 64 * 1024;
/// Linux serial8250 shared-IRQ bound. Edge-triggered ISA lines must be
/// serviced until every port deasserts the line, without trusting broken
/// hardware to do so forever.
pub(crate) const IRQ_PASS_LIMIT: usize = 512;

/// Service one 8250 IRQ source until IIR says the edge-triggered line is
/// deasserted, or until the Linux `PASS_LIMIT` safety bound is reached.
/// Returns whether any pass claimed the source.
/// # C: O(IRQ_PASS_LIMIT)
pub(crate) fn service_irq_chain(mut service_one: impl FnMut() -> bool) -> bool {
    let mut handled = false;
    for _ in 0..IRQ_PASS_LIMIT {
        if !service_one() { break; }
        handled = true;
    }
    handled
}

/// Preserve modem-control state while raising the PC UART interrupt gate.
/// Linux sets OUT2 whenever an IRQ-backed 8250 port is initialized.
/// # C: O(1)
pub(crate) const fn irq_mcr(current: u8) -> u8 { current | (1 << 3) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Transition {
    pub(crate) count: usize,
    pub(crate) ier_changed: bool,
}

struct ByteRing<const N: usize> {
    bytes: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> ByteRing<N> {
    const fn new() -> Self {
        assert!(N > 0 && N.is_power_of_two());
        Self { bytes: [0; N], head: 0, len: 0 }
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn push(&mut self, src: &[u8]) -> usize {
        let count = src.len().min(N - self.len);
        for &byte in &src[..count] {
            let tail = (self.head + self.len) & (N - 1);
            self.bytes[tail] = byte;
            self.len += 1;
        }
        count
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let byte = self.bytes[self.head];
        self.head = (self.head + 1) & (N - 1);
        self.len -= 1;
        Some(byte)
    }
}

/// Runtime xmit FIFO plus the one authoritative 8250 IER shadow.
pub(crate) struct TxEngine<const N: usize> {
    ring: ByteRing<N>,
    ier: u8,
    runtime: bool,
    dropped: u64,
}

impl<const N: usize> TxEngine<N> {
    pub(crate) const fn new() -> Self {
        Self { ring: ByteRing::new(), ier: 0, runtime: false, dropped: 0 }
    }

    /// Begin interrupt-driven runtime operation. RX remains enabled while the
    /// TX-empty bit is toggled with queue occupancy.
    /// # C: O(1)
    pub(crate) fn start_runtime(&mut self) {
        self.ring.clear();
        self.ier = IER_RX_DATA;
        self.runtime = true;
        self.dropped = 0;
    }

    /// Stop all UART interrupts without discarding queued bytes. Shutdown can
    /// then poll those bytes out in order before switching to the late-console
    /// synchronous fallback.
    /// # C: O(1)
    pub(crate) fn stop_runtime(&mut self) {
        self.ier = 0;
        self.runtime = false;
    }

    /// Discard every queued byte during device removal. # C: O(1)
    pub(crate) fn discard(&mut self) { self.ring.clear(); }
    /// Whether ordinary writes use the interrupt-driven queue. # C: O(1)
    pub(crate) const fn runtime(&self) -> bool { self.runtime }
    /// Current authoritative interrupt-enable register shadow. # C: O(1)
    pub(crate) const fn ier(&self) -> u8 { self.ier }

    /// Copy as much as fits and arm THRI exactly on the disabled-to-enabled
    /// transition. The 64 KiB queue matches the in-memory klog capacity; an
    /// overload is counted and drops only the new suffix, never reorders data.
    /// # C: O(bytes.len())
    pub(crate) fn enqueue(&mut self, bytes: &[u8]) -> Transition {
        let old_ier = self.ier;
        let count = self.ring.push(bytes);
        self.dropped = self.dropped.saturating_add((bytes.len() - count) as u64);
        if count != 0 {
            self.ier |= IER_TX_EMPTY;
        }
        Transition { count, ier_changed: self.ier != old_ier }
    }

    /// Move one hardware-FIFO load out of the ring. Emptying the ring clears
    /// THRI so an idle UART cannot interrupt continuously.
    /// # C: O(dst.len())
    pub(crate) fn take_fifo(&mut self, dst: &mut [u8]) -> Transition {
        let old_ier = self.ier;
        let mut count = 0;
        while count < dst.len() {
            let Some(byte) = self.ring.pop() else { break };
            dst[count] = byte;
            count += 1;
        }
        if self.ring.len == 0 {
            self.ier &= !IER_TX_EMPTY;
        }
        Transition { count, ier_changed: self.ier != old_ier }
    }

    /// Pop one queued byte for the shutdown polling fallback. # C: O(1)
    pub(crate) fn pop_for_poll(&mut self) -> Option<u8> { self.ring.pop() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_write_arms_once_and_empty_irq_disarms() {
        let mut tx = TxEngine::<8>::new();
        tx.start_runtime();
        assert_eq!(tx.ier(), IER_RX_DATA);

        assert_eq!(tx.enqueue(b"abc"), Transition { count: 3, ier_changed: true });
        assert_eq!(tx.ier(), IER_RX_DATA | IER_TX_EMPTY);
        assert_eq!(tx.enqueue(b"de"), Transition { count: 2, ier_changed: false });

        let mut first = [0; 2];
        assert_eq!(tx.take_fifo(&mut first), Transition { count: 2, ier_changed: false });
        assert_eq!(&first, b"ab");

        let mut last = [0; TX_FIFO_DEPTH];
        assert_eq!(tx.take_fifo(&mut last), Transition { count: 3, ier_changed: true });
        assert_eq!(&last[..3], b"cde");
        assert_eq!(tx.ier(), IER_RX_DATA);
    }

    #[test]
    fn circular_queue_preserves_order_across_wrap() {
        let mut tx = TxEngine::<8>::new();
        tx.start_runtime();
        assert_eq!(tx.enqueue(b"abcdef").count, 6);
        let mut first = [0; 5];
        assert_eq!(tx.take_fifo(&mut first).count, 5);
        assert_eq!(&first, b"abcde");
        assert_eq!(tx.enqueue(b"ghijk").count, 5);
        let mut rest = [0; 8];
        assert_eq!(tx.take_fifo(&mut rest).count, 6);
        assert_eq!(&rest[..6], b"fghijk");
    }

    #[test]
    fn overflow_drops_only_new_suffix_and_is_counted() {
        let mut tx = TxEngine::<4>::new();
        tx.start_runtime();
        assert_eq!(tx.enqueue(b"abcdef").count, 4);
        assert_eq!(tx.dropped, 2);
        let mut out = [0; 4];
        assert_eq!(tx.take_fifo(&mut out).count, 4);
        assert_eq!(&out, b"abcd");
    }

    #[test]
    fn shutdown_keeps_pending_bytes_for_ordered_poll_flush() {
        let mut tx = TxEngine::<8>::new();
        tx.start_runtime();
        tx.enqueue(b"late");
        tx.stop_runtime();
        assert!(!tx.runtime());
        assert_eq!(tx.ier(), 0);
        assert_eq!(tx.pop_for_poll(), Some(b'l'));
        assert_eq!(tx.pop_for_poll(), Some(b'a'));
        assert_eq!(tx.pop_for_poll(), Some(b't'));
        assert_eq!(tx.pop_for_poll(), Some(b'e'));
        assert_eq!(tx.pop_for_poll(), None);
    }

    #[test]
    fn irq_chain_runs_until_the_edge_triggered_line_deasserts() {
        let mut pending = 3usize;
        let mut calls = 0usize;
        assert!(service_irq_chain(|| {
            calls += 1;
            if pending == 0 { return false; }
            pending -= 1;
            true
        }));
        assert_eq!(calls, 4);
        assert_eq!(pending, 0);
    }

    #[test]
    fn irq_chain_caps_a_source_that_never_deasserts() {
        let mut calls = 0usize;
        assert!(service_irq_chain(|| { calls += 1; true }));
        assert_eq!(calls, IRQ_PASS_LIMIT);
        assert!(!service_irq_chain(|| false));
    }

    #[test]
    fn irq_modem_control_preserves_lines_and_raises_out2() {
        assert_eq!(irq_mcr(0), 0x08);
        assert_eq!(irq_mcr(0x03), 0x0b);
        assert_eq!(irq_mcr(0xff), 0xff);
    }
}
