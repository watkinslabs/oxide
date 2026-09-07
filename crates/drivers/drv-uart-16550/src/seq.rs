//! 8250 transmit sequencing — the register order, independent of port I/O.
//!
//! The 8250 transmit-empty interrupt is a RETIRED source, not a level: reading
//! IIR while it reports transmit-empty clears that source, and the part is only
//! obliged to raise it again on the next holding-register-empty TRANSITION. A
//! service pass that reads IIR and then declines to write the holding register
//! therefore consumes an edge without producing the transition that would
//! replace it, and a queue that is armed, loaded and idle stays that way for
//! ever: the console goes permanently silent on a machine that is still
//! running. Some parts do not re-raise the source when the enable bit goes
//! 0 -> 1 over an already-empty register either, which loses the arming edge
//! the same way.
//!
//! Both holes are closed the way the reference closes them:
//!   * arming the transmit interrupt over an empty holding register transmits
//!     inline instead of waiting for an interrupt that may never arrive;
//!   * a periodic poll re-derives the transmit-empty source from the port's own
//!     state (armed + loaded + holding register empty) and services it, which
//!     recovers a lost edge whatever consumed it.
//!
//! Keeping the rules here rather than beside `inb`/`outb` is what lets a host
//! test drive them against a modelled part that reproduces the stall.

use crate::regs::{IER, IIR, IIR_NO_INTERRUPT, LSR, LSR_THR_EMPTY, RBR};
use crate::tx::{self, TxEngine};

/// The port's register window. One method pair so the sequencer is generic over
/// real port I/O and over a host model (no `dyn`, per `07§5`).
pub(crate) trait PortIo {
    /// Read the byte register at `off` from the port base.
    fn read(&self, off: u16) -> u8;
    /// Write `v` to the byte register at `off` from the port base.
    fn write(&self, off: u16, v: u8);
}

/// Move at most one hardware-FIFO load from the xmit ring into the port,
/// publishing the interrupt-enable change that emptying the ring produces.
/// Returns the byte count written. # C: O(TX_FIFO_DEPTH)
pub(crate) fn tx_chars<const N: usize, IO: PortIo>(eng: &mut TxEngine<N>, io: &IO) -> usize {
    let mut fifo = [0u8; tx::TX_FIFO_DEPTH];
    let t = eng.take_fifo(&mut fifo);
    for &byte in &fifo[..t.count] { io.write(RBR, byte); }
    if t.ier_changed { io.write(IER, eng.ier()); }
    t.count
}

/// Queue `bytes` and arm the transmit-empty interrupt.
///
/// On the disarmed -> armed transition the holding register is sampled and, if
/// already empty, one FIFO load is transmitted inline. The reference gates that
/// inline transmit on a startup probe whose own commentary calls the result
/// unreliable on virtualised parts; it is unconditional here because it can
/// only move bytes the interrupt would have moved, and skipping it is the
/// difference between a console and a silent one.
/// # C: O(bytes.len() + TX_FIFO_DEPTH)
pub(crate) fn start_tx<const N: usize, IO: PortIo>(eng: &mut TxEngine<N>, io: &IO, bytes: &[u8]) {
    let t = eng.enqueue(bytes);
    if !t.ier_changed { return; }
    io.write(IER, eng.ier());
    if eng.ier() & tx::IER_TX_EMPTY == 0 { return; }
    if io.read(LSR) & LSR_THR_EMPTY != 0 { tx_chars(eng, io); }
}

/// Transmit half of one interrupt service pass: fill the FIFO when the port
/// reports the holding register empty and the queue is armed. # C: O(TX_FIFO_DEPTH)
pub(crate) fn irq_tx<const N: usize, IO: PortIo>(eng: &mut TxEngine<N>, io: &IO, lsr: u8) {
    if lsr & LSR_THR_EMPTY == 0 { return; }
    if eng.ier() & tx::IER_TX_EMPTY == 0 { return; }
    tx_chars(eng, io);
}

/// Re-derive a transmit-empty source the port will not raise again and service
/// it. An armed, loaded queue whose holding register is empty is by definition
/// owed an interrupt; when IIR nonetheless reports none, the edge was consumed
/// without being serviced and nothing else would ever move those bytes.
///
/// Reports whether it recovered a LOST edge (IIR had nothing to give), so a
/// caller can count the condition rather than merely survive it. Costs a single
/// ring check while the queue is empty, which is the whole of an idle console.
/// # C: O(1) port reads; O(TX_FIFO_DEPTH) writes
pub(crate) fn poll_lost_tx<const N: usize, IO: PortIo>(eng: &mut TxEngine<N>, io: &IO) -> bool {
    if !eng.runtime() || !eng.queued() { return false; }
    if eng.ier() & tx::IER_TX_EMPTY == 0 { return false; }
    let iir = io.read(IIR);
    let lsr = io.read(LSR);
    // Still transmitting: the completion transition is still owed and will
    // arrive on its own. Nothing to recover, and nothing has been consumed
    // that the handler needed, because this pass transmits whenever it reads a
    // pending source out of IIR.
    if lsr & LSR_THR_EMPTY == 0 { return false; }
    let lost = iir & IIR_NO_INTERRUPT != 0;
    tx_chars(eng, io);
    lost
}
