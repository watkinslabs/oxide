//! 8250/16550 register offsets and status bits.
//!
//! Shared by the transmit sequencer (`seq.rs`, port-I/O independent) and the
//! per-arch hardware backend, so one definition of the aliased register window
//! serves both the sequencing rules and the code that drives real ports.

/// Receiver buffer on read; transmit holding register on write.
pub(crate) const RBR: u16 = 0;
/// Interrupt enable. Aliased to the divisor-latch high byte while LCR.DLAB=1.
pub(crate) const IER: u16 = 1;
/// Interrupt identification on read; FIFO control on write.
pub(crate) const IIR: u16 = 2;
/// FIFO control (write alias of `IIR`).
pub(crate) const FCR: u16 = 2;
/// Line control; bit 7 = DLAB, which re-aims `RBR`/`IER` at DLL/DLM.
pub(crate) const LCR: u16 = 3;
/// Modem control.
pub(crate) const MCR: u16 = 4;
/// Line status.
pub(crate) const LSR: u16 = 5;
/// Scratch byte, used by the legacy presence probe.
pub(crate) const SCR: u16 = 7;

/// IIR bit 0: set means this port has no interrupt to report. Reading IIR
/// while it reports transmit-empty also RETIRES that source: the edge is
/// consumed by the read, and only a later holding-register-empty transition
/// produces another one.
pub(crate) const IIR_NO_INTERRUPT: u8 = 1 << 0;
/// LSR bit 0: a received byte is waiting in RBR.
pub(crate) const LSR_DATA_READY: u8 = 1 << 0;
/// LSR bit 5: the transmit holding register / FIFO is empty.
pub(crate) const LSR_THR_EMPTY: u8 = 1 << 5;

/// FCR: clear the receive FIFO.
pub(crate) const FCR_CLEAR_RX: u8 = 0x02;
/// FCR: clear the transmit FIFO.
pub(crate) const FCR_CLEAR_TX: u8 = 0x04;
/// LCR bit 7: divisor-latch access.
pub(crate) const LCR_DLAB: u8 = 0x80;
/// MCR bit 5: automatic CTS/RTS flow control.
pub(crate) const MCR_AFE: u8 = 1 << 5;
