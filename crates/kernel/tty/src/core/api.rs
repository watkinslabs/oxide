use crate::ldisc::{Sig, TtyDriverHooks};
use crate::pty::TERMIOS_BYTES;

/// TCFLSH queue selector (the ioctl arg). Linux uapi: TCIFLUSH=0 (input),
/// TCOFLUSH=1 (output), TCIOFLUSH=2 (both). Typed so the ioctl shim never
/// passes a bare literal (07§5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtyFlush {
    /// TCIFLUSH — discard unread input.
    Input,
    /// TCOFLUSH — discard untransmitted output.
    Output,
    /// TCIOFLUSH — discard both.
    Both,
}

impl TtyFlush {
    /// Decode the TCFLSH ioctl arg (0/1/2). Unknown values map to `Both`
    /// (conservative — Linux rejects with EINVAL, but flushing more is
    /// harmless and keeps the shim total). # C: O(1)
    pub fn from_arg(arg: u64) -> Self {
        match arg { 0 => Self::Input, 1 => Self::Output, _ => Self::Both }
    }
    /// True when input should be flushed. # C: O(1)
    pub fn input(self) -> bool { matches!(self, Self::Input | Self::Both) }
    /// True when output should be flushed. # C: O(1)
    pub fn output(self) -> bool { matches!(self, Self::Output | Self::Both) }
}

/// TCXONC action (tcflow(3) arg). Linux uapi: TCOOFF=0 (suspend output),
/// TCOON=1 (resume output), TCIOFF=2 (transmit a STOP char to suspend the
/// peer's transmission into us), TCION=3 (transmit a START char to resume
/// it). Typed so the ioctl shim never passes a bare literal (07§5). The
/// shim decodes via `from_arg`, which rejects out-of-range args (EINVAL) —
/// unlike `TtyFlush::from_arg` it validates, because a bogus action must
/// not silently suspend output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtyFlow {
    /// TCOOFF — suspend output (hold the write path until resumed).
    OutputOff,
    /// TCOON — resume output (clear the suspend flag; wake parked writers).
    OutputOn,
    /// TCIOFF — transmit a STOP char (^S) toward the input source.
    InputOff,
    /// TCION — transmit a START char (^Q) toward the input source.
    InputOn,
}

impl TtyFlow {
    /// Decode the TCXONC ioctl arg (0..=3). Out-of-range → `None` so the
    /// shim returns EINVAL (Linux rejects a bad action rather than
    /// treating it as a no-op success). # C: O(1)
    pub fn from_arg(arg: u64) -> Option<Self> {
        match arg {
            0 => Some(Self::OutputOff),
            1 => Some(Self::OutputOn),
            2 => Some(Self::InputOff),
            3 => Some(Self::InputOn),
            _ => None,
        }
    }
}

/// Outcome of a blocking `TtyStruct::read`. The syscall layer maps these:
/// `Bytes(n)` → `n`, `Eof` → `0`, `Interrupted` → `-EINTR`. Returning an
/// explicit enum (vs overloading `usize`) keeps the EINTR signal honest
/// through every caller (static_console, vt_tty, ConsoleInode).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    /// `n` bytes were drained into the caller buffer (n ≥ 1, or 0 only on
    /// a VMIN==0/VTIME timeout polling read that found nothing).
    Bytes(usize),
    /// End of input (canonical ^D at line start) — return 0 to userspace.
    Eof,
    /// A pending unblocked signal interrupted the blocking wait — the
    /// syscall layer returns `-EINTR` (Linux `n_tty_read` → `-ERESTARTSYS`
    /// / `-EINTR`).
    Interrupted,
}

impl ReadOutcome {
    /// Map to the byte count for callers that still expose `usize`
    /// (treats Eof and Interrupted as 0 — only the syscall layer that
    /// threads EINTR should consume the enum directly).
    /// # C: O(1)
    pub fn bytes_or_zero(self) -> usize {
        match self { ReadOutcome::Bytes(n) => n, _ => 0 }
    }
}

/// What the tty core needs from a concrete device (Linux
/// `tty_operations`). The VT console driver (write → emulator → consw),
/// the serial driver (write → UART TX), and the test `RecordingDriver`
/// implement it. Generic — monomorphized, never `dyn` (07§5).
///
/// The driver is ALSO the RX source: on receiving bytes from the device
/// (kbd / UART RX), it calls `TtyStruct::receive_from_driver`, which
/// feeds the port flip buffer → ldisc → wakes readers.
pub trait TtyDriver {
    /// Push already-processed output bytes to the device (the ldisc has
    /// run OPOST / built echo bytes; the driver renders them verbatim).
    /// This is what the ldisc's `TtyDriverHooks::driver_write` ultimately
    /// targets.
    /// # C: O(N) bytes
    fn write(&mut self, bytes: &[u8]);

    /// Raise `sig` on the tty's foreground process group (ISIG ^C/^\/^Z).
    /// Maps onto `Signum` + `tasks_in_pgrp` in the kernel; records in
    /// tests.
    /// # C: O(P) fg-pgrp tasks
    fn signal_fg_pgrp(&mut self, sig: Sig);

    /// Driver-specific ioctl hook. Return `Some(ret)` if handled (ret is
    /// the syscall return value), `None` to let the core's generic TIOC*
    /// handling run. Default: not handled.
    /// # C: driver-defined
    fn ioctl(&mut self, _cmd: u32, _arg: u64) -> Option<i64> {
        None
    }

    /// Termios changed (TCSETS*). Lets a UART driver reprogram baud, a VT
    /// driver note mode changes. Default: no-op.
    /// # C: O(1)
    fn set_termios(&mut self, _new: &[u8; TERMIOS_BYTES]) {}

    /// Device opened (first reference). Default: no-op.
    /// # C: O(1)
    fn open(&mut self) {}

    /// Device closed (last reference). Default: no-op.
    /// # C: O(1)
    fn close(&mut self) {}

    /// Carrier/hangup (controlling-tty hangup, SIGHUP). Default: no-op.
    /// # C: O(1)
    fn hangup(&mut self) {}

    /// A sink that reaches this device WITHOUT the port lock held.
    ///
    /// The port lock is irqsave (the RX ISR takes it), so anything done under
    /// it runs with interrupts masked. For a UART, `write` polls the
    /// transmitter holding register empty PER BYTE — ~87 us/byte at 115200 —
    /// so a large write masked interrupts for its whole transmission, starving
    /// the timer tick (`skizm.md` Step 4e). That is the same disease this
    /// campaign exists to cure, arriving via the fix for 3.1 #6/#7.
    ///
    /// Returning `Some` lets the core buffer the ldisc's output under the lock
    /// and push it here AFTER releasing it, with interrupts restored. Only a
    /// driver whose device is reachable without `&mut self` — a global UART —
    /// can offer one; `None` (the default) keeps the previous inline
    /// behaviour, which is what VT and test drivers want.
    /// # C: O(1)
    fn detached_sink() -> Option<fn(&[u8])> { None }
}

/// `TtyDriverHooks` (the ldisc's view of the device) for any `TtyDriver`.
/// The ldisc only needs `driver_write` + `signal_fg_pgrp`, which map 1:1.
impl<D: TtyDriver> TtyDriverHooks for D {
    fn driver_write(&mut self, bytes: &[u8]) {
        TtyDriver::write(self, bytes)
    }
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        TtyDriver::signal_fg_pgrp(self, sig)
    }
}
