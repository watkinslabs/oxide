// Line discipline layer — Linux `drivers/tty/n_tty.c` + the
// `tty_ldisc_ops` interface, as host-testable pure logic.
//
// Position in the Linux stack (tty-rebuild-plan §0):
//
//   tty core (T4) ──▶ LdiscOps ──▶ TtyDriverHooks ──▶ driver
//        ▲   reads/poll       │  echo + cooked output    (VT emulator
//        └───────────────────┘   go BACK through         / UART / test
//          read queue            driver_write             recorder)
//
// The ldisc owns NO locking and NO blocking. The tty core (T4) wraps
// `NTty` in a Spinlock and parks/wakes around `read`/`has_input`.
// `receive_buf` is the driver→ldisc input path (UART RX / kbd); echo
// re-enters the *driver* write path (`drv.driver_write`) exactly as
// Linux echoes by writing back out the tty, so the emulator/UART
// renders it — never a side channel.
//
// Generic over the driver (`impl TtyDriverHooks`) — no `dyn`, mirrors
// the HAL-trait monomorphization rule (07§5).
//
// Termios bit definitions are REUSED from `crate::pty` (oflag/iflag/
// lflag/cc indices, TERMIOS_BYTES, default_termios) — not duplicated.

pub mod n_tty;
pub use n_tty::{vmin_vtime_decision, NTty, VmtDecision};

/// Poll-mask bits the ldisc reports (Linux uapi `POLLIN`/`POLLOUT`).
/// Typed so callers (the tty core's `poll`) never open-code `1`/`4`.
pub mod pollmask {
    /// Input available (a complete line in canonical mode, any byte in
    /// raw mode, or pending EOF).
    pub const POLLIN: u32 = 0x0001;
    /// Output writable — the ldisc never blocks output, so always set.
    pub const POLLOUT: u32 = 0x0004;
}

/// The three signals N_TTY raises from c_cc control characters under
/// ISIG. Typed alternative to bare signo literals (07§5); the kernel
/// side maps these onto `sched::live::sigpend::Signum` (same numeric
/// values, Linux uapi). Kept local so the ldisc stays host-testable
/// without pulling the kernel-only `sched::live` module.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Sig {
    /// VINTR (^C) → SIGINT.
    Int = 2,
    /// VQUIT (^\) → SIGQUIT.
    Quit = 3,
    /// VSUSP (^Z) → SIGTSTP.
    Tstp = 20,
}

impl Sig {
    /// Linux signo (1-based).
    /// # C: O(1)
    pub const fn signo(self) -> u8 {
        self as u8
    }
}

/// What N_TTY needs from whatever driver it sits on. Implemented by the
/// VT console driver (write → emulator → consw), the serial driver
/// (write → UART TX), and — in tests — a recording buffer.
///
/// Echo and cooked output BOTH flow through `driver_write`; there is no
/// separate echo path (Linux n_tty echoes by re-entering the driver).
pub trait TtyDriverHooks {
    /// Underlying output sink. The ldisc has already run OPOST (output)
    /// or built the echo bytes; the driver renders them verbatim.
    /// # C: O(N) bytes
    fn driver_write(&mut self, bytes: &[u8]);

    /// Raise `sig` on the tty's foreground process group (ISIG). In the
    /// kernel this maps onto `Signum` + `tasks_in_pgrp`; in tests it
    /// records the signal.
    /// # C: O(P) tasks in the fg pgrp
    fn signal_fg_pgrp(&mut self, sig: Sig);
}

/// The `tty_ldisc_ops` surface. The tty core (T4) calls these; blocking
/// + locking are the core's job. Generic over the driver to monomorphize
/// (no `dyn`).
pub trait LdiscOps {
    /// Driver→ldisc input (UART RX / kbd bytes). Runs the full N_TTY
    /// input pipeline: c_iflag mapping (IGNCR/ICRNL/INLCR), ISIG signal
    /// raising, canonical line editing (ERASE/KILL/WERASE/EOF/EOL) with
    /// ECHO, or raw passthrough to the read queue. Echo bytes go through
    /// `drv.driver_write`. On line completion the cooked line moves to
    /// the read queue.
    /// # C: O(N) input bytes
    fn receive_buf<D: TtyDriverHooks>(&mut self, drv: &mut D, input: &[u8]);

    /// Userspace read. Canonical: returns whole terminated lines (never a
    /// partial line) up to `buf.len()`. Raw: up to min(available,
    /// buf.len()) honouring VMIN. Returns 0 on EOF (^D at line start) and
    /// 0 when nothing is ready — does NOT block. The tty core closes the
    /// lost-wakeup window by: check `has_input()`, then park-then-recheck
    /// under the same lock that `receive_buf` takes, waking on input.
    /// # C: O(N) bytes copied
    fn read(&mut self, buf: &mut [u8]) -> usize;

    /// Userspace write — N_TTY output processing (`process_output`).
    /// OPOST: ONLCR (\n→\r\n), OCRNL, ONLRET, tab expansion with column
    /// tracking, then `drv.driver_write`. OPOST clear: passthrough.
    /// Returns bytes consumed from `buf`.
    /// # C: O(N) bytes
    fn write<D: TtyDriverHooks>(&mut self, drv: &mut D, buf: &[u8]) -> usize;

    /// POLLIN when the read queue is non-empty (or EOF pending); POLLOUT
    /// always (output never blocks here).
    /// # C: O(1)
    fn poll(&self) -> u32;

    /// Snapshot the termios byte image (TCGETS).
    /// # C: O(1)
    fn termios(&self) -> [u8; crate::pty::TERMIOS_BYTES];

    /// Replace the termios image and recompute derived state (TCSETS).
    /// # C: O(1)
    fn set_termios(&mut self, new: &[u8; crate::pty::TERMIOS_BYTES]);
}

#[cfg(test)]
mod tests;
