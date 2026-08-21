// Serial tty driver (T6 of tty-rebuild-plan §3-T6). Linux's `ttyS0`
// `tty_driver` shape (serial_core layer): a `TtyDriver`
// whose output goes to the UART and whose RX bytes flow
//
//   UART RX ─▶ console-owned flip worker ─▶ N_TTY ─▶ read
//                                                              │ echo
//   TtyStruct::write ─▶ N_TTY (OPOST/ONLCR) ─▶ SerialTtyDriver ┘─▶ UART TX
//
// This is the serial *tty* (`/dev/ttyS0`, the login line), DISTINCT from
// the serial *console* (the printk consumer — T7). Mirrors the T5 VT
// console driver structure: a `TtyDriver` + an `assemble` factory + a
// (major,minor) registry entry.
//
// ADDITIVE (tty-rebuild-plan §3-T6): does NOT touch klog / ConsoleInode.
// UART RX reaches this tty through the owning UART driver's IRQ handler.
//
// Generic over the UART sink (`U: SerialOut`) — monomorphized, never
// `dyn` (07§5), mirroring the HAL-trait rule. The kernel impl
// (`KernelUart`) calls `drv_serial::emit`; host tests inject a
// `RecordingOut` to capture TX without a real UART. The actual UART emit
// + RX-sink registration are `#[cfg(target_os = "oxide-kernel")]` gated
// so the crate is host-testable end-to-end.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

use tty::ldisc::Sig;
use tty::pty::TERMIOS_BYTES;
use tty::registry::{major, DevId};
use tty::wait::TtyWait;
use tty::{TtyDriver, TtyStruct};

/// `/dev/ttyS0` device id (Linux uapi `Documentation/admin-guide/
/// devices.txt`: serial ttys are major 4, ttyS0 = minor 64). Typed so
/// the device-node / registry layer never hard-codes the bare number.
pub const TTYS0_MINOR: u32 = 64;
/// `(major, minor)` for `/dev/ttyS0`.
pub const TTYS0: DevId = DevId::new(major::SERIAL, TTYS0_MINOR);

/// The UART output sink the serial tty driver writes TX bytes to. The
/// ldisc has already run OPOST/ONLCR, so `write` is a raw byte push to
/// the device. Generic — monomorphized, never `dyn` (07§5).
///
/// Kernel: `KernelUart` → `drv_serial::emit`. Tests: `RecordingOut`
/// captures the bytes so TX is asserted without a real UART.
pub trait SerialOut {
    /// Push already-cooked output bytes to the UART transmitter.
    /// # C: O(N) bytes
    fn emit(&mut self, bytes: &[u8]);

    /// Reprogram the UART baud rate (from TCSETS `c_ospeed`). Default no-op
    /// (test sinks have no real UART). # C: O(1)
    fn set_baud(&mut self, _baud: u32) {}

    /// A sink reaching the same device WITHOUT `&mut self`, so the tty core can
    /// transmit after releasing the (irqsave) port lock rather than with
    /// interrupts masked — see `TtyDriver::detached_sink` and `skizm.md` Step
    /// 4e. Only a globally-addressable device can offer one; `None` (default)
    /// keeps the inline path, which is what the recording test sinks need.
    /// # C: O(1)
    fn detached_sink() -> Option<tty::core::DetachedSink> { None }
}

/// `SerialOut` that drives the real UART via `drv_serial::emit`. The
/// only kernel sink; zero-sized.
#[cfg(target_os = "oxide-kernel")]
#[derive(Default)]
pub struct KernelUart;

#[cfg(target_os = "oxide-kernel")]
impl SerialOut for KernelUart {
    /// The console UART is a global singleton reached through `drv_serial`, so
    /// it can be driven without the port lock held.
    /// # C: O(1)
    fn detached_sink() -> Option<tty::core::DetachedSink> {
        Some(tty::core::DetachedSink::new(0, |_, bytes| drv_serial::emit(bytes)))
    }

    /// # C: O(N) bytes + fg-VT cell render
    fn emit(&mut self, bytes: &[u8]) {
        // SERIAL-ONLY. The serial line (`/dev/ttyS0`) is a SEPARATE device
        // from the video console — it does NOT mirror to the framebuffer
        // (that double-rendered every /dev/console byte). The video VTs
        // render through their own `VtConsoleDriver`; kernel printk reaches
        // the framebuffer via klog's separate fbcon sink. Linux keeps serial
        // and VT consoles independent.
        drv_serial::emit(bytes);
    }
    /// # C: O(1) UART divisor program
    fn set_baud(&mut self, baud: u32) { drv_serial::set_baud(baud); }
}

/// Sink for ISIG signals raised on the fg pgrp (same pattern as the T5
/// VT driver's `FgSignal`). The kernel impl raises a real signal on the
/// fg pgrp; the test impl records `(pgrp, sig)` so the harness can assert
/// ^C → SIGINT. Generic — no `dyn` (07§5).
pub trait FgSignal {
    /// Deliver `sig` to the stable process-group identity (`None` = unset).
    /// # C: O(P) tasks in the fg pgrp
    fn raise(&mut self, pgrp: Option<&sched::pid::PidIdentity>, sig: Sig);
}

/// `FgSignal` that drops every signal (no fg pgrp signal channel wired).
/// Default for a serial line with no controlling shell yet — the real
/// kernel signal raise is wired by the boot integration (additive, T7+).
#[derive(Default)]
pub struct NoSignal;

impl FgSignal for NoSignal {
    fn raise(&mut self, _pgrp: Option<&sched::pid::PidIdentity>, _sig: Sig) {}
}

/// The serial tty driver (Linux serial `tty_driver` / `uart_ops`). Owns
/// the UART sink `U`, the fg-pgrp signal sink `S`, and a reference to the
/// SAME stable process-group identity held by the tty core (so ISIG
/// ^C/^\/^Z can target it without a back-pointer).
///
/// Generic over the UART sink (`U: SerialOut`) and the signal sink
/// (`S: FgSignal`) — monomorphized, never `dyn`.
pub struct SerialTtyDriver<U: SerialOut, S: FgSignal = NoSignal> {
    /// The UART transmitter sink (kernel: `drv_serial::emit`; tests: a
    /// recorder).
    out: U,
    /// Signal sink for ISIG (^C/^\/^Z) on the fg pgrp.
    sig: S,
    /// Shared reference to the tty core's canonical process-group identity.
    /// `TtyStruct::set_foreground_pgrp` is the only mutation path and gives
    /// both layers an `Arc` to the same object; no numeric owner is copied.
    fg_pgrp: Option<alloc::sync::Arc<sched::pid::PidIdentity>>,
}

impl<U: SerialOut> SerialTtyDriver<U, NoSignal> {
    /// Build a serial tty driver over the UART sink `out` with no signal
    /// sink.
    /// # C: O(1)
    pub fn new(out: U) -> Self {
        Self::with_signal(out, NoSignal)
    }
}

impl<U: SerialOut, S: FgSignal> SerialTtyDriver<U, S> {
    /// Build with an explicit fg-pgrp signal sink.
    /// # C: O(1)
    pub fn with_signal(out: U, sig: S) -> Self {
        Self { out, sig, fg_pgrp: None }
    }

    /// The UART sink (test introspection / TX readback).
    /// # C: O(1)
    pub fn out(&self) -> &U {
        &self.out
    }

    /// The fg-pgrp signal sink (test introspection).
    /// # C: O(1)
    pub fn signal_sink(&self) -> &S {
        &self.sig
    }

}

impl<U: SerialOut, S: FgSignal> TtyDriver for SerialTtyDriver<U, S> {
    /// Forward the UART's detached sink so the tty core can transmit outside
    /// the port lock (`skizm.md` Step 4e).
    /// # C: O(1)
    fn detached_sink() -> Option<tty::core::DetachedSink> { U::detached_sink() }

    /// Cooked/echo output sink: the ldisc already ran OPOST/ONLCR, so
    /// push the bytes verbatim to the UART transmitter.
    /// # C: O(N) bytes
    fn write(&mut self, bytes: &[u8]) {
        self.out.emit(bytes);
    }

    /// ISIG: deliver `sig` to the recorded fg pgrp via the signal sink
    /// (Linux `isig` → `kill_pgrp` on the serial line's fg pgrp).
    /// # C: O(P) fg-pgrp tasks
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        self.sig.raise(self.fg_pgrp.as_deref(), sig);
    }

    fn set_foreground_pgrp(
        &mut self,
        pgrp: Option<alloc::sync::Arc<sched::pid::PidIdentity>>,
    ) {
        self.fg_pgrp = pgrp;
    }

    /// Termios change (TCSETS*): reprogram the UART baud from `c_ospeed`
    /// (Linux `uart_set_termios` → `->set_termios`). `c_ospeed` is the explicit
    /// output speed at offset 40 of `struct termios` (termios2/BOTHER style, as
    /// glibc cfsetospeed writes). A zero speed (B0 / unset) leaves the current
    /// rate. # C: O(1) + one divisor program
    fn set_termios(&mut self, new: &[u8; TERMIOS_BYTES]) {
        let ospeed = u32::from_le_bytes([
            new[tty::pty::TERMIOS_OFF_OSPEED],
            new[tty::pty::TERMIOS_OFF_OSPEED + 1],
            new[tty::pty::TERMIOS_OFF_OSPEED + 2],
            new[tty::pty::TERMIOS_OFF_OSPEED + 3],
        ]);
        if ospeed != 0 { self.out.set_baud(ospeed); }
    }
}

/// Assemble a `TtyStruct` around a `SerialTtyDriver`. The T6 deliverable:
/// the serial line wired as one tty.
///
/// Kernel use: `U = KernelUart` (→ `drv_serial::emit`), a real-signal
/// sink, `W = tty::wait::kernel::KernelWait`.
/// Host tests: `U = RecordingOut`, `S = RecordingSignal`,
/// `W = tty::wait::host::HostWait`.
///
/// # C: O(1)
pub fn assemble<U: SerialOut, S: FgSignal, W: TtyWait>(
    out: U,
    sig: S,
    wait: W,
) -> TtyStruct<SerialTtyDriver<U, S>, W> {
    TtyStruct::new(SerialTtyDriver::with_signal(out, sig), wait)
}

/// Resolve and publish the foreground group through the tty core's single
/// mutation path. The driver receives the same stable identity reference.
/// # C: O(1)
pub fn set_fg_pgrp<U: SerialOut, S: FgSignal, W: TtyWait>(
    tty: &TtyStruct<SerialTtyDriver<U, S>, W>,
    pgrp: alloc::sync::Arc<sched::pid::PidIdentity>,
) {
    tty.set_foreground_pgrp(Some(pgrp));
}

#[cfg(test)]
mod tests;
