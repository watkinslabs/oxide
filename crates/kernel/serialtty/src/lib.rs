// Serial tty driver (T6 of tty-rebuild-plan §3-T6). The Linux
// `drivers/tty/serial/serial_core.c` `ttyS0` `tty_driver`: a `TtyDriver`
// whose output goes to the UART and whose RX bytes flow
//
//   UART RX ─▶ rx_byte() ─▶ TtyStruct::receive_from_driver ─▶ N_TTY ─▶ read
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
    fn detached_sink() -> Option<fn(&[u8])> { None }
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
    fn detached_sink() -> Option<fn(&[u8])> { Some(|bytes| drv_serial::emit(bytes)) }

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
    /// Deliver `sig` to process group `pgrp` (0 = unset → no-op in the
    /// kernel; recorded in tests).
    /// # C: O(P) tasks in the fg pgrp
    fn raise(&mut self, pgrp: u32, sig: Sig);
}

/// `FgSignal` that drops every signal (no fg pgrp signal channel wired).
/// Default for a serial line with no controlling shell yet — the real
/// kernel signal raise is wired by the boot integration (additive, T7+).
#[derive(Default)]
pub struct NoSignal;

impl FgSignal for NoSignal {
    fn raise(&mut self, _pgrp: u32, _sig: Sig) {}
}

/// The serial tty driver (Linux serial `tty_driver` / `uart_ops`). Owns
/// the UART sink `U`, the fg-pgrp signal sink `S`, and a shadow of the fg
/// pgrp the core last published (so ISIG ^C/^\/^Z can target it — same
/// pattern as the VT driver).
///
/// Generic over the UART sink (`U: SerialOut`) and the signal sink
/// (`S: FgSignal`) — monomorphized, never `dyn`.
pub struct SerialTtyDriver<U: SerialOut, S: FgSignal = NoSignal> {
    /// The UART transmitter sink (kernel: `drv_serial::emit`; tests: a
    /// recorder).
    out: U,
    /// Signal sink for ISIG (^C/^\/^Z) on the fg pgrp.
    sig: S,
    /// Shadow of the fg pgrp last set by the core (TIOCSPGRP). ISIG
    /// targets it. The kernel core also tracks this on `TtyStruct`; the
    /// driver keeps a copy so `signal_fg_pgrp` needs no back-pointer.
    fg_pgrp: u32,
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
        Self { out, sig, fg_pgrp: 0 }
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

    /// Publish the fg pgrp into the driver shadow so `signal_fg_pgrp`
    /// targets it. The assembly factory keeps this in sync with the
    /// core's `set_fg_pgrp`.
    /// # C: O(1)
    pub fn set_fg_pgrp(&mut self, pgrp: u32) {
        self.fg_pgrp = pgrp;
    }
}

impl<U: SerialOut, S: FgSignal> TtyDriver for SerialTtyDriver<U, S> {
    /// Forward the UART's detached sink so the tty core can transmit outside
    /// the port lock (`skizm.md` Step 4e).
    /// # C: O(1)
    fn detached_sink() -> Option<fn(&[u8])> { U::detached_sink() }

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
        let pgrp = self.fg_pgrp;
        self.sig.raise(pgrp, sig);
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

/// Set the fg pgrp on BOTH the core and the driver shadow (keeps ISIG
/// targeting in sync). Use instead of `TtyStruct::set_fg_pgrp` alone when
/// the driver must raise signals on that pgrp.
/// # C: O(1)
pub fn set_fg_pgrp<U: SerialOut, S: FgSignal, W: TtyWait>(
    tty: &TtyStruct<SerialTtyDriver<U, S>, W>,
    pgrp: u32,
) {
    tty.set_fg_pgrp(pgrp);
    tty.with_driver(|d| d.set_fg_pgrp(pgrp));
}

// ----------------------------------------------------------------- kernel
//
// RX-sink registration. `drv_serial::set_rx_sink` takes a plain
// `fn(u8)` (not a closure), so the UART RX byte must reach THIS ttyS0's
// `TtyStruct::receive_from_driver` through a `static` holder + a free
// `fn rx_byte(u8)`. Gated to the kernel target; host tests call
// `receive_from_driver` directly (no static needed).
#[cfg(target_os = "oxide-kernel")]
pub mod kernelrx {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use tty::wait::kernel::KernelWait;

    /// The concrete kernel ttyS0 type the RX sink forwards into. Uses
    /// `NoSignal` for T6 (additive): the real fg-pgrp signal raise is
    /// wired at the boot cutover (T7+), exactly as the VT console driver.
    pub type KernelSerialTty = TtyStruct<SerialTtyDriver<KernelUart, NoSignal>, KernelWait>;

    /// Pointer to the boot-installed `Arc<KernelSerialTty>`, stored as a
    /// raw `Arc::into_raw` pointer (kept alive for the kernel's lifetime
    /// — the serial line never goes away). 0 = not yet installed.
    static TTYS0_PTR: AtomicU64 = AtomicU64::new(0);

    /// Install the boot-assembled ttyS0 as the RX target and wire the
    /// UART RX sink to `rx_byte`. Call once at boot, before RX starts.
    /// Leaks the `Arc` intentionally: the serial line lives for the whole
    /// kernel lifetime, so the RX sink may dereference it freely.
    /// # C: O(1)
    pub fn install(tty: Arc<KernelSerialTty>) {
        let raw = Arc::into_raw(tty) as u64;
        TTYS0_PTR.store(raw, Ordering::Release);
        drv_serial::set_rx_sink(rx_byte);
    }

    /// UART RX byte sink (`fn(u8)` for `drv_serial::set_rx_sink`). Pushes
    /// the byte into ttyS0's flip path → N_TTY → wakes readers. Mirrors
    /// Linux `uart_insert_char` → `tty_flip_buffer_push`.
    /// # C: O(1) + O(waiters) wake
    pub fn rx_byte(b: u8) {
        let p = TTYS0_PTR.load(Ordering::Acquire);
        if p == 0 {
            return;
        }
        // SAFETY: p was produced by Arc::into_raw in install() from a
        // valid Arc<KernelSerialTty> that is never freed (deliberately
        // leaked for the kernel lifetime); &* yields a shared ref valid
        // for this call, and receive_from_driver takes &self.
        let tty: &KernelSerialTty = unsafe { &*(p as *const KernelSerialTty) };
        tty.receive_from_driver(&[b]);
    }
}

#[cfg(test)]
mod tests;
