// VT console tty driver (T5 of tty-rebuild-plan §3-T5). The Linux
// `drivers/tty/vt/vt.c` console `tty_driver`: a `TtyDriver` whose output
// path runs the ECMA-48 emulator over a per-VT `Vc`, then renders the
// dirtied cells through a `Consw` (fbcon). Assembles the whole VT stack:
//
//   /dev node ─▶ TtyStruct ─▶ N_TTY (ldisc) ─▶ VtConsoleDriver ─▶
//                                              Emulator ─▶ Vc ─▶ Consw
//
// Both program writes (`tty.write`) and ECHO bytes (the ldisc re-enters
// the driver's `write` to echo) flow through `VtConsoleDriver::write`,
// so typed input renders on the screen exactly as Linux echoes by
// writing back out the tty. The RX path (`tty.receive_from_driver`) is
// the tty core's, unchanged.
//
// SEPARATE crate (not folded into `tty`): the driver needs `vtdata`
// (emulator + Vc) and `fbcon` (the renderer) — the tty core must stay
// class-agnostic (Linux layering). `tty` depends on neither; this crate
// depends on all three, so there is no dependency cycle.
//
// Generic over the renderer (`R: Consw`) — monomorphized, never `dyn`
// (07§5), mirroring the HAL-trait rule.
//
// Multi-VT: `vc_cons[N_VT]` + an `fg` index mirror Linux `fg_console`,
// but one active VT is the load-bearing deliverable (T5); the other VTs
// are inert screen buffers until kbd VT-switch lands (a later task).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[cfg(any(test, feature = "hosted"))]
extern crate std;

use vtdata::{Consw, Emulator, Vc, N_VT};

use tty::ldisc::Sig;
use tty::{TtyDriver, TtyStruct};
use tty::pty::TERMIOS_BYTES;
use tty::wait::TtyWait;

/// Default VT geometry (Linux text-mode 80x25). Used by the factory when
/// a renderer's native geometry is not yet known; callers may resize.
pub const DEFAULT_COLS: u16 = 80;
/// Default VT row count.
pub const DEFAULT_ROWS: u16 = 25;

/// Sink for ISIG signals raised on the fg pgrp. The kernel impl raises a
/// real signal on `tty.fg_pgrp()`; the test impl records the (pgrp, sig)
/// so the harness can assert ^C → SIGINT. Generic — no `dyn` (07§5).
///
/// `signal_fg_pgrp` receives the fg pgrp id resolved by the driver from
/// the owning `TtyStruct` (recorded at `write`/RX time via `set_fg_pgrp`).
pub trait FgSignal {
    /// Deliver `sig` to process group `pgrp` (0 = unset → no-op in the
    /// kernel; recorded in tests).
    /// # C: O(P) tasks in the fg pgrp
    fn raise(&mut self, pgrp: u32, sig: Sig);
}

/// `FgSignal` that drops every signal (no fg pgrp wired). Default for a
/// VT with no controlling shell yet.
#[derive(Default)]
pub struct NoSignal;

impl FgSignal for NoSignal {
    fn raise(&mut self, _pgrp: u32, _sig: Sig) {}
}

/// The VT console tty driver (Linux console `tty_driver` + `con_write`).
/// Owns the multi-VT screen buffers (`vc_cons[N_VT]`), the active VT
/// index (`fg`, Linux `fg_console`), one ECMA-48 emulator, the renderer
/// `R`, the fg-pgrp signal sink `S`, and a shadow of the fg pgrp the core
/// last set (so ISIG can target it).
///
/// Generic over the renderer (`R: Consw`) and the signal sink
/// (`S: FgSignal`) — monomorphized, never `dyn`.
pub struct VtConsoleDriver<R: Consw, S: FgSignal = NoSignal> {
    /// Per-VT screen buffers. `vc[fg]` is the visible one.
    vc: alloc::boxed::Box<[Vc]>,
    /// Active/foreground VT index (Linux `fg_console`). 0-based.
    fg: usize,
    /// ECMA-48 parser state (shared; re-pointed per active VT — one
    /// active VT in T5, so a single emulator suffices and matches Linux's
    /// per-vc state being driven one fg at a time).
    em: Emulator,
    /// The renderer (fbcon `VcRenderer` in the kernel; a recorder in
    /// tests).
    renderer: R,
    /// Signal sink for ISIG (^C/^\/^Z) on the fg pgrp.
    sig: S,
    /// Shadow of the fg pgrp last published by the core (TIOCSPGRP). The
    /// kernel core also tracks this on `TtyStruct`; the driver keeps a
    /// copy so `signal_fg_pgrp` knows the target without a back-pointer.
    fg_pgrp: u32,
}

impl<R: Consw> VtConsoleDriver<R, NoSignal> {
    /// Build a VT console driver over `renderer` with the default 80x25
    /// geometry and no signal sink. The renderer is `con_init`'d to the
    /// active VT geometry and the active VT painted once.
    /// # C: O(N_VT * cols * rows)
    pub fn new(renderer: R) -> Self {
        Self::with_geometry(renderer, NoSignal, DEFAULT_COLS, DEFAULT_ROWS)
    }
}

impl<R: Consw, S: FgSignal> VtConsoleDriver<R, S> {
    /// Build with an explicit signal sink and geometry. Allocates `N_VT`
    /// screen buffers, binds the renderer to the active VT, and paints
    /// the active VT once (full repaint).
    /// # C: O(N_VT * cols * rows)
    pub fn with_geometry(mut renderer: R, sig: S, cols: u16, rows: u16) -> Self {
        let mut v = alloc::vec::Vec::with_capacity(N_VT);
        for _ in 0..N_VT {
            v.push(Vc::new(cols, rows));
        }
        renderer.con_init(cols as u32, rows as u32);
        let mut vc = v.into_boxed_slice();
        vtdata::switch(&mut vc[0], &mut renderer);
        Self { vc, fg: 0, em: Emulator::new(), renderer, sig, fg_pgrp: 0 }
    }

    /// The active (foreground) VT screen buffer.
    /// # C: O(1)
    pub fn active(&self) -> &Vc {
        &self.vc[self.fg]
    }

    /// Mutable active VT (tests / VT-switch).
    /// # C: O(1)
    pub fn active_mut(&mut self) -> &mut Vc {
        &mut self.vc[self.fg]
    }

    /// The renderer (introspection / pixel readback by the kernel
    /// framebuffer-flush path or tests).
    /// # C: O(1)
    pub fn renderer(&self) -> &R {
        &self.renderer
    }

    /// The fg-pgrp signal sink (test introspection).
    /// # C: O(1)
    pub fn signal_sink(&self) -> &S {
        &self.sig
    }

    /// Active VT index (Linux `fg_console`).
    /// # C: O(1)
    pub fn fg(&self) -> usize {
        self.fg
    }

    /// Switch the foreground VT to `idx` (Linux VT switch): repaint the
    /// newly-active screen in full. Out-of-range is ignored.
    /// # C: O(cols*rows)
    pub fn switch_vt(&mut self, idx: usize) {
        if idx >= N_VT || idx == self.fg {
            return;
        }
        self.fg = idx;
        vtdata::switch(&mut self.vc[idx], &mut self.renderer);
    }

    /// Feed `bytes` through the emulator into the active VT, then render
    /// the dirtied rows + cursor through the renderer. Shared by program
    /// writes and ldisc echo (both arrive via `TtyDriver::write`).
    /// # C: O(N bytes + dirty_rows*cols)
    fn emit(&mut self, bytes: &[u8]) {
        let vc = &mut self.vc[self.fg];
        self.em.feed_bytes(vc, bytes);
        vtdata::render(vc, &mut self.renderer);
    }
}

impl<R: Consw, S: FgSignal> TtyDriver for VtConsoleDriver<R, S> {
    /// Cooked/echo output sink: emulator over the active `Vc` → consw.
    /// # C: O(N bytes + dirty_rows*cols)
    fn write(&mut self, bytes: &[u8]) {
        self.emit(bytes);
    }

    /// ISIG: deliver `sig` to the recorded fg pgrp via the signal sink.
    /// # C: O(P) fg-pgrp tasks
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        let pgrp = self.fg_pgrp;
        self.sig.raise(pgrp, sig);
    }

    /// Termios change: the VT console honours OPOST/ICANON via the ldisc;
    /// nothing device-specific to reprogram (no baud). No-op.
    /// # C: O(1)
    fn set_termios(&mut self, _new: &[u8; TERMIOS_BYTES]) {}
}

impl<R: Consw, S: FgSignal> VtConsoleDriver<R, S> {
    /// Publish the fg pgrp into the driver shadow so `signal_fg_pgrp`
    /// targets it. The assembly factory keeps this in sync with the
    /// core's `set_fg_pgrp`.
    /// # C: O(1)
    pub fn set_fg_pgrp(&mut self, pgrp: u32) {
        self.fg_pgrp = pgrp;
    }
}

/// Assemble a `TtyStruct` around a `VtConsoleDriver`. This is the T5
/// deliverable: the full VT stack wired as one tty.
///
/// Kernel use: `R = fbcon::VcRenderer`, `S` = a real-signal sink,
/// `W = tty::wait::kernel::KernelWait`.
/// Host tests: `R` = a recording consw, `S = RecordingSignal`,
/// `W = tty::wait::host::HostWait`.
///
/// # C: O(N_VT * cols * rows)
pub fn assemble<R: Consw, S: FgSignal, W: TtyWait>(
    renderer: R,
    sig: S,
    wait: W,
    cols: u16,
    rows: u16,
) -> TtyStruct<VtConsoleDriver<R, S>, W> {
    let drv = VtConsoleDriver::with_geometry(renderer, sig, cols, rows);
    TtyStruct::new(drv, wait)
}

/// Set the fg pgrp on BOTH the core and the driver shadow (keeps ISIG
/// targeting in sync). Use instead of `TtyStruct::set_fg_pgrp` alone when
/// the driver must raise signals on that pgrp.
/// # C: O(1)
pub fn set_fg_pgrp<R: Consw, S: FgSignal, W: TtyWait>(
    tty: &TtyStruct<VtConsoleDriver<R, S>, W>,
    pgrp: u32,
) {
    tty.set_fg_pgrp(pgrp);
    tty.with_driver(|d| d.set_fg_pgrp(pgrp));
}

#[cfg(test)]
mod tests;
