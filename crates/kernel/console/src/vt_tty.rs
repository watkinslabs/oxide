// Numbered-VT tty stack (console-plan B4a). Each `/dev/ttyN` (N in
// 1..=63) gets a REAL `TtyStruct<VtConsoleDriver, KernelWait>` — the same
// N_TTY core the system console (`static_console`) uses — replacing the
// legacy `tty::live` per-VT ring + ad-hoc line discipline. Position in
// the stack (mirrors Linux `drivers/tty/vt/vt.c` con_ops):
//
//   /dev/ttyN inode ─▶ TtyStruct ─▶ N_TTY ─▶ VtConsoleDriver ─▶ fbcon
//                          │ block/wake (KernelWait, lost-wakeup-free)
//                          └ fg_pgrp / sid / termios = SOURCE OF TRUTH
//
// The driver's `write` feeds POST-OPOST bytes (the N_TTY already ran
// ONLCR) straight to `fbcon::kernel::vt_write(vt, …)` — emulator → vc_data
// → consw. `signal_fg_pgrp` raises ISIG (^C/^\/^Z) on the VT's fg pgrp via
// the scheduler registry (reusing `static_console::KernelFgSignal`). RX
// (keyboard / DSR answerback) enters via `TtyStruct::receive_from_driver`.
//
// Per-VT registry: a lazily-built array of leaked `&'static TtyStruct`,
// one per VT slot — same leak-an-Arc-for-the-kernel-lifetime pattern as
// `static_console::install` (the consoles never close).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use tty::ldisc::Sig;
use tty::pty::{default_termios, TERMIOS_BYTES};
use tty::wait::kernel::KernelWait;
use tty::{TtyDriver, TtyStruct};

use crate::static_console::KernelFgSignal;

/// Number of numbered-VT slots (`/dev/tty1`..`/dev/tty63`). Matches
/// `tty::live::N_VT` (the legacy ring this replaces).
pub const N_VT: usize = 63;

/// The VT console `tty_driver` (Linux `vt.c` con_ops). Owns the VT id it
/// renders to, a shadow of the fg pgrp the core last published (so ISIG
/// can target it without a back-pointer — same pattern as
/// `SerialTtyDriver`), and the fg-pgrp signal sink.
pub struct VtConsoleDriver {
    /// 1-based VT id this driver renders to (`fbcon::kernel::vt_write`).
    vt: u8,
    /// Shadow of the fg pgrp (TIOCSPGRP) so `signal_fg_pgrp` targets it.
    fg_pgrp: u32,
    /// ISIG sink: raises a real signal on the fg pgrp via the scheduler
    /// registry (reused from `static_console`, not duplicated).
    sig: KernelFgSignal,
}

impl VtConsoleDriver {
    /// Build a VT console driver rendering to VT `vt` (1-based).
    /// # C: O(1)
    pub fn new(vt: u8) -> Self {
        Self { vt, fg_pgrp: 0, sig: KernelFgSignal }
    }

    /// Publish the fg pgrp into the driver shadow so `signal_fg_pgrp`
    /// targets it (kept in sync with the core by `set_fg_pgrp`).
    /// # C: O(1)
    pub fn set_fg_pgrp(&mut self, pgrp: u32) {
        self.fg_pgrp = pgrp;
    }
}

impl TtyDriver for VtConsoleDriver {
    /// Cooked/echo output sink: the N_TTY already ran OPOST/ONLCR, so feed
    /// the bytes verbatim to the fbcon VT emulator (→ vc_data → consw
    /// cell-blit). `vt_write` no-ops before fbcon init.
    /// # C: O(N) bytes + dirty-cell blit on the fg VT
    fn write(&mut self, bytes: &[u8]) {
        fbcon::kernel::vt_write(self.vt, bytes);
    }

    /// ISIG: deliver `sig` to the recorded fg pgrp (Linux `isig` →
    /// `kill_pgrp` on the VT's fg pgrp). Uses the shared `KernelFgSignal`.
    /// # C: O(P) fg-pgrp tasks
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        use serialtty::FgSignal;
        let pgrp = self.fg_pgrp;
        self.sig.raise(pgrp, sig);
    }

    /// Termios change (TCSETS*): the VT emulator has no baud to reprogram.
    /// # C: O(1)
    fn set_termios(&mut self, _new: &[u8; TERMIOS_BYTES]) {}
}

/// The concrete kernel numbered-VT tty type: VT console driver over fbcon
/// with a real fg-pgrp signal sink, parked on `KernelWait`.
pub type VtTty = TtyStruct<VtConsoleDriver, KernelWait>;

/// Per-VT registry of leaked `&'static VtTty` pointers, indexed by VT-1
/// (slot 0 == VT 1). 0 = not yet built. Each entry is built once on first
/// touch (`vt_tty`) and lives for the kernel lifetime — the numbered VTs
/// never close, so the leak is intentional (matches `static_console`).
static VT_TTYS: [AtomicU64; N_VT] = [const { AtomicU64::new(0) }; N_VT];

/// Build a fresh numbered-VT tty for `vt` (1-based), leak it, and return
/// the `&'static`. Default termios = cooked sane (ICANON|ECHO|ISIG,
/// OPOST|ONLCR) — same as the system console default.
/// # C: O(1)
fn build(vt: u8) -> &'static VtTty {
    let tty: Arc<VtTty> = Arc::new(TtyStruct::with_termios(
        VtConsoleDriver::new(vt),
        KernelWait::new(),
        default_termios(),
    ));
    let raw = Arc::into_raw(tty);
    // build() leaks the Arc for the kernel lifetime (numbered VTs never
    // close); the ref is published into VT_TTYS so callers share one tty.
    // SAFETY: raw came from Arc::into_raw over a freshly allocated Arc<VtTty> deliberately leaked for the kernel lifetime; &* yields a shared ref valid forever, every TtyStruct method takes &self (aliasing-safe).
    unsafe { &*raw }
}

/// Borrow the `&'static VtTty` for `vt` (1-based, 1..=N_VT), lazily
/// building + leaking it on first touch. Out-of-range `vt` clamps to slot
/// 1 (devfs paths are validated at registration, but inode reuse makes a
/// defensive clamp cheap). Callable from process / softirq context (the
/// answerback tick drain): the publish is a plain CAS, no sleeping.
/// # C: O(1)
pub fn vt_tty(vt: u8) -> &'static VtTty {
    let idx = (vt.max(1) as usize).min(N_VT) - 1;
    let cur = VT_TTYS[idx].load(Ordering::Acquire);
    if cur != 0 {
        // SAFETY: cur is a pointer published by a prior build()→CAS over a
        // leaked Arc<VtTty> that is never freed; &* yields a shared ref
        // valid for the kernel lifetime, TtyStruct methods take &self.
        return unsafe { &*(cur as *const VtTty) };
    }
    let fresh = build((idx + 1) as u8);
    let fresh_raw = fresh as *const VtTty as u64;
    match VT_TTYS[idx].compare_exchange(0, fresh_raw, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        // Lost the race: another caller published first. Our `fresh` leaks
        // (kernel-lifetime object, no destructor to run) — return the
        // winner so every caller shares ONE tty per VT.
        Err(won) => {
            // SAFETY: won is the winning pointer published by the racing
            // build()→CAS over a leaked Arc<VtTty>; &* is valid for the
            // kernel lifetime, methods take &self.
            unsafe { &*(won as *const VtTty) }
        }
    }
}

/// Set the fg pgrp on BOTH the core and the driver shadow (keeps ISIG
/// targeting in sync) — the VT counterpart of `serialtty::set_fg_pgrp`.
/// # C: O(1)
pub fn set_fg_pgrp(vt: u8, pgrp: u32) {
    let tty = vt_tty(vt);
    tty.set_fg_pgrp(pgrp);
    tty.with_driver(|d| d.set_fg_pgrp(pgrp));
}

/// Claim VT `vt` as the controlling tty of session `sid` and seed the fg
/// pgrp with `pgid` (POSIX: a session leader acquiring a ctty sets the fg
/// pgrp to its own pgrp). The VT counterpart of
/// `static_console::set_session_and_fg`.
/// # C: O(1)
pub fn set_session_and_fg(vt: u8, sid: u32, pgid: u32) {
    let tty = vt_tty(vt);
    tty.set_ctty(sid);
    tty.set_fg_pgrp(pgid);
    tty.with_driver(|d| d.set_fg_pgrp(pgid));
}

/// Release the controlling tty for VT `vt` (clear sid + fg pgrp + driver
/// shadow). The VT counterpart of `static_console::notty`.
/// # C: O(1)
pub fn notty(vt: u8) {
    let tty = vt_tty(vt);
    tty.notty();
    tty.with_driver(|d| d.set_fg_pgrp(0));
}
