// Numbered-VT tty stack (console-plan B4a). Each `/dev/ttyN` (N in
// 1..=63) gets a REAL `TtyStruct<VtConsoleDriver, KernelWait>` — the same
// N_TTY core the system console (`static_console`) uses — replacing the
// legacy `tty::live` per-VT ring + ad-hoc line discipline. Position in
// the stack (mirrors Linux VT `con_ops`):
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
use tty::core::DetachedSink;

use crate::static_console::KernelFgSignal;

/// Number of numbered-VT slots (`/dev/tty1`..`/dev/tty63`). Matches
/// `tty::live::N_VT` (the legacy ring this replaces).
pub const N_VT: usize = 63;

/// The VT console `tty_driver` (Linux `vt.c` con_ops). Owns the VT id it
/// renders to, a reference to the SAME stable process-group identity held by
/// the tty core (so ISIG can target it without a back-pointer), and the
/// fg-pgrp signal sink.
pub struct VtConsoleDriver {
    /// 1-based VT id this driver renders to (`fbcon::kernel::vt_write`).
    vt: u8,
    /// Shared reference to the tty core's canonical process-group identity.
    fg_pgrp: Option<Arc<sched::pid::PidIdentity>>,
    /// ISIG sink: raises a real signal on the fg pgrp via the scheduler
    /// registry (reused from `static_console`, not duplicated).
    sig: KernelFgSignal,
}

impl VtConsoleDriver {
    /// Build a VT console driver rendering to VT `vt` (1-based).
    /// # C: O(1)
    pub fn new(vt: u8) -> Self {
        Self { vt, fg_pgrp: None, sig: KernelFgSignal }
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
        self.sig.raise(self.fg_pgrp.as_deref(), sig);
    }

    fn set_foreground_pgrp(&mut self, pgrp: Option<Arc<sched::pid::PidIdentity>>) {
        self.fg_pgrp = pgrp;
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
    let sink = DetachedSink::new(vt, |vt, bytes| fbcon::kernel::vt_write(vt, bytes));
    let tty: Arc<VtTty> = Arc::new(TtyStruct::with_termios_and_sink(
        VtConsoleDriver::new(vt),
        KernelWait::new(),
        default_termios(),
        Some(sink),
    ));
    // A VT created after fbcon comes up must inherit the same native geometry
    // that an existing VT receives through `sync_framebuffer_winsizes`.
    if let Some((rows, cols, ypixel)) = fbcon::kernel::console_geometry() {
        tty.set_winsize(crate::framebuffer::winsize(rows, cols, ypixel));
    }
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

/// Apply a committed framebuffer geometry to every already-open numbered VT.
///
/// TIOCGWINSZ must follow the text grid after firmware hands the display to a
/// native scanout. A changed foreground pgrp receives SIGWINCH after its tty
/// state is committed, so full-screen programs redraw with the new dimensions.
/// # C: O(N_VT + P) foreground-pgrp tasks
pub fn sync_framebuffer_winsizes(rows: u16, cols: u16, ypixel: u16) {
    let winsize = crate::framebuffer::winsize(rows, cols, ypixel);
    for raw in &VT_TTYS {
        let raw = raw.load(Ordering::Acquire);
        if raw == 0 { continue; }
        // SAFETY: each nonzero slot was published by vt_tty after build leaked
        // its owning Arc for the kernel lifetime; this shared reference stays
        // valid while set_winsize and fg_pgrp operate through interior locks.
        let tty = unsafe { &*(raw as *const VtTty) };
        let changed = tty.set_winsize(winsize);
        let pgrp = tty.fg_pgrp();
        if changed && pgrp != 0 {
            for task in sched::live::registry::tasks_in_pgrp(pgrp) {
                sched::live::send_sig_priv_group(&task, sched::Signum::Sigwinch as u32);
            }
        }
    }
}

/// Publish the same foreground-group identity through the tty core and driver
/// — the VT counterpart of `serialtty::set_fg_pgrp`.
/// # C: O(1)
pub fn set_fg_pgrp(vt: u8, pgrp: Arc<sched::pid::PidIdentity>) {
    let tty = vt_tty(vt);
    tty.set_foreground_pgrp(Some(pgrp));
}

/// Claim VT `vt` as the controlling tty of session `sid` and seed the fg
/// pgrp with `pgid` (POSIX: a session leader acquiring a ctty sets the fg
/// pgrp to its own pgrp). The VT counterpart of
/// `static_console::set_session_and_fg`.
/// # C: O(1)
pub fn set_session_and_fg(
    vt: u8,
    session: Arc<sched::pid::PidIdentity>,
    pgrp: Arc<sched::pid::PidIdentity>,
) {
    let tty = vt_tty(vt);
    tty.set_session(Some(session));
    tty.set_foreground_pgrp(Some(pgrp));
}

/// Linux `__tty_hangup` on VT `vt`. The VT counterpart of
/// `static_console::hangup`; the session walk lives in `tty::hangup`.
/// # C: O(W) waiters
pub fn hangup(vt: u8, kind: tty::HangupKind) {
    let tty = vt_tty(vt);
    tty.hangup(kind);
}

/// Release the controlling tty for VT `vt` (clear sid and every reference to
/// its foreground-group identity). The VT counterpart of
/// `static_console::notty`.
/// # C: O(1)
pub fn notty(vt: u8) {
    let tty = vt_tty(vt);
    tty.notty();
}
