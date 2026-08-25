use ::core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use alloc::sync::Arc;

use sync::{Spinlock, Tty as TtyClass};

use super::api::{DetachedSink, ReadOutcome, TtyDriver, TtyFlow, TtyFlush};
use crate::hangup::HangupKind;
use crate::ldisc::{vmin_vtime_decision, LdiscOps, NTty, Sig, VmtDecision};
use crate::pty::{Winsize, TERMIOS_BYTES};
use crate::wait::TtyWait;

/// Buffers `driver_write` output instead of emitting it, so the caller can
/// transmit after dropping the port lock. Every other hook forwards to the
/// real driver unchanged — only the byte sink is diverted.
pub(super) struct TxCollector<'a, D: TtyDriver> {
    pub(super) drv: &'a mut D,
    pub(super) buf: alloc::vec::Vec<u8>,
}

impl<D: TtyDriver> crate::ldisc::TtyDriverHooks for TxCollector<'_, D> {
    fn driver_write(&mut self, bytes: &[u8]) { self.buf.extend_from_slice(bytes); }
    fn signal_fg_pgrp(&mut self, sig: Sig) { TtyDriver::signal_fg_pgrp(self.drv, sig); }
}


/// The mutable state the port lock protects: the line discipline (which
/// owns the cooked read queue + the half-built canonical line — Linux's
/// flip buffer is consumed straight into `n_tty_receive_buf`, so the
/// ldisc IS the post-flip input store here) and the driver state. Device I/O
/// for a detached sink occurs under the separate `tx` owner, outside this
/// irqsave lock.
pub(super) struct PortInner<D: TtyDriver> {
    pub(super) ldisc: NTty,
    pub(super) driver: D,
}

/// `tty_port` + `tty_struct` fused into one core object (oxide collapses
/// the two Linux structs — there is one port per tty for the device
/// classes we ship). Owns:
///   - the port lock (serializes read-enqueue vs RX-queue+wake — the
///     lost-wakeup-free invariant),
///   - the ldisc (`NTty`) + driver behind that lock,
///   - the wait queue (`W: TtyWait`),
///   - winsize, fg pgrp, session id, controlling-tty linkage atomics.
pub struct TtyStruct<D: TtyDriver, W: TtyWait> {
    pub(super) inner: Spinlock<PortInner<D>, TtyClass>,
    /// Serialises transmission for drivers with a detached sink. The emit now
    /// happens AFTER the port lock is released, so without this two writers
    /// could interleave their bytes on the wire. Plain, not irqsave: the RX ISR
    /// never takes it, and masking interrupts across the transmission is
    /// exactly what Step 4e removes.
    tx: Spinlock<(), sync::TtyTx>,
    sink: Option<DetachedSink>,
    wait: W,
    /// Linux `tty_port::buf` — bytes staged by a device INTERRUPT for the line
    /// discipline to cook later, in process context. Separate from `inner`
    /// because the whole point is that the producer never touches the ldisc:
    /// taking the port lock in an ISR is what made a keystroke run
    /// `n_tty_receive_buf`, the UART echo poll and `wake_all` on the per-CPU
    /// hardirq stack (see `core/flip.rs`).
    flip: Spinlock<super::flip::FlipRing, TtyClass>,
    /// `winsize` (rows/cols/xpixel/ypixel) — TIOCGWINSZ/TIOCSWINSZ.
    winsize: Spinlock<Winsize, TtyClass>,
    /// Foreground process group — TIOCGPGRP/TIOCSPGRP. 0 = unset.
    fg_pgrp: Spinlock<Option<Arc<sched::pid::PidIdentity>>, TtyClass>,
    /// Controlling session id — TIOCSCTTY/TIOCGSID. 0 = unset.
    session: Spinlock<Option<Arc<sched::pid::PidIdentity>>, TtyClass>,
    /// Open reference count (Linux `tty_struct::count`). `open()` bumps,
    /// `close()` drops; the driver's `open()`/`close()` hooks fire on the
    /// 0→1 / 1→0 edges only (first open powers the device, last close
    /// quiesces it).
    pub(super) open_count: AtomicU32,
    /// Exclusive reopen mode (Linux `TTY_EXCLUSIVE`, set by TIOCEXCL).
    /// While an opener exists, later opens by callers without CAP_SYS_ADMIN
    /// fail with EBUSY; TIOCNXCL clears it and TIOCGEXCL reads it.
    pub(super) exclusive: AtomicBool,
    /// Per-tty poll/select/epoll wait queue (the Linux `tty->poll` wait
    /// queue). poll/select/epoll subscribe here via the fd's inode; every
    /// RX / hangup transition calls `subs.notify()` to wake ONLY the tasks
    /// polling THIS tty — no global broadcast.
    subs: alloc::sync::Arc<vfs::PollSubscribers>,
    /// Output-suspend flag (Linux `tty->flow.stopped` / `STOP_OUTPUT`).
    /// Set by TCXONC TCOOFF or a ^S under IXON; cleared by TCOON / ^Q.
    /// While set, `write` parks the caller on the wait queue rather than
    /// emitting — the program's output pauses, never drops (Linux holds
    /// the chars in the driver write queue; we hold the writer's thread).
    /// Lives outside the port lock so the write-park loop can re-check it
    /// without holding the ldisc lock across `park_commit`.
    output_stopped: AtomicBool,
    /// Hangup generation — the per-OPEN half of `__tty_hangup`, which the
    /// reference gets by swapping every open file's `f_op` to a dead vtable.
    /// Bumped once per hangup; each open description samples it and the data
    /// path compares (`crate::hangup::revoke`). Starts at
    /// `revoke::FIRST_GEN`, never decreases, so a revoked description stays
    /// revoked across every later open of the same line.
    pub(super) hup_gen: AtomicU64,
}

#[path = "tty/io.rs"]
mod io;
#[path = "tty/control.rs"]
mod control;

// RX (device-interrupt staging + the workqueue cook) lives in `tty/rx.rs`.
#[path = "tty/rx.rs"] mod rx;
// Per-open revocation (the `hung_up_tty_fops` data path) lives in `tty/revoke.rs`.
#[path = "tty/revoke.rs"] mod revoke;
