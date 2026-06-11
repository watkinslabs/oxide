// TTY core — Linux `drivers/tty/tty_io.c`: `tty_struct`, `tty_driver`,
// `tty_port`. Ties an N_TTY ldisc (T3) to a driver, owns the blocking
// read/write, the input flip buffer, termios, winsize, fg pgrp / sid,
// controlling-tty linkage, and the TIOC* ioctls.
//
// Position in the stack (tty-rebuild-plan §0):
//
//   /dev node (T8) ─▶ TtyStruct ─▶ NTty (ldisc, T3) ─▶ TtyDriver
//        read/write/    │  block/wake    cook/echo/      │ VT emulator
//        poll/ioctl     │  flip buffer   ISIG            │ or UART
//                       └── TtyWait (park/wake) ─────────┘
//
// LOST-WAKEUP-FREE BLOCKING READ — the whole reason login was flaky.
// See `wait.rs` for the full argument. The ordering, enforced here:
//
//   read():
//     loop {
//       fast path: drain ready bytes → return                (no lock)
//       LOCK port
//         wait.park_prepare()         // enqueue self as waiter
//         if ldisc.has_input() { wait.park_abort(); UNLOCK; continue; }
//       UNLOCK port
//       wait.park_commit()            // sleep
//     }
//
//   receive_from_driver():
//     LOCK port
//       ldisc.receive_buf(...)        // queue cooked bytes
//     UNLOCK port
//     wait.wake_all()                 // wake parked readers
//
// `park_prepare` (enqueue) runs UNDER the port lock and BEFORE the
// `has_input` re-check (also under the lock); the producer queues bytes
// under the same lock before waking. So a byte queued after our re-check
// always comes with a wake that finds us enqueued; a byte queued before
// our re-check is seen by the re-check. No interleaving sleeps forever.
//
// Generic over the driver (`D: TtyDriver`) and the wait (`W: TtyWait`) —
// no `dyn` (07§5). The ldisc is `NTty` (T3) directly; swappable
// disciplines are out of scope for v1 (N_TTY is the only one Linux ships
// for ttys).

extern crate alloc;

use ::core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, Tty as TtyClass};

use crate::ldisc::{vmin_vtime_decision, LdiscOps, NTty, Sig, TtyDriverHooks, VmtDecision};
use crate::pty::{Winsize, TERMIOS_BYTES};
use crate::wait::TtyWait;

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

/// The mutable state the port lock protects: the line discipline (which
/// owns the cooked read queue + the half-built canonical line — Linux's
/// flip buffer is consumed straight into `n_tty_receive_buf`, so the
/// ldisc IS the post-flip input store here) and the driver (the
/// `driver_write` echo path re-enters it under the same lock).
struct PortInner<D: TtyDriver> {
    ldisc: NTty,
    driver: D,
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
    inner: Spinlock<PortInner<D>, TtyClass>,
    wait: W,
    /// `winsize` (rows/cols/xpixel/ypixel) — TIOCGWINSZ/TIOCSWINSZ.
    winsize: Spinlock<Winsize, TtyClass>,
    /// Foreground process group — TIOCGPGRP/TIOCSPGRP. 0 = unset.
    fg_pgrp: AtomicU32,
    /// Controlling session id — TIOCSCTTY/TIOCGSID. 0 = unset.
    sid: AtomicU32,
    /// Open reference count (Linux `tty_struct::count`). `open()` bumps,
    /// `close()` drops; the driver's `open()`/`close()` hooks fire on the
    /// 0→1 / 1→0 edges only (first open powers the device, last close
    /// quiesces it).
    open_count: AtomicU32,
    /// Per-tty poll/select/epoll wait queue (the Linux `tty->poll` wait
    /// queue). poll/select/epoll subscribe here via the fd's inode; every
    /// RX / hangup transition calls `subs.notify()` to wake ONLY the tasks
    /// polling THIS tty — no global broadcast.
    subs: vfs::PollSubscribers,
}

impl<D: TtyDriver, W: TtyWait> TtyStruct<D, W> {
    /// Build a tty around a driver, a fresh N_TTY ldisc, and a wait queue.
    /// # C: O(1)
    pub fn new(driver: D, wait: W) -> Self {
        Self {
            inner: Spinlock::new(PortInner { ldisc: NTty::new(), driver }),
            wait,
            winsize: Spinlock::new(Winsize::default_pty()),
            fg_pgrp: AtomicU32::new(0),
            sid: AtomicU32::new(0),
            open_count: AtomicU32::new(0),
            subs: vfs::PollSubscribers::new(),
        }
    }

    /// The per-tty poll/select/epoll wait queue, for the fd inode's
    /// `poll_subscribers()`. # C: O(1)
    pub fn poll_subs(&self) -> &vfs::PollSubscribers { &self.subs }

    /// Build with a caller-supplied termios image (raw-mode ptys etc.).
    /// # C: O(1)
    pub fn with_termios(driver: D, wait: W, t: [u8; TERMIOS_BYTES]) -> Self {
        let s = Self::new(driver, wait);
        s.inner.lock().ldisc = NTty::with_termios(t);
        s
    }

    /// RX path: device delivered `input` (UART RX / kbd). Runs the ldisc
    /// receive pipeline (cook/echo/ISIG) UNDER the port lock, then wakes
    /// parked readers OUTSIDE the lock. The under-lock queue + the
    /// release-then-wake is the producer half of the lost-wakeup-free
    /// protocol (see module header).
    /// # C: O(N) input bytes + O(W) waiters
    pub fn receive_from_driver(&self, input: &[u8]) {
        {
            let mut g = self.inner.lock();
            let PortInner { ldisc, driver } = &mut *g;
            ldisc.receive_buf(driver, input);
        }
        // Wake AFTER dropping the lock: a reader that enqueued under the
        // lock (park_prepare) and then re-checked is guaranteed visible to
        // wake_all here, because its enqueue serialized with our queue
        // above on the same port lock.
        self.wait.wake_all();
        // The RX byte queue just flipped POLLIN readable: wake ONLY the tasks
        // polling THIS tty (poll/select/ppoll/epoll subscribed to our
        // `PollSubscribers` via the fd inode's `poll_subscribers()`). Per-fd,
        // targeted — the Linux `->poll` wait-queue wake. Outside the port lock
        // (same as the reader wake); level-triggered, so spurious wakes safe.
        self.subs.notify();
    }

    /// Blocking read — THE lost-wakeup-free read. Returns a whole cooked
    /// line in canonical mode, or honours c_cc[VMIN]/c_cc[VTIME] in
    /// noncanonical mode (the 4 Linux cases), or EOF, or `Interrupted`
    /// when an unblocked signal lands during the wait (Linux `n_tty_read`
    /// `signal_pending` → -EINTR). See the module header for the
    /// lost-wakeup ordering proof.
    /// # C: O(N) bytes copied + sleeps until input / timer / signal
    pub fn read(&self, buf: &mut [u8]) -> ReadOutcome {
        if buf.is_empty() {
            return ReadOutcome::Bytes(0);
        }
        if self.inner.lock().ldisc.canonical() {
            self.read_canon(buf)
        } else {
            self.read_raw(buf)
        }
    }

    /// Canonical (ICANON) blocking read: block until a whole line or EOF,
    /// interruptible by an unblocked signal. Unchanged line semantics —
    /// the login / PAM path depends on this returning a full `\n`-
    /// terminated line.
    fn read_canon(&self, buf: &mut [u8]) -> ReadOutcome {
        loop {
            // Fast path: drain whatever is ready without parking.
            {
                let mut g = self.inner.lock();
                let n = g.ldisc.read(buf);
                if n > 0 {
                    return ReadOutcome::Bytes(n);
                }
                // n == 0 with EOF pending also returns (canonical ^D).
                if g.ldisc.eof_consumed() {
                    return ReadOutcome::Eof;
                }
            }
            // A pending unblocked signal aborts the blocking read (EINTR).
            if self.wait.should_interrupt() {
                return ReadOutcome::Interrupted;
            }
            // Slow path: enqueue, RE-CHECK under the lock, then sleep.
            {
                let g = self.inner.lock();
                self.wait.park_prepare();
                if g.ldisc.has_input() {
                    // A byte landed between the fast-path drain and our
                    // enqueue — drop the would-be sleep and loop to drain.
                    self.wait.park_abort();
                    continue;
                }
                // Drop the port lock BEFORE sleeping so the producer can
                // take it to queue + wake.
            }
            self.wait.park_commit();
        }
    }

    /// Noncanonical (raw) blocking read honouring c_cc[VMIN]/c_cc[VTIME]
    /// (the 4 Linux cases — see `vmin_vtime_decision`). The VTIME timers
    /// use the wait queue's `park_commit_deadline`; the read-timer base is
    /// captured at entry and the interbyte timer resets as bytes arrive.
    /// Signal-interruptible like the canonical path.
    fn read_raw(&self, buf: &mut [u8]) -> ReadOutcome {
        // Monotonic bases (kernel clock; host returns 0 — host VMIN/VTIME
        // coverage drives `vmin_vtime_decision` directly).
        let start = self.wait.now_ns();
        let mut last_byte_at = start;
        let mut got_any = false;
        let mut prev_avail = 0usize;
        loop {
            let (min, time, avail) = {
                let g = self.inner.lock();
                (g.ldisc.vmin(), g.ldisc.vtime(), g.ldisc.available())
            };
            // Interbyte timer (MIN>0,TIME>0): reset the timer base on each
            // newly-arrived byte (Linux restarts VTIME per received char).
            if avail > prev_avail {
                got_any = true;
                last_byte_at = self.wait.now_ns();
            }
            prev_avail = avail;
            let now = self.wait.now_ns();
            let decision = vmin_vtime_decision(
                min, time, avail, buf.len(),
                now.saturating_sub(start), now.saturating_sub(last_byte_at), got_any,
            );
            match decision {
                VmtDecision::ReturnNow(_) => {
                    // Drain ignoring VMIN: a VTIME timeout returns fewer
                    // than VMIN bytes (incl. 0 on a polling read).
                    let n = self.inner.lock().ldisc.read_raw_drain(buf);
                    return ReadOutcome::Bytes(n);
                }
                VmtDecision::BlockUntil(rel) => {
                    if self.wait.should_interrupt() {
                        return ReadOutcome::Interrupted;
                    }
                    // Re-check under the lock then park with a deadline.
                    {
                        let g = self.inner.lock();
                        self.wait.park_prepare();
                        if g.ldisc.has_input() {
                            self.wait.park_abort();
                            continue;
                        }
                    }
                    // For MIN==0 the deadline is start-relative; for the
                    // interbyte timer it is last-byte-relative — both
                    // resolve to an absolute clock instant here.
                    let base = if min == 0 { start } else { last_byte_at };
                    self.wait.park_commit_deadline(base.saturating_add(rel));
                }
                VmtDecision::BlockNoDeadline => {
                    if self.wait.should_interrupt() {
                        return ReadOutcome::Interrupted;
                    }
                    {
                        let g = self.inner.lock();
                        self.wait.park_prepare();
                        if g.ldisc.has_input() {
                            self.wait.park_abort();
                            continue;
                        }
                    }
                    self.wait.park_commit();
                }
            }
        }
    }

    /// Non-blocking read: drain ready bytes, never park. Returns 0 when
    /// nothing is queued (callers map that to EAGAIN at the syscall layer
    /// for O_NONBLOCK fds).
    /// # C: O(N) bytes copied
    pub fn read_nonblock(&self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        self.inner.lock().ldisc.read(buf)
    }

    /// Write `buf` through the ldisc output processing (OPOST/ONLCR/…) to
    /// the driver. Returns bytes consumed.
    /// # C: O(N) bytes
    pub fn write(&self, buf: &[u8]) -> usize {
        let mut g = self.inner.lock();
        let PortInner { ldisc, driver } = &mut *g;
        ldisc.write(driver, buf)
    }

    /// Poll mask (POLLIN when a read would return; POLLOUT always).
    /// # C: O(1)
    pub fn poll(&self) -> u32 {
        self.inner.lock().ldisc.poll()
    }

    /// True when a `read` would not block.
    /// # C: O(1)
    pub fn readable(&self) -> bool {
        self.inner.lock().ldisc.has_input()
    }

    // --- termios -------------------------------------------------------

    /// Snapshot the termios image (TCGETS).
    /// # C: O(1)
    pub fn termios(&self) -> [u8; TERMIOS_BYTES] {
        self.inner.lock().ldisc.termios()
    }

    /// Replace the termios image (TCSETS{,W,F}); notifies the driver.
    /// # C: O(1)
    pub fn set_termios(&self, new: &[u8; TERMIOS_BYTES]) {
        let mut g = self.inner.lock();
        g.ldisc.set_termios(new);
        g.driver.set_termios(new);
    }

    /// TCFLSH: discard queued I/O. `qsel` is the ioctl arg — TCIFLUSH(0)
    /// drops unread input, TCOFLUSH(1) drops untransmitted output,
    /// TCIOFLUSH(2) both. Also the input-flush half of TCSETSF. # C: O(1)
    pub fn flush(&self, qsel: TtyFlush) {
        let mut g = self.inner.lock();
        if qsel.input() { g.ldisc.flush_input(); }
        if qsel.output() { g.ldisc.flush_output(); }
    }

    // --- winsize -------------------------------------------------------

    /// Read winsize (TIOCGWINSZ).
    /// # C: O(1)
    pub fn winsize(&self) -> Winsize {
        *self.winsize.lock()
    }

    /// Set winsize (TIOCSWINSZ). Returns true if it changed (caller
    /// raises SIGWINCH on the fg pgrp).
    /// # C: O(1)
    pub fn set_winsize(&self, ws: Winsize) -> bool {
        let mut g = self.winsize.lock();
        let changed = *g != ws;
        *g = ws;
        changed
    }

    // --- pgrp / session ------------------------------------------------

    /// Foreground pgrp (TIOCGPGRP). 0 = unset.
    /// # C: O(1)
    pub fn fg_pgrp(&self) -> u32 {
        self.fg_pgrp.load(Ordering::Acquire)
    }

    /// Set foreground pgrp (TIOCSPGRP / tcsetpgrp).
    /// # C: O(1)
    pub fn set_fg_pgrp(&self, pgid: u32) {
        self.fg_pgrp.store(pgid, Ordering::Release)
    }

    /// Controlling session id (TIOCGSID). 0 = unset.
    /// # C: O(1)
    pub fn sid(&self) -> u32 {
        self.sid.load(Ordering::Acquire)
    }

    /// Claim this tty as the controlling tty of session `sid` (TIOCSCTTY).
    /// # C: O(1)
    pub fn set_ctty(&self, sid: u32) {
        self.sid.store(sid, Ordering::Release)
    }

    /// Release the controlling tty (TIOCNOTTY): clear sid + fg pgrp.
    /// # C: O(1)
    pub fn notty(&self) {
        self.sid.store(0, Ordering::Release);
        self.fg_pgrp.store(0, Ordering::Release);
    }

    /// Generic TIOC* ioctl dispatch shared by every device class. The
    /// driver gets first refusal (`TtyDriver::ioctl`); unhandled TIOC*
    /// fall through to the core's pgrp/sid/termios/winsize handling via
    /// the typed `IoctlReq` decode in `ioctl.rs`. Returns the syscall
    /// return value, or `None` if the request is not a core tty ioctl
    /// (caller returns ENOTTY).
    /// # C: O(1)
    pub fn ioctl(&self, cmd: u32, arg: u64) -> Option<i64> {
        if let Some(rv) = self.inner.lock().driver.ioctl(cmd, arg) {
            return Some(rv);
        }
        crate::ioctl::core_ioctl(self, cmd, arg)
    }

    // --- open / close / hangup (Linux tty lifecycle) ------------------

    /// Current open reference count (Linux `tty_struct::count`).
    /// # C: O(1)
    pub fn open_count(&self) -> u32 {
        self.open_count.load(Ordering::Acquire)
    }

    /// Open reference: bump the count; fire `driver.open()` on the 0→1
    /// edge (first opener powers the device). The VFS open path for the
    /// tty inode calls this once per `open(2)` that succeeds. Returns the
    /// new count.
    /// # C: O(1)
    pub fn open(&self) -> u32 {
        let prev = self.open_count.fetch_add(1, Ordering::AcqRel);
        if prev == 0 {
            self.inner.lock().driver.open();
        }
        prev + 1
    }

    /// Release reference: drop the count; fire `driver.close()` on the
    /// 1→0 edge (last closer quiesces the device). The VFS release path
    /// (final fd close) calls this. Saturates at 0 (a close with no open
    /// is a no-op, never an underflow). Returns the new count.
    /// # C: O(1)
    pub fn close(&self) -> u32 {
        let prev = self.open_count.load(Ordering::Acquire);
        if prev == 0 { return 0; }
        let now = self.open_count.fetch_sub(1, Ordering::AcqRel) - 1;
        if now == 0 {
            self.inner.lock().driver.close();
        }
        now
    }

    /// Hang up the tty (Linux `tty_hangup` / `__tty_hangup`): raise SIGHUP
    /// on the foreground process group, reset the ldisc into its hung-up
    /// state (queues flushed; reads → EOF, writes dropped), notify the
    /// driver, and clear the controlling-session linkage. Idempotent — a
    /// second hangup re-signals but the ldisc state is already hung.
    /// # C: O(P) fg-pgrp tasks
    pub fn hangup(&self) {
        {
            let mut g = self.inner.lock();
            let PortInner { ldisc, driver } = &mut *g;
            ldisc.hangup();
            driver.signal_fg_pgrp(Sig::Hup);
            driver.hangup();
        }
        // Drop the controlling-tty linkage (Linux clears tty->session /
        // tty->pgrp on hangup) and wake any parked reader so it observes
        // the hung-up EOF immediately rather than sleeping.
        self.sid.store(0, Ordering::Release);
        self.fg_pgrp.store(0, Ordering::Release);
        self.wait.wake_all();
        // Hangup flips POLLHUP + read→EOF: wake poll/select/epoll waiters too
        // (same rationale as receive_from_driver).
        self.subs.notify();
    }

    /// True once `hangup` has dropped the ldisc into its EOF/EIO state.
    /// # C: O(1)
    pub fn is_hung_up(&self) -> bool {
        self.inner.lock().ldisc.is_hung_up()
    }

    /// Run a closure against the driver (open/close/hangup plumbing, and
    /// driver-specific RX injection in tests).
    /// # C: closure-defined
    pub fn with_driver<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        f(&mut self.inner.lock().driver)
    }

    /// Borrow the wait queue (introspection / test counters).
    /// # C: O(1)
    pub fn wait_handle(&self) -> &W {
        &self.wait
    }
}

#[cfg(test)]
mod tests;
