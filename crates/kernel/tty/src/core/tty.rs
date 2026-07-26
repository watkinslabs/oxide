use ::core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, Tty as TtyClass};

use super::api::{ReadOutcome, TtyDriver, TtyFlow, TtyFlush};
use crate::ldisc::{vmin_vtime_decision, LdiscOps, NTty, Sig, VmtDecision};
use crate::pty::{Winsize, TERMIOS_BYTES};
use crate::wait::TtyWait;

/// The mutable state the port lock protects: the line discipline (which
/// owns the cooked read queue + the half-built canonical line — Linux's
/// flip buffer is consumed straight into `n_tty_receive_buf`, so the
/// ldisc IS the post-flip input store here) and the driver (the
/// `driver_write` echo path re-enters it under the same lock).
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
    pub(super) open_count: AtomicU32,
    /// Exclusive reopen mode (Linux `TTY_EXCLUSIVE`, set by TIOCEXCL).
    /// While an opener exists, later opens by callers without CAP_SYS_ADMIN
    /// fail with EBUSY; TIOCNXCL clears it and TIOCGEXCL reads it.
    pub(super) exclusive: AtomicBool,
    /// Per-tty poll/select/epoll wait queue (the Linux `tty->poll` wait
    /// queue). poll/select/epoll subscribe here via the fd's inode; every
    /// RX / hangup transition calls `subs.notify()` to wake ONLY the tasks
    /// polling THIS tty — no global broadcast.
    subs: vfs::PollSubscribers,
    /// Output-suspend flag (Linux `tty->flow.stopped` / `STOP_OUTPUT`).
    /// Set by TCXONC TCOOFF or a ^S under IXON; cleared by TCOON / ^Q.
    /// While set, `write` parks the caller on the wait queue rather than
    /// emitting — the program's output pauses, never drops (Linux holds
    /// the chars in the driver write queue; we hold the writer's thread).
    /// Lives outside the port lock so the write-park loop can re-check it
    /// without holding the ldisc lock across `park_commit`.
    output_stopped: AtomicBool,
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
            exclusive: AtomicBool::new(false),
            subs: vfs::PollSubscribers::new(),
            output_stopped: AtomicBool::new(false),
        }
    }

    /// The per-tty poll/select/epoll wait queue, for the fd inode's
    /// `poll_subscribers()`. # C: O(1)
    pub fn poll_subs(&self) -> &vfs::PollSubscribers { &self.subs }

    /// Build with a caller-supplied termios image (raw-mode ptys etc.).
    /// # C: O(1)
    pub fn with_termios(driver: D, wait: W, t: [u8; TERMIOS_BYTES]) -> Self {
        let s = Self::new(driver, wait);
        s.inner.lock_irqsave::<W::Irq>().ldisc = NTty::with_termios(t);
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
            let mut g = self.inner.lock_irqsave::<W::Irq>();
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
        if self.inner.lock_irqsave::<W::Irq>().ldisc.canonical() {
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
                let mut g = self.inner.lock_irqsave::<W::Irq>();
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
                let g = self.inner.lock_irqsave::<W::Irq>();
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
                let g = self.inner.lock_irqsave::<W::Irq>();
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
                    let n = self.inner.lock_irqsave::<W::Irq>().ldisc.read_raw_drain(buf);
                    return ReadOutcome::Bytes(n);
                }
                VmtDecision::BlockUntil(rel) => {
                    if self.wait.should_interrupt() {
                        return ReadOutcome::Interrupted;
                    }
                    // Re-check under the lock then park with a deadline.
                    {
                        let g = self.inner.lock_irqsave::<W::Irq>();
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
                        let g = self.inner.lock_irqsave::<W::Irq>();
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
        self.inner.lock_irqsave::<W::Irq>().ldisc.read(buf)
    }

    /// Write `buf` through the ldisc output processing (OPOST/ONLCR/…) to
    /// the driver. Returns bytes consumed.
    ///
    /// OUTPUT FLOW CONTROL (TCXONC TCOOFF / ^S): if `output_stopped` is
    /// set, park the writer on the wait queue until TCOON / ^Q clears it,
    /// then emit — Linux pauses the program's output, it does not drop or
    /// error. A pending unblocked signal aborts the wait (the byte count
    /// returned is 0 → the syscall layer maps that to a short write /
    /// EINTR like a parked reader). The re-check uses the same wait queue
    /// the reader path uses, so the `flow` resume wakes both.
    /// # C: O(N) bytes; sleeps while output is suspended
    pub fn write(&self, buf: &[u8]) -> usize {
        // Hold the writer while output is suspended. Re-check after each
        // wake (level-triggered: resume clears the flag then wakes). No
        // port lock is held across the park, so RX + resume proceed.
        while self.output_stopped.load(Ordering::Acquire) {
            if self.wait.should_interrupt() { return 0; }
            self.wait.park_prepare();
            // Re-check under the just-enqueued state: if resume cleared the
            // flag between the load and the enqueue, abort the sleep.
            if !self.output_stopped.load(Ordering::Acquire) {
                self.wait.park_abort();
                break;
            }
            self.wait.park_commit();
        }
        // KNOWN COST (`skizm.md` Step 4e): the guard is irqsave — it must be,
        // the RX ISR takes this lock — and `ldisc.write` reaches
        // `driver_write`, which on the serial console polls LSR THR-empty PER
        // BYTE. So a large write masks interrupts for its whole transmission.
        // Linux does not do this: its `uart_port` lock covers queueing into the
        // TX ring and the TX ISR drains it. Fixing it here needs that TX ring,
        // not a narrower lock — the ldisc and the driver share this guard.
        let mut g = self.inner.lock_irqsave::<W::Irq>();
        let PortInner { ldisc, driver } = &mut *g;
        ldisc.write(driver, buf)
    }

    /// TCXONC software flow control (tcflow(3)). TCOOFF suspends output
    /// (sets the flag so `write` parks); TCOON resumes (clears it + wakes
    /// parked writers). TCIOFF/TCION (transmit a STOP/START char toward the
    /// input source) are honoured as state on the local flag for the
    /// console/serial line: there is no separate upstream to signal, so
    /// InputOff is treated like a local output-suspend request and InputOn
    /// like a resume — `false` is returned for them so the shim can choose
    /// to report the narrower no-effect honestly; callers that only care
    /// about the must-have output path use OutputOff/OutputOn.
    ///
    /// Returns `true` when the action changed the output-suspend state.
    /// # C: O(W) parked writers on resume
    pub fn flow(&self, action: TtyFlow) -> bool {
        match action {
            TtyFlow::OutputOff => {
                let prev = self.output_stopped.swap(true, Ordering::AcqRel);
                !prev
            }
            TtyFlow::OutputOn => {
                let prev = self.output_stopped.swap(false, Ordering::AcqRel);
                // Wake any writer parked in `write`'s suspend loop.
                self.wait.wake_all();
                prev
            }
            // No upstream transmitter to flow-control on a directly-attached
            // line; record nothing and report no state change.
            TtyFlow::InputOff | TtyFlow::InputOn => false,
        }
    }

    /// True while output is suspended (TCXONC TCOOFF / ^S in effect).
    /// # C: O(1)
    pub fn output_stopped(&self) -> bool {
        self.output_stopped.load(Ordering::Acquire)
    }

    /// Poll mask (POLLIN when a read would return; POLLOUT always).
    /// # C: O(1)
    pub fn poll(&self) -> u32 {
        self.inner.lock_irqsave::<W::Irq>().ldisc.poll()
    }

    /// True when a `read` would not block.
    /// # C: O(1)
    pub fn readable(&self) -> bool {
        self.inner.lock_irqsave::<W::Irq>().ldisc.has_input()
    }

    // --- termios -------------------------------------------------------

    /// Snapshot the termios image (TCGETS).
    /// # C: O(1)
    pub fn termios(&self) -> [u8; TERMIOS_BYTES] {
        self.inner.lock_irqsave::<W::Irq>().ldisc.termios()
    }

    /// Replace the termios image (TCSETS{,W,F}); notifies the driver.
    /// # C: O(1)
    pub fn set_termios(&self, new: &[u8; TERMIOS_BYTES]) {
        let mut g = self.inner.lock_irqsave::<W::Irq>();
        g.ldisc.set_termios(new);
        g.driver.set_termios(new);
    }

    /// TCFLSH: discard queued I/O. `qsel` is the ioctl arg — TCIFLUSH(0)
    /// drops unread input, TCOFLUSH(1) drops untransmitted output,
    /// TCIOFLUSH(2) both. Also the input-flush half of TCSETSF. # C: O(1)
    pub fn flush(&self, qsel: TtyFlush) {
        let mut g = self.inner.lock_irqsave::<W::Irq>();
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
        if let Some(rv) = self.inner.lock_irqsave::<W::Irq>().driver.ioctl(cmd, arg) {
            return Some(rv);
        }
        crate::ioctl::core_ioctl(self, cmd, arg)
    }

    /// Hang up the tty (Linux `tty_hangup` / `__tty_hangup`): raise SIGHUP
    /// on the foreground process group, reset the ldisc into its hung-up
    /// state (queues flushed; reads → EOF, writes dropped), notify the
    /// driver, and clear the controlling-session linkage. Idempotent — a
    /// second hangup re-signals but the ldisc state is already hung.
    /// # C: O(P) fg-pgrp tasks
    pub fn hangup(&self) {
        {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
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
        self.inner.lock_irqsave::<W::Irq>().ldisc.is_hung_up()
    }

    /// Run a closure against the driver (open/close/hangup plumbing, and
    /// driver-specific RX injection in tests).
    /// # C: closure-defined
    pub fn with_driver<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        f(&mut self.inner.lock_irqsave::<W::Irq>().driver)
    }

    /// Borrow the wait queue (introspection / test counters).
    /// # C: O(1)
    pub fn wait_handle(&self) -> &W {
        &self.wait
    }
}
