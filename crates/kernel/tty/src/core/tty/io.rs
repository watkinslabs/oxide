use super::*;

impl<D: TtyDriver, W: TtyWait> TtyStruct<D, W> {
    /// Build a tty around a driver, a fresh N_TTY ldisc, and a wait queue.
    /// # C: O(1)
    pub fn new(driver: D, wait: W) -> Self {
        Self::new_with_sink(driver, wait, D::detached_sink())
    }

    /// Build a tty with an endpoint selected by the device instance. # C: O(1)
    pub fn new_with_sink(driver: D, wait: W, sink: Option<DetachedSink>) -> Self {
        Self {
            inner: Spinlock::new(PortInner { ldisc: NTty::new(), driver }),
            tx: Spinlock::new(()),
            sink,
            flip: Spinlock::new(super::super::flip::FlipRing::new()),
            wait,
            winsize: Spinlock::new(Winsize::default_pty()),
            fg_pgrp: Spinlock::new(None),
            session: Spinlock::new(None),
            open_count: AtomicU32::new(0),
            exclusive: AtomicBool::new(false),
            subs: alloc::sync::Arc::new(vfs::PollSubscribers::new()),
            output_stopped: AtomicBool::new(false),
            hup_gen: AtomicU64::new(crate::hangup::revoke::FIRST_GEN),
        }
    }

    /// The per-tty poll/select/epoll wait queue, for the fd inode's
    /// `poll_subscribers()`. # C: O(1)
    pub fn poll_subs(&self) -> &vfs::PollSubscribers { &self.subs }

    /// The same queue as a shared handle, so the tty's device inode can
    /// publish it through `InodeBuilder::poll_subs_arc` — one list, shared by
    /// the notifier and the waiter, never two that can disagree. # C: O(1)
    pub fn poll_subs_arc(&self) -> alloc::sync::Arc<vfs::PollSubscribers> {
        alloc::sync::Arc::clone(&self.subs)
    }

    /// Build with a caller-supplied termios image (raw-mode ptys etc.).
    /// # C: O(1)
    pub fn with_termios(driver: D, wait: W, t: [u8; TERMIOS_BYTES]) -> Self {
        let s = Self::new(driver, wait);
        s.inner.lock_irqsave::<W::Irq>().ldisc = NTty::with_termios(t);
        s
    }

    /// Build with caller-selected termios and post-lock output endpoint. # C: O(1)
    pub fn with_termios_and_sink(driver: D, wait: W, t: [u8; TERMIOS_BYTES], sink: Option<DetachedSink>) -> Self {
        let s = Self::new_with_sink(driver, wait, sink);
        s.inner.lock_irqsave::<W::Irq>().ldisc = NTty::with_termios(t);
        s
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
        // The port lock is irqsave (the RX ISR takes it), so anything done
        // under it runs with interrupts masked. When the driver offers a
        // detached sink, buffer the ldisc's output under the lock and push it
        // to the device AFTER releasing it — so device submission never runs
        // with this tty port's interrupts masked (`skizm.md` Step 4e). Drivers
        // without such a sink (VT, tests) keep the inline path, unchanged.
        let Some(sink) = self.sink else {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
            let PortInner { ldisc, driver } = &mut *g;
            return ldisc.write(driver, buf);
        };
        // Held across buffer+emit so writers serialise; taken BEFORE the port
        // lock (rank 119 < 120), and the ISR never takes it.
        let _tx = self.tx.lock();
        let (n, pending) = {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
            let PortInner { ldisc, driver } = &mut *g;
            let mut tx = TxCollector { drv: driver, buf: alloc::vec::Vec::new() };
            let n = ldisc.write(&mut tx, buf);
            (n, tx.buf)
        };
        // Guard released, interrupts restored: transmit here.
        if !pending.is_empty() { sink.emit(&pending); }
        n
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
}
