use super::*;

impl<D: TtyDriver, W: TtyWait> TtyStruct<D, W> {
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
        // Staged-but-uncooked input is input too: leaving it would make
        // TCIFLUSH deliver it a moment later instead of discarding it.
        if qsel.input() { self.flip.lock_irqsave::<W::Irq>().clear(); }
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
        self.fg_pgrp.lock().as_ref().map_or(0, |id| id.tid)
    }

    /// Strong PID identity held by `tty->ctrl.pgrp`. # C: O(1)
    pub fn foreground_pgrp(&self) -> Option<Arc<sched::pid::PidIdentity>> {
        self.fg_pgrp.lock().as_ref().map(Arc::clone)
    }

    /// Set foreground pgrp (TIOCSPGRP / tcsetpgrp).
    /// # C: O(1)
    pub fn set_fg_pgrp(&self, pgid: u32) {
        let pgrp = if pgid == 0 { None } else {
            sched::registry::tasks_in_pgrp(pgid).into_iter().next().map(|task| task.pgrp())
        };
        #[cfg(test)]
        let pgrp = pgrp.or_else(|| (pgid != 0)
            .then(|| Arc::new(sched::pid::PidIdentity::new(pgid))));
        self.set_foreground_pgrp(pgrp);
    }

    /// Install the already-resolved foreground process-group identity.
    /// # C: O(1)
    pub fn set_foreground_pgrp(&self, pgrp: Option<Arc<sched::pid::PidIdentity>>) {
        self.inner.lock_irqsave::<W::Irq>().driver
            .set_foreground_pgrp(pgrp.as_ref().map(Arc::clone));
        *self.fg_pgrp.lock() = pgrp;
    }

    /// Controlling session id (TIOCGSID). 0 = unset.
    /// # C: O(1)
    pub fn sid(&self) -> u32 {
        self.session.lock().as_ref().map_or(0, |id| id.tid)
    }

    /// Strong PID identity held by `tty->ctrl.session`. # C: O(1)
    pub fn session(&self) -> Option<Arc<sched::pid::PidIdentity>> {
        self.session.lock().as_ref().map(Arc::clone)
    }

    /// Claim this tty as the controlling tty of session `sid` (TIOCSCTTY).
    /// # C: O(1)
    pub fn set_ctty(&self, sid: u32) {
        let session = if sid == 0 { None } else {
            sched::registry::try_snapshot().and_then(|tasks| tasks.into_iter()
                .find(|task| task.session().tid == sid).map(|task| task.session()))
        };
        #[cfg(test)]
        let session = session.or_else(|| (sid != 0)
            .then(|| Arc::new(sched::pid::PidIdentity::new(sid))));
        *self.session.lock() = session;
    }

    /// Install the already-resolved controlling-session identity. # C: O(1)
    pub fn set_session(&self, session: Option<Arc<sched::pid::PidIdentity>>) {
        *self.session.lock() = session;
    }

    /// Release the controlling tty (TIOCNOTTY): clear sid + fg pgrp.
    /// # C: O(1)
    pub fn notty(&self) {
        self.set_session(None);
        self.set_foreground_pgrp(None);
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

    /// Hang up the tty — Linux `__tty_hangup(tty, exit_session)`:
    /// reset the ldisc into its hung-up
    /// state (queues flushed; reads → EOF, writes dropped), notify the driver,
    /// and clear the controlling-session linkage (`tty->ctrl.session` /
    /// `tty->ctrl.pgrp`). Idempotent.
    ///
    /// `kind` selects Linux's `exit_session` argument. It decides ONLY whether
    /// the foreground process group is SIGHUP'd wholesale: `tty_signal_session
    /// _leader` sends `kill_pgrp(tty_pgrp, SIGHUP)` when `exit_session` is set
    /// and NOT otherwise. Signalling the
    /// SESSION LEADER is the caller's job — it needs the task list, which the
    /// driver hook cannot reach (`crate::hangup`).
    /// # C: O(P) fg-pgrp tasks on `SessionExit`, O(1) otherwise
    pub fn hangup(&self, kind: HangupKind) {
        {
            let mut g = self.inner.lock_irqsave::<W::Irq>();
            let PortInner { ldisc, driver } = &mut *g;
            ldisc.hangup();
            if kind == HangupKind::SessionExit { driver.signal_fg_pgrp(Sig::Hup); }
            driver.hangup();
            // Retire every description open across this hangup. Bumped under
            // the port lock, which `open_revocable` also holds while it reads
            // the generation, so an open racing a hangup lands on exactly one
            // side of it and never samples a generation it did not get.
            self.hup_gen.fetch_add(1, Ordering::AcqRel);
        }
        // Drop the controlling-tty linkage (Linux clears tty->session /
        // tty->pgrp on hangup) and wake any parked reader so it observes
        // the hung-up EOF immediately rather than sleeping.
        self.set_session(None);
        self.set_foreground_pgrp(None);
        self.wait.wake_all();
        // Hangup flips POLLHUP + read→EOF: wake poll/select/epoll waiters too
        // (same rationale as receive_from_driver). `tty_release` wakes both the
        // read and the write queue.
        self.subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP);
    }

    /// True once `hangup` has dropped the ldisc into its EOF/EIO state.
    /// # C: O(1)
    pub fn is_hung_up(&self) -> bool {
        self.inner.lock_irqsave::<W::Irq>().ldisc.is_hung_up()
    }

    /// Linux `clear_bit(TTY_HUPPED, &tty->flags)` on a successful `tty_open`.
    /// # C: O(1)
    pub fn clear_hangup(&self) {
        self.inner.lock_irqsave::<W::Irq>().ldisc.clear_hangup();
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

