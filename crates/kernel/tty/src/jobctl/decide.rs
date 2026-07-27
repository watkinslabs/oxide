// Pure core of Linux `__tty_check_change` (`drivers/tty/tty_jobctrl.c:33-66`).
// Kept out of any driver so the rule is verified by oracle tests and cannot
// drift between the console/serial VTs and the devpts pty slaves; each driver
// supplies the live context and acts on the outcome.

/// Whether the access being gated is a read or a write.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Access {
    Read,
    Write,
}

/// Outcome of the job-control check.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Decision {
    /// Allowed — perform the read/write.
    Proceed,
    /// Fail with EIO (orphaned pgrp, or background read with the stop
    /// signal ignored/blocked).
    Eio,
    /// Stop the caller's process group (send SIGTTIN/SIGTTOU) and fail the
    /// syscall with `-ERESTARTSYS` (`drivers/tty/tty_jobctrl.c:55-59`).
    Stop,
}

impl Decision {
    /// The VFS error this decision fails with, or `None` to proceed.
    ///
    /// `Stop` is `-ERESTARTSYS`, NOT `-EINTR`, and that is a different rule
    /// from the ordinary interruptible read-queue wait in the same driver.
    /// Linux pairs it with `set_thread_flag(TIF_SIGPENDING)`
    /// (`tty_jobctrl.c:56-58`) precisely so the access RE-RUNS once SIGCONT
    /// continues the stopped process group — with EINTR a backgrounded read
    /// fails permanently instead of resuming after `fg`.
    /// # C: O(1)
    pub const fn vfs_err(self) -> Option<vfs::VfsError> {
        match self {
            Decision::Proceed => None,
            Decision::Eio => Some(vfs::VfsError::Eio),
            Decision::Stop => Some(vfs::VfsError::Erestartsys),
        }
    }
}

/// Decide whether a (possibly background) access to a controlling tty is
/// allowed (Linux `tty_check_change`). Inputs:
///   `is_ctty`   — the tty is the caller's controlling tty
///   `pgid`/`fg` — caller's pgrp / tty's foreground pgrp (0 = unset)
///   `tostop`    — TOSTOP set in `c_lflag`
///   `ignored`/`blocked` — caller's disposition of the stop signal
///   `orphaned`  — caller's pgrp is orphaned (no continuing parent)
/// # C: O(1).
pub fn decide(
    is_ctty: bool,
    pgid: u32,
    fg: u32,
    tostop: bool,
    access: Access,
    ignored: bool,
    blocked: bool,
    orphaned: bool,
) -> Decision {
    // Not our controlling tty, or unset fg/pgid, or foreground → allowed.
    if !is_ctty || fg == 0 || pgid == 0 || pgid == fg {
        return Decision::Proceed;
    }
    // Background write is allowed unless TOSTOP is set.
    if access == Access::Write && !tostop {
        return Decision::Proceed;
    }
    if ignored || blocked {
        // Background read with SIGTTIN ignored/blocked → EIO; background
        // write with SIGTTOU ignored/blocked is allowed through.
        return match access {
            Access::Read => Decision::Eio,
            Access::Write => Decision::Proceed,
        };
    }
    // An orphaned pgrp has no shell to continue it — don't stop it.
    if orphaned {
        return Decision::Eio;
    }
    Decision::Stop
}
