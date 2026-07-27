// POSIX job-control access decision for a controlling tty — the pure core
// of Linux `tty_check_change` / n_tty `job_control` (`28§6`). Kept in the
// tty crate (host-testable) so the decision is verified by oracle tests;
// the console driver supplies the live context (current task pgrp, ctty
// match, signal disposition, orphan status) and acts on the outcome.

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

#[cfg(test)]
mod tests {
    use super::{decide, Access, Decision};

    #[test]
    fn foreground_and_non_ctty_always_proceed() {
        assert_eq!(decide(true, 5, 5, false, Access::Read, false, false, false), Decision::Proceed);
        assert_eq!(decide(false, 9, 5, false, Access::Read, false, false, true), Decision::Proceed);
        assert_eq!(decide(true, 9, 0, false, Access::Read, false, false, false), Decision::Proceed);
    }

    #[test]
    fn background_read_stops_pgrp() {
        assert_eq!(decide(true, 9, 5, false, Access::Read, false, false, false), Decision::Stop);
    }

    #[test]
    fn background_read_eio_when_ignored_blocked_or_orphaned() {
        assert_eq!(decide(true, 9, 5, false, Access::Read, true, false, false), Decision::Eio);
        assert_eq!(decide(true, 9, 5, false, Access::Read, false, true, false), Decision::Eio);
        assert_eq!(decide(true, 9, 5, false, Access::Read, false, false, true), Decision::Eio);
    }

    #[test]
    fn background_write_allowed_without_tostop() {
        assert_eq!(decide(true, 9, 5, false, Access::Write, false, false, false), Decision::Proceed);
    }

    #[test]
    fn background_write_under_tostop_stops_or_allows() {
        assert_eq!(decide(true, 9, 5, true, Access::Write, false, false, false), Decision::Stop);
        // SIGTTOU ignored → allowed (NOT EIO, unlike read).
        assert_eq!(decide(true, 9, 5, true, Access::Write, true, false, false), Decision::Proceed);
        assert_eq!(decide(true, 9, 5, true, Access::Write, false, false, true), Decision::Eio);
    }
}

#[cfg(test)]
mod restart_tests {
    use super::*;

    #[test]
    fn a_background_access_that_stops_the_pgrp_returns_erestartsys_not_eintr() {
        // `drivers/tty/tty_jobctrl.c:55-59` — kill_pgrp + TIF_SIGPENDING +
        // -ERESTARTSYS, so the access re-runs after the job is continued.
        assert_eq!(Decision::Stop.vfs_err(), Some(vfs::VfsError::Erestartsys));
        assert_ne!(Decision::Stop.vfs_err(), Some(vfs::VfsError::Eintr));
    }

    #[test]
    fn the_orphan_and_ignored_cases_stay_eio_and_proceed_stays_ok() {
        // `tty_jobctrl.c:50-54`: is_ignored -> EIO for SIGTTIN,
        // is_current_pgrp_orphaned -> EIO. Neither is a restart.
        assert_eq!(Decision::Eio.vfs_err(), Some(vfs::VfsError::Eio));
        assert_eq!(Decision::Proceed.vfs_err(), None);
    }

    #[test]
    fn a_stopped_background_read_is_the_only_restartable_outcome() {
        for d in [Decision::Proceed, Decision::Eio] {
            assert_ne!(d.vfs_err(), Some(vfs::VfsError::Erestartsys), "{d:?}");
        }
    }
}
