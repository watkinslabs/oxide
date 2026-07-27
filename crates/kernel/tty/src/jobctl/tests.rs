use super::{decide, Access, Decision};
use crate::ctty::{kind_can_be_ctty, should_acquire_ctty, TtyKind};

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

// ---------------------------------------------------------------------------
// Decision chain of `userspace/wait_diff/jobctl.c` (B1451).
//
// The probe's session leader `setsid()`s and opens the tty (no O_NOCTTY),
// then forks a child into its OWN process group which reads the same tty.
// Whether that read stops on SIGTTIN depends on BOTH links: the open must
// acquire the ctty, and only then can `decide` see `is_ctty`. Testing
// `decide` alone hid the real defect — the pty slave never took link 1, so
// `is_ctty` was false and every background read on `/dev/pts/<n>` silently
// proceeded (i.e. blocked forever) instead of stopping.
// ---------------------------------------------------------------------------

const LEADER_PGID: u32 = 100;
const JOB_PGID: u32 = 101;

/// What a background `read(2)` of `kind` resolves to for a job started by a
/// session leader that opened the tty fresh. `o_noctty` is the leader's open
/// flag; the job inherits the leader's ctty across `fork`.
fn probe_background_read(kind: TtyKind, o_noctty: bool) -> Decision {
    let leader_acquired = should_acquire_ctty(
        kind_can_be_ctty(kind),
        o_noctty,
        /*is_session_leader*/ true,
        /*has_ctty*/ false,
        /*tty_has_session*/ false,
    );
    // Acquisition also seeds the tty's foreground pgrp with the leader's
    // (`tty_jobctrl.c` `__proc_set_tty`); an unacquired tty has none.
    let fg = if leader_acquired { LEADER_PGID } else { 0 };
    decide(leader_acquired, JOB_PGID, fg, false, Access::Read, false, false, false)
}

#[test]
fn a_backgrounded_read_of_a_pts_slave_stops_the_job() {
    assert_eq!(probe_background_read(TtyKind::PtySlave, false), Decision::Stop);
    assert_eq!(
        probe_background_read(TtyKind::PtySlave, false).vfs_err(),
        Some(vfs::VfsError::Erestartsys),
        "the stop must be restartable so the read re-runs after `fg` + SIGCONT");
}

#[test]
fn a_backgrounded_read_of_a_terminal_line_stops_the_job() {
    assert_eq!(probe_background_read(TtyKind::Terminal, false), Decision::Stop);
}

#[test]
fn a_pty_master_read_is_never_job_controlled() {
    // The master half is the shell's/emulator's end: it is nobody's ctty
    // (`tty_io.c:2166-2167`), so its reads always proceed.
    assert_eq!(probe_background_read(TtyKind::PtyMaster, false), Decision::Proceed);
}

#[test]
fn o_noctty_leaves_the_job_ungated_on_every_kind() {
    for kind in [TtyKind::Terminal, TtyKind::PtySlave, TtyKind::PtyMaster] {
        assert_eq!(probe_background_read(kind, true), Decision::Proceed, "{kind:?}");
    }
}
