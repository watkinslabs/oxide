// Controlling-terminal hangup — Linux `__tty_hangup`
// (`drivers/tty/tty_io.c:568-656`), `tty_signal_session_leader`
// (`drivers/tty/tty_jobctrl.c:196-238`) and `SYSCALL_DEFINE0(vhangup)`
// (`fs/open.c:1530-1537`).
//
// `vhangup(2)` is a security boundary, not a convenience: `login`/`agetty`
// call it between sessions so nothing the PREVIOUS session left behind can
// still read from or write to the line. Two things make that true, and both
// are easy to omit — the tty must be REVOKED (every other opener's reads
// become EOF and writes EIO) and every session member must LOSE the tty as
// its controlling terminal. Posting SIGHUP and calling it done leaves any
// process that ignores SIGHUP holding a live handle on the next user's
// terminal.
//
// Module manifest:
// - `decide`:      pure per-task rule + the syscall's own admission ladder.
// - `disassociate`: pure `disassociate_ctty` ladder — a session leader's exit
//                  and TIOCNOTTY.
// - `live`:        the session walk + pgrp signalling (needs `sched::live`),
//                  kernel-gated.
// - `tests`:       hosted tests for the decide/vhangup halves.

mod decide;
pub use decide::{session_member_action, vhangup_decision, HangupKind, SessionMemberAction,
    VhangupOutcome};

pub mod disassociate;
pub use disassociate::{disassociate_ctty, CttyFacts, DisassociateActions, DisassociateCause,
    PgrpSignal};

#[cfg(target_os = "oxide-kernel")]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub use live::{clear_session_ctty, hangup_session, signal_pgrp};

#[cfg(test)]
mod tests;
