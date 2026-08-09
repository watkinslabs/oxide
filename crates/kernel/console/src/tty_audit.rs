// What a console terminal reports to the input auditor.
//
// The serial line and every numbered VT answer the same way: they are real
// terminals, never the controlling half of a pty pair, and their canonical and
// echo state comes from the termios the line discipline is actually running.

use tty::pty::{lflag, read_lflag, TERMIOS_BYTES};

/// # C: O(1)
pub(crate) fn facts(rdev: u32, termios: &[u8; TERMIOS_BYTES]) -> vfs::TtyAuditFacts {
    let l = read_lflag(termios);
    let dev = vfs::Devt::from_raw(rdev);
    vfs::TtyAuditFacts {
        major: dev.major(),
        minor: dev.minor(),
        icanon: l & lflag::ICANON != 0,
        echo: l & lflag::ECHO != 0,
        pty_master: false,
    }
}
