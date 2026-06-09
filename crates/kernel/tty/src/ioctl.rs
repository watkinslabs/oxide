// Core TTY ioctls — the device-class-agnostic TIOC* / TCGETS surface
// (`drivers/tty/tty_io.c:tty_ioctl`). The syscall layer (T8) hands the
// request number + a pointer-as-u64 and is responsible for user-buffer
// copy in/out; this module operates on the `TtyStruct` state and the
// already-fetched / to-be-stored bytes via the `IoctlArg` accessor so it
// stays host-testable (no userspace pointer deref here).
//
// Typed request constants (no bare magic numbers per 07§5) — the same
// Linux `_IO*` values the syscall ioctl dispatcher (`016_ioctl.rs`) uses.

use crate::core::{TtyDriver, TtyStruct};
use crate::pty::{Winsize, TERMIOS_BYTES};
use crate::wait::TtyWait;

/// Linux tty ioctl request numbers (`include/uapi/asm-generic/ioctls.h`).
pub mod req {
    /// Get termios (`struct termios`).
    pub const TCGETS: u32 = 0x5401;
    /// Set termios now.
    pub const TCSETS: u32 = 0x5402;
    /// Set termios after output drains (== TCSETS for us — no TX queue).
    pub const TCSETSW: u32 = 0x5403;
    /// Set termios + flush input (== TCSETS for us).
    pub const TCSETSF: u32 = 0x5404;
    /// Get window size (`struct winsize`).
    pub const TIOCGWINSZ: u32 = 0x5413;
    /// Set window size.
    pub const TIOCSWINSZ: u32 = 0x5414;
    /// Get foreground pgrp.
    pub const TIOCGPGRP: u32 = 0x540F;
    /// Set foreground pgrp.
    pub const TIOCSPGRP: u32 = 0x5410;
    /// Make this the controlling tty.
    pub const TIOCSCTTY: u32 = 0x540E;
    /// Give up the controlling tty.
    pub const TIOCNOTTY: u32 = 0x5422;
    /// Get controlling session id.
    pub const TIOCGSID: u32 = 0x5429;
}

/// Outcome of a core ioctl: the syscall layer turns this into a return
/// value and (for the GET variants) a user-buffer store. Keeping the
/// produced bytes in the enum keeps the core logic host-testable without
/// a userspace pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoctlOut {
    /// Success, nothing to copy back (the SET variants).
    Ok,
    /// Success; copy these `TERMIOS_BYTES` back to the user (TCGETS).
    Termios([u8; TERMIOS_BYTES]),
    /// Success; copy this winsize (8 bytes LE) back (TIOCGWINSZ).
    Winsize(Winsize),
    /// Success; copy this `u32` (pgrp / sid) back (TIOCGPGRP/TIOCGSID).
    U32(u32),
}

/// Core tty ioctl. `arg_u32` carries the integer argument the SET
/// variants need already fetched from userspace (pgrp for TIOCSPGRP, sid
/// for TIOCSCTTY); `termios_in` / `winsize_in` carry the structures for
/// TCSETS* / TIOCSWINSZ. Returns `None` if `cmd` is not a core tty ioctl
/// (caller returns ENOTTY); `Some(IoctlOut)` otherwise.
///
/// Returns the data-bearing `IoctlOut` so the syscall layer can copy it
/// back; this is the host-testable core. The thin syscall wrapper
/// (`core_ioctl`) below adapts to the pointer-based path.
/// # C: O(1)
pub fn core_ioctl_decoded<D: TtyDriver, W: TtyWait>(
    tty: &TtyStruct<D, W>,
    cmd: u32,
    arg_u32: u32,
    termios_in: Option<&[u8; TERMIOS_BYTES]>,
    winsize_in: Option<Winsize>,
) -> Option<(IoctlOut, bool)> {
    // The bool is "winsize changed" for TIOCSWINSZ so the caller raises
    // SIGWINCH; false for everything else.
    match cmd {
        req::TCGETS => Some((IoctlOut::Termios(tty.termios()), false)),
        req::TCSETS | req::TCSETSW | req::TCSETSF => {
            if let Some(t) = termios_in {
                tty.set_termios(t);
            }
            Some((IoctlOut::Ok, false))
        }
        req::TIOCGWINSZ => Some((IoctlOut::Winsize(tty.winsize()), false)),
        req::TIOCSWINSZ => {
            let changed = match winsize_in {
                Some(ws) => tty.set_winsize(ws),
                None => false,
            };
            Some((IoctlOut::Ok, changed))
        }
        req::TIOCGPGRP => Some((IoctlOut::U32(tty.fg_pgrp()), false)),
        req::TIOCSPGRP => {
            tty.set_fg_pgrp(arg_u32);
            Some((IoctlOut::Ok, false))
        }
        req::TIOCSCTTY => {
            tty.set_ctty(arg_u32);
            Some((IoctlOut::Ok, false))
        }
        req::TIOCNOTTY => {
            tty.notty();
            Some((IoctlOut::Ok, false))
        }
        req::TIOCGSID => Some((IoctlOut::U32(tty.sid()), false)),
        _ => None,
    }
}

/// Pointer-based adapter used by `TtyStruct::ioctl` for the kernel
/// syscall path. The syscall layer (T8) will instead call
/// `core_ioctl_decoded` after doing its own validated user-buffer copies;
/// this stub exists so `TtyStruct::ioctl` compiles as a self-contained
/// unit. It does not deref userspace here (additive, T8 wires the real
/// copy-in/out), so it only handles the no-argument query/release forms
/// and reports the rest as "needs the syscall-layer copy path" by
/// returning `None` (→ caller falls back / ENOTTY until T8).
/// # C: O(1)
pub fn core_ioctl<D: TtyDriver, W: TtyWait>(
    tty: &TtyStruct<D, W>,
    cmd: u32,
    _arg: u64,
) -> Option<i64> {
    match cmd {
        // No-copy releases / queries with an in-register result are safe
        // to answer here; the rest defer to T8's copy-in/out wiring.
        req::TIOCNOTTY => {
            tty.notty();
            Some(0)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests;
