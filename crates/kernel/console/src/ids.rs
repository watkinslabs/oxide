//! Console device inode NUMBERS, drawn from the pseudo-inode registry
//! (`vfs::pseudo_ino`).
//!
//! A number here is a `st_ino` value, never an identity test — which tty a
//! console char-device inode speaks for comes from the `ConsoleData` in its
//! `i_private` (`crate::identity`). Deriving it from `ino & 0xFF` claimed every
//! CharDev in the kernel: a signalfd (`0x7200_0000`), a timerfd or a bpf fd
//! decoded as "video VT <low byte>".

use vfs::pseudo_ino::{CONSOLE_TTY, CONSOLE_VCS, CONSOLE_VCSA};
use vfs::Ino;

/// Console char-device ino base; the low byte selects the device.
pub const TTY_INO_BASE: Ino = CONSOLE_TTY.start();
/// Low-byte selector for the serial tty (`/dev/ttyS0`).
pub const SERIAL_INO_LB: u8 = 0xFE;
/// Low-byte selector for `/dev/tty0`, the foreground-video-VT device.
pub const FG_VT_INO_LB: u8 = 0xFD;
/// Low-byte selector for the `/dev/tty` controlling-terminal alias. Distinct
/// from `/dev/tty0`: both follow the foreground VT for I/O, but only this one
/// has Linux device number 5:0 and open-time ctty semantics.
pub const TTY_ALIAS_INO_LB: u8 = 0xFC;
/// Low-byte selector for `/dev/console`, the preferred-console device. It used
/// to be `0x01`, which is `/dev/tty1`'s selector — the two devices reported
/// the SAME `st_ino` on the SAME `st_dev`, so nothing keyed on inode identity
/// (inotify marks, `tty_hangup`'s per-inode session clear) could tell them
/// apart.
pub const SYSTEM_CONSOLE_INO_LB: u8 = 0xFB;

/// Highest numbered VT device (`/dev/tty1`..`/dev/tty63`). Above it the low
/// byte is a named selector, not a VT.
pub const MAX_VT_INO_LB: u8 = 63;

/// `/dev/vcs*` — the text-only screen dump.
pub(crate) const VCS_INO: Ino = CONSOLE_VCS.start();
/// `/dev/vcsa*` — the text+attribute screen dump.
pub(crate) const VCSA_INO: Ino = CONSOLE_VCSA.start();

/// `st_ino` of the console char-device with low-byte selector `lb`. # C: O(1)
pub(crate) const fn tty_ino(lb: u8) -> Ino { TTY_INO_BASE | lb as Ino }

/// `st_ino` of the VT device pinned to `vt`; `0` is `/dev/tty0`, the
/// foreground-VT alias. # C: O(1)
pub(crate) const fn vt_ino(vt: u8) -> Ino {
    if vt == 0 { tty_ino(FG_VT_INO_LB) } else { tty_ino(vt) }
}

/// Whether `ino` is in the console tty band. A NUMBERING question — ownership
/// is [`crate::identity::is_console_tty`]'s. # C: O(1)
pub(crate) const fn is_tty_band(ino: Ino) -> bool { CONSOLE_TTY.contains(ino) }

const _: () = assert!(is_tty_band(tty_ino(SERIAL_INO_LB)), "serial ino escapes CONSOLE_TTY");
const _: () = assert!(is_tty_band(vt_ino(MAX_VT_INO_LB)), "top VT ino escapes CONSOLE_TTY");
// The four named selectors must not collide with each other or with a VT.
const _: () = assert!(SYSTEM_CONSOLE_INO_LB > MAX_VT_INO_LB, "/dev/console aliases a VT");
const _: () = assert!(TTY_ALIAS_INO_LB > MAX_VT_INO_LB, "/dev/tty aliases a VT");
const _: () = assert!(FG_VT_INO_LB > MAX_VT_INO_LB, "/dev/tty0 aliases a VT");
const _: () = assert!(SERIAL_INO_LB > MAX_VT_INO_LB, "/dev/ttyS0 aliases a VT");
const _: () = assert!(SYSTEM_CONSOLE_INO_LB != TTY_ALIAS_INO_LB
    && SYSTEM_CONSOLE_INO_LB != FG_VT_INO_LB && SYSTEM_CONSOLE_INO_LB != SERIAL_INO_LB
    && TTY_ALIAS_INO_LB != FG_VT_INO_LB && TTY_ALIAS_INO_LB != SERIAL_INO_LB
    && FG_VT_INO_LB != SERIAL_INO_LB, "two console devices share one selector");
