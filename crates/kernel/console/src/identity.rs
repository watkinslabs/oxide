// Which tty a console char-device inode IS.
//
// Linux reaches `tty_ioctl` only through `tty_fops`, and the tty it acts on is
// `file->private_data` — a description that is not a tty has no
// `->unlocked_ioctl` at all, so `vfs_ioctl` answers ENOTTY. Nothing about the
// inode's NUMBER takes part.
//
// Oxide resolved the target with `ino & 0xFF`, and the fallback arm was
// `n => TtyTarget::Vt(n)`, which never declines. Because `handle_tty_ioctl` is
// the unclaimed-CharDev fallback of the ioctl dispatcher, that meant EVERY
// CharDev the earlier stages did not claim — a signalfd (`0x7200_0000`), an
// inotify fd, a timerfd, a bpf fd — got TCGETS/TIOCGWINSZ answered from a
// fabricated video VT derived from its low ino byte. Identity now comes from
// the `ConsoleData` the console node constructors install (`crate::nodes`),
// and [`binding_of`] returns `None` for everything else.

use vfs::Inode;

/// Which backing tty a console char-device resolves to right now.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TtyTarget {
    /// The serial UART tty (`static_console`).
    Serial,
    /// Video VT `n` (1-based) — `vt_tty(n)`.
    Vt(u8),
}

/// What a console char-device inode is bound to. Fixed at construction; the
/// two "follow whatever is current" bindings are resolved per call, which is
/// what keeps `/dev/tty0` correct across a VT switch and `/dev/console`
/// correct on a serial boot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TtyBinding {
    /// `/dev/ttyS0` — the serial UART line.
    Serial,
    /// `/dev/tty0` and the `/dev/tty` ctty alias — whichever VT is foreground.
    ForegroundVt,
    /// `/dev/tty<N>` — VT `N` specifically.
    Vt(u8),
    /// `/dev/console` — whichever line `cmdline::preferred_console()` selects.
    PreferredConsole,
}

/// Backend-private state (`i_private`) of a console tty inode. Only
/// `crate::nodes` mints one, so holding it is proof of console ownership.
pub struct ConsoleData {
    binding: TtyBinding,
}

impl ConsoleData {
    /// Bind an inode to `binding`. # C: O(1)
    pub(crate) const fn new(binding: TtyBinding) -> Self { Self { binding } }
    /// What this inode speaks for. # C: O(1)
    pub fn binding(&self) -> TtyBinding { self.binding }
    /// The VT this inode pins, in the `0 = foreground` form the VT file
    /// operations use. `None` when the inode is not a VT device. # C: O(1)
    pub(crate) fn vt(&self) -> Option<u8> {
        match self.binding {
            TtyBinding::ForegroundVt => Some(0),
            TtyBinding::Vt(n) => Some(n),
            TtyBinding::Serial | TtyBinding::PreferredConsole => None,
        }
    }
}

/// What `inode` is bound to, or `None` when it is not a console tty. # C: O(1)
pub fn binding_of(inode: &Inode) -> Option<TtyBinding> {
    inode.private::<ConsoleData>().map(|d| d.binding)
}

/// Whether `inode` is a console / serial / numbered-VT tty char-device.
/// # C: O(1)
pub fn is_console_tty(inode: &Inode) -> bool { binding_of(inode).is_some() }

#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
