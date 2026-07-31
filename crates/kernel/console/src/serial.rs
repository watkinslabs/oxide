use tty::ReadOutcome;
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use crate::routing::{foreground_vt, SERIAL_INO_LB, TTY_INO_BASE};

const SERIAL_CONSOLE_MODE: u16 = 0o660;

/// `/dev/ttyS0` inode number. # C: O(1)
fn serial_ino() -> Ino {
    TTY_INO_BASE | SERIAL_INO_LB as Ino
}

pub(crate) const fn serial_rdev() -> u32 {
    crate::devnum::serial_rdev()
}

pub(crate) fn session() -> u32 {
    crate::static_console::session()
}

pub(crate) fn set_session_and_fg(sid: u32, pgid: u32) {
    crate::static_console::set_session_and_fg(sid, pgid);
}

pub(crate) fn poll() -> u32 {
    crate::static_console::poll()
}

fn serial_jobctl(access: tty::jobctl::Access) -> KResult<()> {
    tty::jobctl::check(
        crate::static_console::foreground_pgid(),
        crate::static_console::session(),
        serial_ino(),
        tty::pty::read_lflag(&crate::static_console::termios_get()),
        access,
    )
}

pub(crate) fn serial_read(buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    serial_jobctl(tty::jobctl::Access::Read)?;
    match crate::static_console::read(buf) {
        ReadOutcome::Bytes(n) => Ok(n),
        ReadOutcome::Eof => Ok(0),
        ReadOutcome::Interrupted => Err(VfsError::Eintr),
    }
}

pub(crate) fn serial_read_nonblock(buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    serial_jobctl(tty::jobctl::Access::Read)?;
    let n = crate::static_console::read_nonblock(buf);
    if n == 0 {
        return Err(VfsError::Eagain);
    }
    Ok(n)
}

pub(crate) fn serial_write(buf: &[u8]) -> KResult<usize> {
    serial_jobctl(tty::jobctl::Access::Write)?;
    Ok(crate::static_console::write(buf))
}

struct SerialFileOps;

impl FileOps for SerialFileOps {
    fn on_open(&self, _i: &Inode) -> KResult<()> {
        crate::static_console::open()
    }

    fn on_release(&self, _i: &Inode) {
        crate::static_console::close();
    }

    fn read(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        serial_read(buf)
    }

    fn read_nonblock(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        serial_read_nonblock(buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, _i: &Inode) -> u32 {
        crate::static_console::poll()
    }

    /// `/dev/ttyS0`'s poll waiters belong on the serial `TtyStruct`'s own
    /// `read_wait` — the list `receive_from_driver` notifies on every UART RX
    /// byte. Resolved per call because the tty is installed after the inode is
    /// built. # C: O(1)
    fn poll_subscribers(&self, _file: &vfs::File) -> Option<alloc::sync::Arc<vfs::PollSubscribers>> {
        crate::static_console::poll_subscribers()
    }

    fn write(&self, _i: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        serial_write(buf)
    }
}

pub fn make_serial_inode() -> InodeRef {
    InodeBuilder::new(
        serial_ino(),
        mk_mode(FileType::CharDev, SERIAL_CONSOLE_MODE),
        default_inode_ops(),
        alloc::sync::Arc::new(SerialFileOps),
    )
    .fsid(devfs::DEVFS_FSID)
    .rdev(serial_rdev())
    .build()
}

/// Keyboard byte for the foreground VT. Staged rather than cooked inline —
/// this runs in the virtio-input SOFTIRQ, on the per-CPU hardirq stack; see
/// `crate::vt_input`.
/// # C: O(1)
pub fn kbd_input(b: u8) {
    crate::vt_input::stage(foreground_vt(), &[b]);
}

/// DSR/answerback reply from the VT emulator, injected into `vt`'s input.
/// Through the same staging ring as the keyboard, or a reply could overtake
/// the keystrokes that preceded it.
/// # C: O(len)
pub fn vt_reply_sink(vt: u8, bytes: &[u8]) {
    crate::vt_input::stage(vt.max(1), bytes);
}

pub fn system_console_inode() -> InodeRef {
    crate::vt_console::make_system_console_inode()
}
