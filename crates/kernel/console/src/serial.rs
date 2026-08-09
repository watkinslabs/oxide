use tty::ReadOutcome;
use vfs::{File, FileOps, Ino, Inode, InodeRef, KResult, VfsError};

use crate::ids;
use crate::routing::foreground_vt;

/// `/dev/ttyS0` inode number. # C: O(1)
fn serial_ino() -> Ino {
    ids::tty_ino(ids::SERIAL_INO_LB)
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

pub(crate) fn poll(gen: u64) -> u32 {
    crate::static_console::poll_open(gen)
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

/// Blocking read for the description that sampled hangup generation `gen`.
/// A revoked one reads EOF without the job-control gate — `hung_up_tty_fops`
/// has no `job_control` step. # C: backend-dependent
pub(crate) fn serial_read(gen: u64, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    if crate::static_console::hung_up_open(gen) { return Ok(tty::hangup::revoke::HUNG_UP_READ); }
    serial_jobctl(tty::jobctl::Access::Read)?;
    match crate::static_console::read(buf) {
        ReadOutcome::Bytes(n) => Ok(n),
        ReadOutcome::Eof => Ok(0),
        ReadOutcome::Interrupted => Err(VfsError::Eintr),
    }
}

/// Non-blocking read; empty ⇒ `Eagain`, revoked ⇒ EOF. # C: O(buf.len())
pub(crate) fn serial_read_nonblock(gen: u64, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    if crate::static_console::hung_up_open(gen) { return Ok(tty::hangup::revoke::HUNG_UP_READ); }
    serial_jobctl(tty::jobctl::Access::Read)?;
    let n = crate::static_console::read_nonblock(buf);
    if n == 0 {
        return Err(VfsError::Eagain);
    }
    Ok(n)
}

/// Write; `EIO` once the description has been revoked. # C: backend-dependent
pub(crate) fn serial_write(gen: u64, buf: &[u8]) -> KResult<usize> {
    if crate::static_console::hung_up_open(gen) { return Err(VfsError::Eio); }
    serial_jobctl(tty::jobctl::Access::Write)?;
    Ok(crate::static_console::write(buf))
}

pub(crate) struct SerialFileOps;

impl FileOps for SerialFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        // Bind this description to the generation the open observed; a later
        // hangup retires it permanently (`tty::hangup::revoke`).
        file.set_revoke_gen(crate::static_console::open_revocable()?);
        Ok(())
    }

    fn on_release(&self, _i: &Inode) {
        crate::static_console::close();
    }

    fn read_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        serial_read(file.revoke_gen(), buf)
    }

    fn read_nonblock_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        serial_read_nonblock(file.revoke_gen(), buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_open_file(&self, file: &File) -> u32 {
        crate::static_console::poll_open(file.revoke_gen())
    }

    /// `/dev/ttyS0`'s poll waiters belong on the serial `TtyStruct`'s own
    /// `read_wait` — the list `receive_from_driver` notifies on every UART RX
    /// byte. Resolved per call because the tty is installed after the inode is
    /// built. # C: O(1)
    fn poll_subscribers(&self, _file: &vfs::File) -> Option<alloc::sync::Arc<vfs::PollSubscribers>> {
        crate::static_console::poll_subscribers()
    }

    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        serial_write(file.revoke_gen(), buf)
    }

    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_file(file, off, buf)
    }
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
    crate::nodes::make_system_console_inode()
}
