use alloc::string::ToString;
use alloc::sync::Arc;

use tty::ReadOutcome;
use vfs::{Dentry, FdTable, File, FileOps, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};

use crate::devnum;
use crate::ids;
use crate::identity::ConsoleData;
use crate::routing::foreground_vt;
use crate::serial;
use crate::vt_tty;

/// Device number of the VT device pinned to `vt`. # C: O(1)
pub(crate) fn console_rdev(vt: u8) -> u32 { devnum::vt_rdev(vt) }

/// `st_ino` of the VT device pinned to `vt`. # C: O(1)
pub(crate) fn console_ino(vt: u8) -> Ino { ids::vt_ino(vt) }

/// Blocking read of VT `vt` (vt 0 → foreground VT). `ino` is the device's own
/// inode number (job-control gate). # C: backend-dependent
pub(crate) fn vt_read(vt: u8, ino: Ino, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    tty::jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        tty::jobctl::Access::Read,
    )?;
    match tty.read(buf) {
        ReadOutcome::Bytes(n) => Ok(n),
        ReadOutcome::Eof => Ok(0),
        ReadOutcome::Interrupted => Err(VfsError::Eintr),
    }
}

/// Non-blocking read of VT `vt` (empty ⇒ `Eagain`). # C: O(buf.len())
pub(crate) fn vt_read_nonblock(vt: u8, ino: Ino, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    tty::jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        tty::jobctl::Access::Read,
    )?;
    let n = tty.read_nonblock(buf);
    if n == 0 {
        return Err(VfsError::Eagain);
    }
    Ok(n)
}

/// Readiness for poll/ppoll/select on VT `vt`. POLLIN only when input is
/// actually queued; always writable. # C: O(1)
pub(crate) fn vt_poll(vt: u8) -> u32 {
    let v = if vt == 0 { foreground_vt() } else { vt };
    vt_tty::vt_tty(v).poll()
}

/// Write `buf` to VT `vt`. The per-VT `TtyStruct` owns OPOST (ONLCR), then
/// `VtConsoleDriver::write` feeds the post-OPOST bytes to the fbcon emulator.
/// Does NOT touch the serial UART. # C: backend-dependent
pub(crate) fn vt_write(vt: u8, ino: Ino, buf: &[u8]) -> KResult<usize> {
    dtrace!(b"CW_IN", buf.len() as u64);
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    tty::jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        tty::jobctl::Access::Write,
    )?;
    let n = tty.write(buf);
    dtrace!(b"CW_OUT", n as u64);
    Ok(n)
}

pub(crate) struct ConsoleFileOps;

impl FileOps for ConsoleFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let vt = console_vt(file.inode())?;
        let v = if vt == 0 { foreground_vt() } else { vt };
        let cap = sched::current().map(|t| t.has_cap(sched::cap::SYS_ADMIN)).unwrap_or(false);
        vt_tty::vt_tty(v).open_with_cap_sys_admin(cap)?;
        file.set_private_data(v as u64);
        Ok(())
    }

    fn on_release_file(&self, file: &File) {
        let v = file.private_data() as u8;
        if v == 0 { return; }
        vt_tty::vt_tty(v).close();
    }

    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let vt = console_vt(inode)?;
        vt_read(vt, inode.ino(), buf)
    }

    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let vt = console_vt(inode)?;
        vt_read_nonblock(vt, inode.ino(), buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, inode: &Inode) -> u32 {
        match console_vt(inode) {
            Ok(vt) => vt_poll(vt),
            Err(_) => vfs::POLL_ERR,
        }
    }

    /// Linux `n_tty_poll` registers the caller on `tty->read_wait`; the tty a
    /// VT node speaks for is resolved the same way `poll`/`read` resolve it
    /// (`vt == 0` = whichever VT is foreground right now), so the waiter joins
    /// the queue the RX path actually notifies. Resolving here rather than
    /// stamping `poll_subs` on the inode is what keeps `/dev/tty0` correct
    /// across a VT switch — one list, owned by the tty. # C: O(1)
    fn poll_subscribers(&self, file: &File) -> Option<Arc<vfs::PollSubscribers>> {
        let vt = console_vt(file.inode()).ok()?;
        Some(vt_tty::vt_tty(if vt == 0 { foreground_vt() } else { vt }).poll_subs_arc())
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let vt = console_vt(inode)?;
        vt_write(vt, inode.ino(), buf)
    }
}

/// The VT a `ConsoleFileOps` inode pins, in the `0 = foreground` form. These
/// operations are only ever installed on a VT device, so anything else means
/// the inode was built outside `crate::nodes`. # C: O(1)
fn console_vt(inode: &Inode) -> KResult<u8> {
    inode.private::<ConsoleData>().and_then(|d| d.vt()).ok_or(VfsError::Einval)
}

pub(crate) struct SystemConsoleFileOps;

impl FileOps for SystemConsoleFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => {
                crate::static_console::open()?;
                file.set_private_data(0);
                Ok(())
            }
            cmdline::ConsoleKind::Vt(_) => {
                let vt = foreground_vt();
                let cap = sched::current().map(|t| t.has_cap(sched::cap::SYS_ADMIN)).unwrap_or(false);
                vt_tty::vt_tty(vt).open_with_cap_sys_admin(cap)?;
                file.set_private_data(vt as u64);
                Ok(())
            }
        }
    }

    fn on_release_file(&self, file: &File) {
        let v = file.private_data() as u8;
        if v == 0 { crate::static_console::close(); }
        else { vt_tty::vt_tty(v).close(); }
    }

    fn read(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::serial_read(buf),
            cmdline::ConsoleKind::Vt(_) => vt_read(0, console_ino(0), buf),
        }
    }

    fn read_nonblock(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::serial_read_nonblock(buf),
            cmdline::ConsoleKind::Vt(_) => vt_read_nonblock(0, console_ino(0), buf),
        }
    }

    fn write(&self, _i: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::serial_write(buf),
            cmdline::ConsoleKind::Vt(_) => vt_write(0, console_ino(0), buf),
        }
    }

    fn write_nonblock(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(inode, off, buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, _i: &Inode) -> u32 {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::poll(),
            cmdline::ConsoleKind::Vt(_) => vt_poll(0),
        }
    }

    /// `/dev/console` forwards to whichever tty `preferred_console()` selects,
    /// so its poll waiters must land on THAT tty's `read_wait` — the same
    /// resolution `poll`/`read` use, evaluated per call because the serial tty
    /// does not exist until `static_console::install`. # C: O(1)
    fn poll_subscribers(&self, _file: &File) -> Option<Arc<vfs::PollSubscribers>> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => crate::static_console::poll_subscribers(),
            cmdline::ConsoleKind::Vt(_) => Some(vt_tty::vt_tty(foreground_vt()).poll_subs_arc()),
        }
    }
}

/// Build the `init`-process fd table with fd 0/1/2 all pointing at
/// `/dev/console`.
pub fn init_console_fd_table() -> Arc<FdTable> {
    let table = Arc::new(FdTable::new());
    let inode: InodeRef = crate::system_console_inode();
    let dentry = Dentry::new(None, "/dev/console".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    let _fd0 = table.alloc(file.clone());
    let _fd1 = table.alloc(file.clone());
    let _fd2 = table.alloc(file);
    table
}
