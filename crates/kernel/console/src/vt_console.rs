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

/// The `TtyStruct` a VT node speaks for (`vt == 0` = whichever VT is
/// foreground right now). # C: O(1)
fn tty_of(vt: u8) -> &'static vt_tty::VtTty {
    vt_tty::vt_tty(if vt == 0 { foreground_vt() } else { vt })
}

/// POSIX job-control gate for a VT access. Skipped entirely for a revoked
/// description: `hung_up_tty_fops` has no `job_control` step — a descriptor
/// the hangup retired gets EOF/EIO, never SIGTTIN/SIGTTOU. # C: O(1)
fn vt_jobctl(tty: &vt_tty::VtTty, ino: Ino, access: tty::jobctl::Access) -> KResult<()> {
    tty::jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        access,
    )
}

/// Blocking read of VT `vt` (vt 0 → foreground VT) for the description that
/// sampled hangup generation `gen`. `ino` is the device's own inode number
/// (job-control gate). # C: backend-dependent
pub(crate) fn vt_read(vt: u8, ino: Ino, gen: u64, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let tty = tty_of(vt);
    if !tty.hung_up_open(gen) { vt_jobctl(tty, ino, tty::jobctl::Access::Read)?; }
    match tty.read_open(gen, buf) {
        ReadOutcome::Bytes(n) => Ok(n),
        ReadOutcome::Eof => Ok(0),
        ReadOutcome::Interrupted => Err(VfsError::Eintr),
    }
}

/// Non-blocking read of VT `vt` (empty ⇒ `Eagain`; revoked ⇒ EOF).
/// # C: O(buf.len())
pub(crate) fn vt_read_nonblock(vt: u8, ino: Ino, gen: u64, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let tty = tty_of(vt);
    if !tty.hung_up_open(gen) { vt_jobctl(tty, ino, tty::jobctl::Access::Read)?; }
    tty.read_nonblock_open(gen, buf)
}

/// Readiness for poll/ppoll/select on VT `vt`. POLLIN only when input is
/// actually queued; always writable. A revoked description reports the full
/// `hung_up_tty_poll` mask. # C: O(1)
pub(crate) fn vt_poll(vt: u8, gen: u64) -> u32 {
    tty_of(vt).poll_open(gen)
}

/// Write `buf` to VT `vt`. The per-VT `TtyStruct` owns OPOST (ONLCR), then
/// `VtConsoleDriver::write` feeds the post-OPOST bytes to the fbcon emulator.
/// Does NOT touch the serial UART. # C: backend-dependent
pub(crate) fn vt_write(vt: u8, ino: Ino, gen: u64, buf: &[u8]) -> KResult<usize> {
    dtrace!(b"CW_IN", buf.len() as u64);
    let tty = tty_of(vt);
    if !tty.hung_up_open(gen) { vt_jobctl(tty, ino, tty::jobctl::Access::Write)?; }
    let n = tty.write_open(gen, buf)?;
    dtrace!(b"CW_OUT", n as u64);
    Ok(n)
}

/// The VT a description was OPENED on. `on_open_file` resolved `/dev/tty0`'s
/// `0 = foreground` once and took the open reference on that concrete tty, so
/// the revocation check and the release must name the same one. `0` = this
/// description never passed the open hook (the boot fd table). # C: O(1)
fn file_vt(file: &File) -> u8 { file.private_data() as u8 }

pub(crate) struct ConsoleFileOps;

impl FileOps for ConsoleFileOps {
    fn tty_audit_facts(&self, file: &File) -> Option<vfs::TtyAuditFacts> {
        let v = file_vt(file);
        let v = if v == 0 { foreground_vt() } else { v };
        Some(crate::tty_audit::facts(crate::devnum::vt_rdev(v), &vt_tty::vt_tty(v).termios()))
    }

    fn on_open_file(&self, file: &File) -> KResult<()> {
        let vt = console_vt(file.inode())?;
        let v = if vt == 0 { foreground_vt() } else { vt };
        let cap = sched::current().map(|t| t.has_cap(sched::cap::SYS_ADMIN)).unwrap_or(false);
        let gen = vt_tty::vt_tty(v).open_revocable(cap)?;
        file.set_private_data(v as u64);
        // Bind this description to the generation the open observed; a later
        // hangup retires it permanently (`tty::hangup::revoke`).
        file.set_revoke_gen(gen);
        Ok(())
    }

    fn on_release_file(&self, file: &File) {
        let v = file_vt(file);
        if v == 0 { return; }
        vt_tty::vt_tty(v).close();
    }

    fn read_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        vt_read(file_vt(file), file.inode().ino(), file.revoke_gen(), buf)
    }

    fn read_nonblock_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        vt_read_nonblock(file_vt(file), file.inode().ino(), file.revoke_gen(), buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_open_file(&self, file: &File) -> u32 {
        vt_poll(file_vt(file), file.revoke_gen())
    }

    /// Linux `n_tty_poll` registers the caller on `tty->read_wait`; the tty a
    /// VT node speaks for is resolved the same way `poll`/`read` resolve it
    /// (`vt == 0` = whichever VT is foreground right now), so the waiter joins
    /// the queue the RX path actually notifies. Resolving here rather than
    /// stamping `poll_subs` on the inode is what keeps `/dev/tty0` correct
    /// across a VT switch — one list, owned by the tty. # C: O(1)
    fn poll_subscribers(&self, file: &File) -> Option<Arc<vfs::PollSubscribers>> {
        let v = file_vt(file);
        let v = if v == 0 { console_vt(file.inode()).ok()? } else { v };
        Some(vt_tty::vt_tty(if v == 0 { foreground_vt() } else { v }).poll_subs_arc())
    }

    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        vt_write(file_vt(file), file.inode().ino(), file.revoke_gen(), buf)
    }

    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_file(file, off, buf)
    }
}

/// The VT a `ConsoleFileOps` inode pins, in the `0 = foreground` form. These
/// operations are only ever installed on a VT device, so anything else means
/// the inode was built outside `crate::nodes`. # C: O(1)
fn console_vt(inode: &Inode) -> KResult<u8> {
    inode.private::<ConsoleData>().and_then(|d| d.vt()).ok_or(VfsError::Einval)
}

/// The VT a `/dev/console` description was opened on under the VT backend
/// (`on_open_file` resolved the foreground VT once and took the reference on
/// it). `0` = never passed the open hook — the boot fd table — which resolves
/// to the current foreground VT, as before. # C: O(1)
fn sys_console_vt(file: &File) -> u8 { file.private_data() as u8 }

pub(crate) struct SystemConsoleFileOps;

impl FileOps for SystemConsoleFileOps {
    /// `/dev/console` speaks for whichever backend the command line selected,
    /// so the facts come from the tty it is actually bound to.
    fn tty_audit_facts(&self, file: &File) -> Option<vfs::TtyAuditFacts> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial =>
                Some(crate::tty_audit::facts(crate::devnum::serial_rdev(),
                                             &crate::static_console::termios_get())),
            cmdline::ConsoleKind::Vt(_) => {
                let v = sys_console_vt(file);
                let v = if v == 0 { foreground_vt() } else { v };
                Some(crate::tty_audit::facts(crate::devnum::vt_rdev(v),
                                             &vt_tty::vt_tty(v).termios()))
            }
        }
    }

    fn on_open_file(&self, file: &File) -> KResult<()> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => {
                let gen = crate::static_console::open_revocable()?;
                file.set_private_data(0);
                file.set_revoke_gen(gen);
                Ok(())
            }
            cmdline::ConsoleKind::Vt(_) => {
                let vt = foreground_vt();
                let cap = sched::current().map(|t| t.has_cap(sched::cap::SYS_ADMIN)).unwrap_or(false);
                let gen = vt_tty::vt_tty(vt).open_revocable(cap)?;
                file.set_private_data(vt as u64);
                // Bind this description to the generation the open observed; a
                // later hangup retires it permanently (`tty::hangup::revoke`).
                file.set_revoke_gen(gen);
                Ok(())
            }
        }
    }

    fn on_release_file(&self, file: &File) {
        let v = file.private_data() as u8;
        if v == 0 { crate::static_console::close(); }
        else { vt_tty::vt_tty(v).close(); }
    }

    fn read_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let gen = file.revoke_gen();
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::serial_read(gen, buf),
            cmdline::ConsoleKind::Vt(_) => vt_read(sys_console_vt(file), console_ino(0), gen, buf),
        }
    }

    fn read_nonblock_file(&self, file: &File, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let gen = file.revoke_gen();
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::serial_read_nonblock(gen, buf),
            cmdline::ConsoleKind::Vt(_) => vt_read_nonblock(sys_console_vt(file), console_ino(0), gen, buf),
        }
    }

    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        let gen = file.revoke_gen();
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::serial_write(gen, buf),
            cmdline::ConsoleKind::Vt(_) => vt_write(sys_console_vt(file), console_ino(0), gen, buf),
        }
    }

    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_file(file, off, buf)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll_open_file(&self, file: &File) -> u32 {
        let gen = file.revoke_gen();
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::poll(gen),
            cmdline::ConsoleKind::Vt(_) => vt_poll(sys_console_vt(file), gen),
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
