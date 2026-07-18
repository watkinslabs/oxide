use alloc::string::ToString;
use alloc::sync::Arc;

use tty::ReadOutcome;
use vfs::{default_inode_ops, mk_mode, Dentry, FdTable, File, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError};

use crate::jobctl;
use crate::devnum;
use crate::routing::{foreground_vt, FG_VT_INO_LB, TTY_ALIAS_INO_LB, TTY_INO_BASE};
use crate::serial;
use crate::vt_tty;

/// Backend-private state (`i_private`) for a VT console inode: which VT it
/// pins. `vt == 0` = foreground video VT (`/dev/tty0`), resolved at I/O
/// time; `vt 1..=N_VT` pin a specific VT.
pub struct ConsoleData {
    pub(crate) vt: u8,
}

const CONSOLE_MODE: u16 = 0o666;
const VT_MODE: u16 = 0o620;
const SYSTEM_CONSOLE_MODE: u16 = 0o600;

/// Distinct inode numbers per VT so VFS-level introspection (`stat`/
/// `getdents` ino fields) reflects the underlying device. vt=0 = the
/// foreground-VT alias (low byte 0xFD); vt N = that VT (low byte N). # C: O(1)
pub(crate) fn console_ino(vt: u8) -> Ino {
    if vt == 0 {
        TTY_INO_BASE | FG_VT_INO_LB as Ino
    } else {
        TTY_INO_BASE | vt as Ino
    }
}

pub(crate) fn console_rdev(vt: u8) -> u32 { devnum::vt_rdev(vt) }

pub(crate) fn console_perm(vt: u8) -> u16 {
    if vt == 0 { CONSOLE_MODE } else { VT_MODE }
}

/// Build a VT console inode pinned to `vt`. Use 0 for `/dev/tty0`, the
/// foreground-VT device (Linux `4:0`); 1..=N_VT for the per-VT slots.
/// # C: O(1)
pub fn make_console_inode(vt: u8) -> InodeRef {
    make_vt_inode(vt, console_ino(vt), console_rdev(vt))
}

/// Build the `/dev/tty` controlling-terminal alias (Linux `5:0`).  It has a
/// distinct VFS identity from `/dev/tty0` so openat can apply the alias's
/// per-process `ctty` resolution without changing direct `/dev/tty0` opens.
/// # C: O(1)
pub fn make_tty_alias_inode() -> InodeRef {
    make_vt_inode(0, TTY_INO_BASE | TTY_ALIAS_INO_LB as Ino, devnum::tty_alias_rdev())
}

fn make_vt_inode(vt: u8, ino: Ino, rdev: u32) -> InodeRef {
    InodeBuilder::new(
        ino,
        mk_mode(FileType::CharDev, console_perm(vt)),
        default_inode_ops(),
        Arc::new(ConsoleFileOps),
    )
    .fsid(devfs::DEVFS_FSID)
    .rdev(rdev)
    .private(Arc::new(ConsoleData { vt }))
    .build()
}

/// Blocking read of VT `vt` (vt 0 → foreground VT). `ino` is the device's own
/// inode number (job-control gate). # C: backend-dependent
pub(crate) fn vt_read(vt: u8, ino: Ino, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        jobctl::Access::Read,
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
    jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        jobctl::Access::Read,
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
    jobctl::check(
        tty.fg_pgrp(),
        tty.sid(),
        ino,
        tty::pty::read_lflag(&tty.termios()),
        jobctl::Access::Write,
    )?;
    let n = tty.write(buf);
    dtrace!(b"CW_OUT", n as u64);
    Ok(n)
}

struct ConsoleFileOps;

impl FileOps for ConsoleFileOps {
    fn on_open_file(&self, file: &File) -> KResult<()> {
        let vt = console_data(file.inode())?.vt;
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
        let vt = console_data(inode)?.vt;
        vt_read(vt, inode.ino(), buf)
    }

    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let vt = console_data(inode)?.vt;
        vt_read_nonblock(vt, inode.ino(), buf)
    }

    fn poll(&self, inode: &Inode) -> u32 {
        match console_data(inode) {
            Ok(d) => vt_poll(d.vt),
            Err(_) => vfs::POLL_ERR,
        }
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let vt = console_data(inode)?.vt;
        vt_write(vt, inode.ino(), buf)
    }
}

fn console_data(inode: &Inode) -> KResult<&ConsoleData> {
    inode.private::<ConsoleData>().ok_or(VfsError::Einval)
}

struct SystemConsoleFileOps;

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

    fn poll(&self, _i: &Inode) -> u32 {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial::poll(),
            cmdline::ConsoleKind::Vt(_) => vt_poll(0),
        }
    }
}

/// Build the `/dev/console` (preferred-console, 5:1) inode. # C: O(1)
pub fn make_system_console_inode() -> InodeRef {
    InodeBuilder::new(
        TTY_INO_BASE | crate::routing::SYSTEM_CONSOLE_INO_LB as Ino,
        mk_mode(FileType::CharDev, SYSTEM_CONSOLE_MODE),
        default_inode_ops(),
        Arc::new(SystemConsoleFileOps),
    )
    .fsid(devfs::DEVFS_FSID)
    .rdev(devnum::system_console_rdev())
    .build()
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
