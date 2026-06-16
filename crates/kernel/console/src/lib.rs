#![cfg(target_os = "oxide-kernel")]  // kernel-only crate (uses static_console/sched::live)
#![no_std]
#[macro_use] extern crate kmacros;
extern crate alloc;

// `/dev/console` + `/dev/tty<N>` char-devices per docs/16 + docs/28.
//
// T7 core cutover (tty-rebuild-plan §3-T7): `/dev/console`, `/dev/tty`,
// `/dev/tty0`, `/dev/ttyS0` (the serial login path) all delegate to ONE
// global serial `TtyStruct` (`static_console`) built on the new tty
// stack — N_TTY ldisc + lost-wakeup-free `TtyStruct::read` + N_TTY OPOST
// → UART write. This replaces the old input-only `tty::live` VT-ring and
// the racy `ConsoleInode::read` park loop (the intermittent login race).
// The `/dev/tty1`..N per-VT nodes still carry their own VT id for the
// (inert until kbd VT-switch) multi-VT screen buffers.
//
// printk stays SEPARATE: kernel logs reach the UART via klog's serial
// sink (and mirror to fbcon); a tty write here goes TtyStruct → UART, NOT
// into the kmsg ring — the dmesg/shell-output split.
//
// init's fd 0/1/2 install a vt=0 (system console) ConsoleInode.

pub mod jobctl;
pub mod static_console;
pub mod vt_tty;

use alloc::string::ToString;
use alloc::sync::Arc;

use tty::ReadOutcome;
use vfs::{Dentry, FdTable, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};

// --- device routing (Linux serial-vs-VT split) -------------------------
//
// Linux keeps the serial line and the video VTs as SEPARATE tty devices —
// they are NOT one console mirrored to two sinks. The char-device inode's
// low byte selects the backing tty:
//   0xFE  → the serial tty (`/dev/ttyS0`) — serial UART only.
//   0xFD  → the FOREGROUND video VT (`/dev/console`,`/dev/tty`,`/dev/tty0`).
//   1..63 → that numbered VT (`/dev/ttyN`).
// High bits 0x7400 keep these clear of the pty (0x6000_0000), vcs
// (0x7600/0x7700), fbdev (0xFB00) and pidfd (0xFF00_0000) ino ranges.

/// Console char-device ino base (low byte = device selector).
pub const TTY_INO_BASE: Ino = 0x7400;
/// Low-byte selector for the serial tty (`/dev/ttyS0`).
pub const SERIAL_INO_LB: u8 = 0xFE;
/// Low-byte selector for the foreground video VT (`/dev/console`/tty0).
pub const FG_VT_INO_LB: u8 = 0xFD;

/// Which backing tty a console char-device ino maps to.
pub enum TtyTarget {
    /// The serial UART tty (`static_console`).
    Serial,
    /// Video VT `n` (1-based) — `vt_tty(n)`.
    Vt(u8),
}

/// Resolve a console char-device ino to its backing tty (the Linux device
/// split). `0xFE` → serial; `0xFD` → foreground video VT; `1..63` → VT n.
/// # C: O(1)
pub fn route(ino: u64) -> TtyTarget {
    match (ino & 0xff) as u8 {
        SERIAL_INO_LB => TtyTarget::Serial,
        FG_VT_INO_LB  => TtyTarget::Vt(tty::live::foreground().max(1)),
        n             => TtyTarget::Vt(n),
    }
}

/// The current foreground video VT (1-based). `/dev/console` + the keyboard
/// follow this. # C: O(1)
pub fn foreground_vt() -> u8 { tty::live::foreground().max(1) }

/// `/dev/tty<N>` + foreground-VT inode. `vt == 0` = foreground video VT
/// (`/dev/console`,`/dev/tty`,`/dev/tty0`), resolved at I/O time; vt 1..=N_VT
/// pin a specific VT. The serial line is a SEPARATE device — see
/// [`SerialInode`]. Output renders to the framebuffer via the VT console
/// driver; it does NOT touch the serial UART (no mirroring).
pub struct ConsoleInode {
    vt: u8,
}

impl ConsoleInode {
    /// Build an inode pinned to `vt`. Use 0 for foreground-alias
    /// (`/dev/console`, `/dev/tty`, `/dev/tty0`); 1..=N_VT for
    /// the per-VT slots.
    /// # C: O(1)
    pub const fn new(vt: u8) -> Self { Self { vt } }
}

impl Inode for ConsoleInode {
    /// Distinct inode numbers per VT so VFS-level introspection
    /// (`stat` / `getdents` ino fields) reflects the underlying
    /// device. vt=0 keeps ino=1 for backwards compatibility with
    /// existing /dev/console callers.
    fn ino(&self) -> Ino {
        // vt 0 = foreground-VT alias (low byte 0xFD); vt N = that VT (low byte N).
        if self.vt == 0 { TTY_INO_BASE | FG_VT_INO_LB as Ino }
        else { TTY_INO_BASE | self.vt as Ino }
    }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }

    fn lookup(&self, _name: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }

    /// Blocking read. vt==0 (the system console: /dev/console, /dev/tty,
    /// /dev/tty0, /dev/ttyS0) delegates to the new serial `TtyStruct`'s
    /// lost-wakeup-free `read` (N_TTY cooks/blocks; returns a whole line
    /// in ICANON, so PAM's `read(STDIN, line, N)` sees the full password
    /// up to `\n` — the B18 stale-tail bug cannot recur). The numbered VT
    /// nodes (vt 1..N) keep their per-VT screen-ring path (T7b territory).
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        // TtyStruct::read parks lost-wakeup-free and returns a cooked line
        // (Bytes), 0 on ^D (Eof), or Interrupted when an unblocked signal
        // lands during the blocking wait → -EINTR (Linux n_tty_read).
        // vt 0 = foreground video VT; vt N = that VT. The serial line is a
        // separate device (SerialInode) — never reached here.
        let vt = if self.vt == 0 { foreground_vt() } else { self.vt };
        let tty = vt_tty::vt_tty(vt);
        jobctl::check(tty.fg_pgrp(), tty.sid(), self.ino(),
            tty::pty::read_lflag(&tty.termios()), jobctl::Access::Read)?;
        let outcome = tty.read(buf);
        match outcome {
            ReadOutcome::Bytes(n) => Ok(n),
            ReadOutcome::Eof => Ok(0),
            ReadOutcome::Interrupted => Err(VfsError::Eintr),
        }
    }

    /// Non-blocking read per `15§5` / `28§3`. systemd PID1 opens
    /// `/dev/console` with `O_NONBLOCK` and runs a `ppoll`+`read` loop: it
    /// expects `read` to return `EAGAIN` on an empty input queue, NOT to
    /// park. vt==0 delegates to the serial `TtyStruct`'s non-blocking
    /// drain; the numbered VTs drain their ring. Either way, empty ⇒
    /// `Eagain`.
    /// # C: O(buf.len())
    fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let vt = if self.vt == 0 { foreground_vt() } else { self.vt };
        let tty = vt_tty::vt_tty(vt);
        jobctl::check(tty.fg_pgrp(), tty.sid(), self.ino(),
            tty::pty::read_lflag(&tty.termios()), jobctl::Access::Read)?;
        let n = tty.read_nonblock(buf);
        if n == 0 { return Err(VfsError::Eagain); }
        Ok(n)
    }

    /// Readiness for poll/ppoll/select. POLLIN only when input is actually
    /// queued (the default Inode::poll claims always readable, which makes
    /// a `ppoll(console, POLLIN, timeout)` loop spin on EAGAIN — systemd's
    /// DSR terminal-size probe does exactly that). Always writable.
    /// # C: O(1)
    fn poll(&self) -> u32 {
        // vt 0 = foreground video VT; vt N = that VT. The per-VT TtyStruct
        // owns readiness; pollmask bits (POLLIN=1, POLLOUT=4) match Linux uapi.
        let vt = if self.vt == 0 { foreground_vt() } else { self.vt };
        vt_tty::vt_tty(vt).poll()
    }

    /// The per-VT tty's poll/select/epoll wait queue — poll/select/epoll
    /// subscribe here and the VT's RX/hangup `notify()`s it (Linux
    /// `->poll` wait queue). # C: O(1)
    fn poll_subscribers(&self) -> Option<&vfs::PollSubscribers> {
        let vt = if self.vt == 0 { foreground_vt() } else { self.vt };
        Some(vt_tty::vt_tty(vt).poll_subs())
    }

    /// Write `buf` to the video VT. The per-VT `TtyStruct` owns OPOST: its
    /// N_TTY runs ONLCR, then `VtConsoleDriver::write` feeds the post-OPOST
    /// bytes to the fbcon emulator (→ vc_data → consw cell-blit) — rendered
    /// ONCE. This device does NOT touch the serial UART; `/dev/ttyS0` is a
    /// separate device (no mirroring → no double-print). printk still reaches
    /// the framebuffer via its own klog sink, independent of this path.
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        dtrace!(b"CW_IN", buf.len() as u64);
        let vt = if self.vt == 0 { foreground_vt() } else { self.vt };
        let tty = vt_tty::vt_tty(vt);
        jobctl::check(tty.fg_pgrp(), tty.sid(), self.ino(),
            tty::pty::read_lflag(&tty.termios()), jobctl::Access::Write)?;
        let n = tty.write(buf);
        dtrace!(b"CW_OUT", n as u64);
        Ok(n)
    }
}

/// `/dev/ttyS0` — the serial UART tty, a SEPARATE device from the video
/// console. Serial-only: never renders to the framebuffer. Its winsize is
/// the serial-terminal default (80×24 until the remote sends SIGWINCH),
/// independent of the framebuffer geometry.
pub struct SerialInode;

impl SerialInode {
    /// Job-control gate for ttyS0 (background-pgrp read/write of the
    /// controlling serial tty). # C: O(pgrp size).
    fn jobctl(&self, access: jobctl::Access) -> KResult<()> {
        jobctl::check(
            static_console::foreground_pgid(),
            static_console::session(),
            self.ino(),
            tty::pty::read_lflag(&static_console::termios_get()),
            access,
        )
    }
}

impl Inode for SerialInode {
    fn ino(&self) -> Ino { TTY_INO_BASE | SERIAL_INO_LB as Ino }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }

    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        self.jobctl(jobctl::Access::Read)?;
        match static_console::read(buf) {
            ReadOutcome::Bytes(n) => Ok(n),
            ReadOutcome::Eof => Ok(0),
            ReadOutcome::Interrupted => Err(VfsError::Eintr),
        }
    }
    fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        self.jobctl(jobctl::Access::Read)?;
        let n = static_console::read_nonblock(buf);
        if n == 0 { return Err(VfsError::Eagain); }
        Ok(n)
    }
    fn poll(&self) -> u32 { static_console::poll() }
    fn poll_subscribers(&self) -> Option<&vfs::PollSubscribers> {
        static_console::poll_subscribers()
    }
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        self.jobctl(jobctl::Access::Write)?;
        Ok(static_console::write(buf))
    }
}

/// Keyboard input sink: deliver one byte to the FOREGROUND video VT's tty
/// (Linux `kbd_keycode` → the fg console's `tty_port`). Routes to
/// `vt_tty(foreground())`, NOT the serial tty — the keyboard belongs to the
/// video console, the serial line gets its own RX (`drv_serial` → ttyS0).
/// Registered as the kbd sink at boot. # C: O(1) + waiter wake
pub fn kbd_input(b: u8) {
    vt_tty::vt_tty(foreground_vt()).receive_from_driver(&[b]);
}

/// Route a VT emulator's terminal answerback (DSR/CPR reply per `CSI n`)
/// into VT `vt`'s tty INPUT ring so the program that issued the query reads
/// its reply back — the Linux `respond_string` → `tty_insert_flip_string`
/// counterpart. Every VT (incl. the fg console) is a `vt_tty`; the serial
/// line answers via its remote terminal, not here. Registered with
/// `fbcon::kernel::set_reply_sink` at boot. # C: O(N) bytes + waiter wake
pub fn vt_reply_sink(vt: u8, bytes: &[u8]) {
    vt_tty::vt_tty(vt.max(1)).receive_from_driver(bytes);
}

/// Build the `init`-process fd table with fd 0/1/2 all pointing at
/// `/dev/console` — the *preferred console* per `console=`
/// ([`system_console_inode`]), so a kernel-spawned PID1 writes its stdout/
/// stderr to the serial line when booted `console=ttyS0` (matching Linux,
/// where init inherits the console device). Returns an `Arc<FdTable>` ready
/// to install on the spawned user task. # C: O(1)
pub fn init_console_fd_table() -> Arc<FdTable> {
    let table = Arc::new(FdTable::new());
    let inode: InodeRef = system_console_inode();
    // Full path so /proc/self/fd/{0,1,2} readlink to /dev/console
    // (the Linux contract) and symlink follow (/dev/stdout → fd/1 →
    // /dev/console) reopens the real node.
    let dentry = Dentry::new(None, "/dev/console".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    // alloc returns the lowest-free fd; first three calls give
    // 0, 1, 2 in order.
    let _fd0 = table.alloc(file.clone());
    let _fd1 = table.alloc(file.clone());
    let _fd2 = table.alloc(file);
    table
}

/// `/dev/vcs` (text) + `/dev/vcsa` (text+attr) — the VT screen-dump devices
/// (Linux `drivers/tty/vt/vc_screen.c`). A read snapshots the FOREGROUND VT's
/// screen: `vcs` = `rows*cols` glyph bytes; `vcsa` = a 4-byte header
/// `[rows, cols, cursor_x, cursor_y]` then `[glyph, attr]` pairs. Read-only
/// here (writing the screen via vcs is not supported → EINVAL).
pub struct VcsInode { with_attr: bool }

impl VcsInode {
    /// `attr=false` → /dev/vcs(0); `attr=true` → /dev/vcsa(0). # C: O(1)
    pub const fn new(attr: bool) -> Self { Self { with_attr: attr } }
}

impl Inode for VcsInode {
    // Distinct, collision-free inos (low byte 0 ⇒ the VT/fbdev ioctl routers
    // skip these): 0x7600 = vcs, 0x7700 = vcsa.
    fn ino(&self) -> Ino { if self.with_attr { 0x7700 } else { 0x7600 } }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = fbcon::kernel::screen_dump(self.with_attr);
        let off = off as usize;
        if off >= data.len() { return Ok(0); }
        let n = (data.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }
    fn write(&self, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Einval) }
}

/// The backing inode for `/dev/console` — the *preferred console* named by
/// the LAST `console=` on the boot cmdline (Linux: `/dev/console` (5:1) is the
/// kernel's preferred console device, NOT a fixed alias of the video VT).
/// `console=ttyS0`/`ttyAMA0` ⇒ the serial tty; `console=tty<n>`/none ⇒ the
/// foreground video VT. This is what makes systemd's `console-getty` (whose
/// `TTYPath=/dev/console`) put `oxide login:` on the serial line when booted
/// `console=ttyS0`, matching Linux. # C: O(cmdline length)
pub fn system_console_inode() -> InodeRef {
    match cmdline::preferred_console() {
        cmdline::ConsoleKind::Serial => Arc::new(SerialInode) as InodeRef,
        cmdline::ConsoleKind::Vt(_)  => Arc::new(ConsoleInode::new(0)) as InodeRef,
    }
}

/// Register the console/tty char-device nodes into devfs (self-registration
/// per docs/56). `/dev/console` follows the preferred `console=`
/// ([`system_console_inode`]); `/dev/tty`+`/dev/tty0` are the foreground VT;
/// /dev/tty1..N each carry their own VT id; /dev/vcs{,0,a,a0} dump the screen.
/// Boot, once.
/// # C: O(N_VT)
pub fn register_devnodes() {
    use alloc::sync::Arc;
    use alloc::string::String;
    // /dev/console = the preferred console (serial when console=ttyS0/ttyAMA0,
    // else the fg VT) — the Linux 5:1 kernel-console device.
    devfs::register("/dev/console", system_console_inode());
    // /dev/tty, /dev/tty0 = the foreground video VT (always video; distinct
    // from /dev/console, which the console= cmdline may point at serial).
    let fg: vfs::InodeRef = Arc::new(ConsoleInode::new(0));
    devfs::register("/dev/tty",     Arc::clone(&fg));
    devfs::register("/dev/tty0",    fg);
    // Serial line — a SEPARATE device (its own tty, serial-only, own winsize).
    devfs::register("/dev/ttyS0",   Arc::new(SerialInode) as vfs::InodeRef);
    for vt in 1..=tty::live::N_VT as u8 {
        let mut path = String::with_capacity(10);
        path.push_str("/dev/tty");
        if vt >= 10 { path.push((b'0' + (vt / 10)) as char); }
        path.push((b'0' + (vt % 10)) as char);
        devfs::register_owned(path, Arc::new(ConsoleInode::new(vt)) as vfs::InodeRef);
    }
    // VT screen-dump devices (vc_screen.c). 0 = current foreground VT.
    let vcs: vfs::InodeRef = Arc::new(VcsInode::new(false));
    devfs::register("/dev/vcs",  Arc::clone(&vcs));
    devfs::register("/dev/vcs0", vcs);
    let vcsa: vfs::InodeRef = Arc::new(VcsInode::new(true));
    devfs::register("/dev/vcsa",  Arc::clone(&vcsa));
    devfs::register("/dev/vcsa0", vcsa);
}
