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

pub mod static_console;
pub mod vt_tty;

use alloc::string::ToString;
use alloc::sync::Arc;

use vfs::{Dentry, FdTable, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError};

/// `/dev/console` + `/dev/tty<N>` inode. `vt == 0` means
/// "foreground alias" and resolves at read-time; vt 1..=N_VT
/// pin to a specific slot.
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
    fn ino(&self) -> Ino { (self.vt as Ino).max(1) }
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
        if self.vt == 0 {
            // TtyStruct::read parks lost-wakeup-free and returns a cooked
            // line (or 0 on ^D EOF).
            return Ok(static_console::read(buf));
        }
        // Numbered VT (B4a): the real per-VT `TtyStruct` parks
        // lost-wakeup-free and returns a cooked line (or 0 on ^D EOF) —
        // the same N_TTY core the system console uses.
        Ok(vt_tty::vt_tty(self.vt).read(buf))
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
        let n = if self.vt == 0 {
            static_console::read_nonblock(buf)
        } else {
            vt_tty::vt_tty(self.vt).read_nonblock(buf)
        };
        if n == 0 { return Err(VfsError::Eagain); }
        Ok(n)
    }

    /// Readiness for poll/ppoll/select. POLLIN only when input is actually
    /// queued (the default Inode::poll claims always readable, which makes
    /// a `ppoll(console, POLLIN, timeout)` loop spin on EAGAIN — systemd's
    /// DSR terminal-size probe does exactly that). Always writable.
    /// # C: O(1)
    fn poll(&self) -> u32 {
        if self.vt == 0 {
            return static_console::poll();
        }
        // Numbered VT (B4a): the per-VT TtyStruct owns readiness. The
        // ldisc pollmask bits (POLLIN=1, POLLOUT=4) match vfs::POLL_IN /
        // POLL_OUT (Linux uapi), so the mask passes through unchanged.
        vt_tty::vt_tty(self.vt).poll()
    }

    /// Write `buf`. vt==0 (the system console) goes through the serial
    /// `TtyStruct`'s N_TTY output processing (OPOST/ONLCR) → UART, and
    /// does NOT touch the kmsg ring (the dmesg/shell-output split). The
    /// numbered VTs still emit through the old per-VT ONLCR path to the
    /// UART (T7b moves them onto the VT console driver).
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        dtrace!(b"CW_IN", buf.len() as u64);
        if self.vt == 0 {
            // System console. The serial line is the SECONDARY console (the
            // durable log + the boot/login path): cooked OPOST/ONLCR → UART
            // via the serial `TtyStruct`. The PRIMARY console is the
            // framebuffer VT `vc_cons[0]` — feed the SAME bytes through its
            // `vc_data` emulator (the Linux fb-console contract, the same
            // path the numbered VTs use). That is what renders /dev/console
            // on the framebuffer AND answers DSR/CPR (`ESC[6n`) LOCALLY with
            // the real fbcon geometry: the emulator queues the reply and the
            // tick drain injects it back into THIS tty's input ring
            // (`vt_reply_sink(0)` → `static_console::rx_byte`), so a probe
            // (`printf '\033[6n'; read -d R`) on /dev/console reads oxide's
            // geometry, not the serial host terminal's. `vt_write` no-ops
            // before fbcon init, so a serial-only machine keeps a pure-serial
            // /dev/console (the remote terminal answers, as Linux serial does).
            let n = static_console::write(buf);
            let oflag = tty::pty::read_oflag(&static_console::termios_get());
            let onlcr = (oflag & tty::pty::oflag::OPOST) != 0
                && (oflag & tty::pty::oflag::ONLCR) != 0;
            fbcon_feed(0, buf, onlcr);
            dtrace!(b"CW_OUT", n as u64);
            return Ok(n);
        }
        // Numbered VT (B4a): the per-VT `TtyStruct` owns OPOST. Its N_TTY
        // runs ONLCR, then `VtConsoleDriver::write` feeds the post-OPOST
        // bytes to the fbcon emulator (→ vc_data → consw cell-blit). The
        // ldisc owns OPOST now — NO manual fbcon_feed/ONLCR here.
        Ok(vt_tty::vt_tty(self.vt).write(buf))
    }
}

/// Feed `buf` to fbcon VT `vt`'s `vc_data` emulator (the Linux VT console
/// device write: emulator → `vc_data` → consw cell-blit + DSR/CPR
/// answerback). Applies ONLCR output translation (`\n` → `\r\n`) when
/// `onlcr` is set — the ldisc's OPOST job; the emulator itself treats `\n`
/// as a bare linefeed (no column reset). Shared by the system console
/// (vt 0) and the numbered VTs.
/// # C: O(N) bytes + dirty-cell blit on the fg VT.
fn fbcon_feed(vt: u8, buf: &[u8], onlcr: bool) {
    if !onlcr {
        fbcon::kernel::vt_write(vt, buf);
        return;
    }
    let mut start = 0;
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' {
            if i > start { fbcon::kernel::vt_write(vt, &buf[start..i]); }
            fbcon::kernel::vt_write(vt, b"\r\n");
            start = i + 1;
        }
    }
    if start < buf.len() { fbcon::kernel::vt_write(vt, &buf[start..]); }
}

/// Route a VT emulator's terminal answerback (DSR/CPR reply per `CSI n`)
/// into the matching tty INPUT ring so the program that issued the query
/// reads its reply back — the fbcon counterpart of Linux `respond_string`
/// → `tty_insert_flip_string`. `vt == 0` is the system console (the serial
/// `TtyStruct`'s flip path → N_TTY); `1..=N_VT` are the numbered VTs (the
/// `tty::live` per-VT input ring, same path keyboard RX uses). Registered
/// with `fbcon::kernel::set_reply_sink` at boot.
/// # C: O(N) bytes + waiter wake
pub fn vt_reply_sink(vt: u8, bytes: &[u8]) {
    if vt == 0 {
        // System console: feed the bytes into ttyS0's RX flip path so the
        // reader (e.g. btop on /dev/console) drains them. The console tty
        // is in raw mode while a full-screen app runs, so the reply passes
        // straight through N_TTY into the read queue.
        for &b in bytes {
            static_console::rx_byte(b);
        }
    } else {
        // Numbered VT (B4a): inject the answerback into the per-VT
        // TtyStruct's RX flip path (→ N_TTY → read queue), the same path
        // keyboard RX takes. Safe from the tick-drain context (process /
        // softirq): vt_tty lazy-alloc is a plain CAS, no sleeping.
        vt_tty::vt_tty(vt).receive_from_driver(bytes);
    }
}

/// Build the `init`-process fd table with fd 0/1/2 all pointing
/// at `/dev/console` (vt=0, foreground-alias). Returns an
/// `Arc<FdTable>` ready to install on the spawned user task.
/// # C: O(1)
pub fn init_console_fd_table() -> Arc<FdTable> {
    let table = Arc::new(FdTable::new());
    let inode: InodeRef = Arc::new(ConsoleInode::new(0));
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

/// Register the console/tty char-device nodes into devfs (self-registration
/// per docs/56). /dev/{console,tty,tty0,ttyS0} alias the foreground VT (vt=0);
/// /dev/tty1..N each carry their own VT id; /dev/vcs{,0,a,a0} dump the screen.
/// Boot, once.
/// # C: O(N_VT)
pub fn register_devnodes() {
    use alloc::sync::Arc;
    use alloc::string::String;
    let fg: vfs::InodeRef = Arc::new(ConsoleInode::new(0));
    devfs::register("/dev/console", Arc::clone(&fg));
    devfs::register("/dev/tty",     Arc::clone(&fg));
    devfs::register("/dev/tty0",    Arc::clone(&fg));
    devfs::register("/dev/ttyS0",   fg);
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
