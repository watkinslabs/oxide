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
        // Numbered VT: block-and-drain the per-VT ring (unchanged).
        let first = loop {
            if let Some(b) = tty::live::try_read_vt(self.vt) { break b; }
            // SAFETY: we are the running task on this CPU; preempt-off; park before yielding.
            unsafe { tty::live::park_current_for_tty_vt(self.vt); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is now Sleeping so schedule() won't re-enqueue us — only the VT-ring wake will.
            unsafe { sched::live::schedule(); }
        };
        buf[0] = first;
        let mut n: usize = 1;
        while n < buf.len() {
            match tty::live::try_read_vt(self.vt) {
                Some(b) => { buf[n] = b; n += 1; }
                None    => break,
            }
        }
        Ok(n)
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
            let mut k: usize = 0;
            while k < buf.len() {
                match tty::live::try_read_vt(self.vt) {
                    Some(b) => { buf[k] = b; k += 1; }
                    None    => break,
                }
            }
            k
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
        let mut mask = vfs::POLL_OUT;
        if tty::live::vt_has_input(self.vt) { mask |= vfs::POLL_IN; }
        mask
    }

    /// Write `buf`. vt==0 (the system console) goes through the serial
    /// `TtyStruct`'s N_TTY output processing (OPOST/ONLCR) → UART, and
    /// does NOT touch the kmsg ring (the dmesg/shell-output split). The
    /// numbered VTs still emit through the old per-VT ONLCR path to the
    /// UART (T7b moves them onto the VT console driver).
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        dtrace!(b"CW_IN", buf.len() as u64);
        if self.vt == 0 {
            let n = static_console::write(buf);
            dtrace!(b"CW_OUT", n as u64);
            return Ok(n);
        }
        // Numbered VT path (tty-rebuild-plan §3-T7b Piece 3): route the
        // write through the fbcon VT console — emulator → vc_data → consw
        // cell-blit (the real Linux VT console driver path), NOT the old
        // klog/kmsg-ring funnel. OPOST/ONLCR is applied here (the ldisc's
        // output-processing job) before the emulator sees the bytes; the
        // emulator itself treats `\n` as a raw linefeed (no column reset),
        // so ONLCR-expanded `\r\n` is what moves to col 0 + next row.
        //
        // Per-VT framebuffer consoles (tty-rebuild-plan §3-P3): each
        // numbered `/dev/ttyN` feeds its OWN `vc_cons[vt]` screen buffer
        // (lazily allocated). Only the foreground VT is blitted to the
        // physical FB; a write to an offscreen VT updates its `Vc` only.
        // Ctrl-Alt-Fn (kbd) calls `fbcon::kernel::switch_vt` to bring a
        // VT forward. Input (read/poll) uses the per-VT `tty::live` ring
        // above.
        let oflag = tty::live::output_oflag(self.vt);
        let post = (oflag & tty::pty::oflag::OPOST) != 0;
        let onlcr = post && (oflag & tty::pty::oflag::ONLCR) != 0;
        if !onlcr {
            fbcon::kernel::vt_write(self.vt, buf);
            return Ok(buf.len());
        }
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                if i > start { fbcon::kernel::vt_write(self.vt, &buf[start..i]); }
                fbcon::kernel::vt_write(self.vt, b"\r\n");
                start = i + 1;
            }
        }
        if start < buf.len() { fbcon::kernel::vt_write(self.vt, &buf[start..]); }
        Ok(buf.len())
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

/// Register the console/tty char-device nodes into devfs (self-registration
/// per docs/56). /dev/{console,tty,tty0,ttyS0} alias the foreground VT (vt=0);
/// /dev/tty1..N each carry their own VT id. Boot, once.
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
}
