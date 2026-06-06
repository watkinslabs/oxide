#![no_std]
#[macro_use] extern crate kmacros;
extern crate alloc;

// `/dev/console` + `/dev/tty<N>` char-devices per docs/16 + docs/28.
// Multi-VT layout (post-B07):
//   - `/dev/tty1`..`/dev/tty6` each carry a distinct VT id and
//     read from that VT's ring (`tty::try_read_vt`).
//   - `/dev/console`, `/dev/tty`, `/dev/tty0` all carry vt=0,
//     which `tty::vt_index` resolves to the live foreground at
//     every read — they alias whatever VT the user is "looking
//     at" without holding stale references.
// Writes still go to the single UART path via `klog::write_raw`;
// per-VT TX framebuffers are a follow-up (gates the K13 DRM/KMS
// scanout path).
//
// init's fd 0/1/2 install a vt=0 (foreground-alias) ConsoleInode
// — backwards-compatible with the pre-B07 single-VT behavior.


use alloc::string::ToString;
use alloc::sync::Arc;

// Use-aliased import per R06 carve-out (same pattern as
// `crates/syscall::dispatch::sys_write`): the user-console
// byte-emit path is intentionally not gated under a
// `debug-<sub>` feature because writing user TTY output is
// the device's purpose, not diagnostic logging.
use klog::write_raw as console_emit;
use vfs::{Dentry, FdTable, File, FileType, Ino, Inode, InodeRef, KResult, OpenFlags, VfsError, POLL_IN, POLL_OUT};

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

    /// Block-and-drain read from this VT's ringbuffer per `28§3`
    /// console semantics. Blocks until at least one byte arrives,
    /// then drains everything currently in the ring into `buf` (up
    /// to `buf.len()` bytes) and returns. Returning just `Ok(1)`
    /// here breaks any caller that reads whole lines in one syscall
    /// — notably Linux-PAM's misc_conv, which does
    /// `read(STDIN, line, INPUTSIZE-1)` expecting the full
    /// password-up-to-`\n`. With one-byte returns it took the first
    /// byte as the entire password and left the rest of the typed
    /// line in the ring as stale input for the next reader (agetty
    /// then saw that stale tail as the next username, producing the
    /// "password came through as the username" symptom on B18).
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        // Block until at least one byte is available.
        let first = loop {
            if let Some(b) = tty::live::try_read_vt(self.vt) { break b; }
            // SAFETY: we are the running task on this CPU; preempt-off; park before yielding.
            unsafe { tty::live::park_current_for_tty_vt(self.vt); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is now Sleeping so schedule() won't re-enqueue us — only the wake from `tick_poll_uart` (or future kbd→VT route) will.
            unsafe { sched::live::schedule(); }
        };
        buf[0] = first;
        let mut n: usize = 1;
        // Drain whatever else is already queued. ICANON line
        // discipline only flushes a line into the ring on `\n` /
        // VEOF / VEOL, so what's there after the first byte IS the
        // tail of the user's typed line — return it all in one
        // syscall so misc_conv sees the whole line.
        while n < buf.len() {
            match tty::live::try_read_vt(self.vt) {
                Some(b) => { buf[n] = b; n += 1; }
                None    => break,
            }
        }
        Ok(n)
    }

    /// Non-blocking read per `15§5` / `28§3`. systemd PID1 opens
    /// `/dev/console` with `O_NONBLOCK` and runs a `ppoll`+`read`
    /// loop: it expects `read` to return `EAGAIN` on an empty input
    /// ring, NOT to park. The default `Inode::read_nonblock`
    /// delegates to the blocking `read` above, which wedged PID1
    /// (it slept in the console read forever — never reached the
    /// sd-event main loop). Drain whatever is queued without ever
    /// parking; return `Eagain` when the ring is empty.
    /// # C: O(buf.len())
    fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let mut n: usize = 0;
        while n < buf.len() {
            match tty::live::try_read_vt(self.vt) {
                Some(b) => { buf[n] = b; n += 1; }
                None    => break,
            }
        }
        if n == 0 { return Err(VfsError::Eagain); }
        Ok(n)
    }

    /// Readiness for poll/ppoll/select. POLLIN only when this VT's RX
    /// ring actually holds input (the default Inode::poll claims always
    /// readable, which makes a `ppoll(console, POLLIN, timeout)` loop
    /// spin on EAGAIN instead of waiting out its deadline — systemd's
    /// DSR terminal-size probe does exactly that). Always writable.
    /// # C: O(1)
    fn poll(&self) -> u32 {
        let mut mask = POLL_OUT;
        if tty::live::vt_has_input(self.vt) { mask |= POLL_IN; }
        mask
    }

    /// Emit `buf` via the kernel UART path. `klog::write_raw`
    /// only accepts `&'static str` for format strings, but
    /// raw byte writes are exactly what the UART path needs;
    /// we bypass the format-checked klog macros and call the
    /// raw byte sink directly per the R06 console-output carve-out.
    ///
    /// Output processing per the VT's c_oflag: OPOST gates whether
    /// any translation runs at all; ONLCR maps each NL on output
    /// to CRLF so a host serial terminal advances cleanly. The
    /// rest of the OPOST flags (OCRNL/ONOCR/ONLRET) are stored in
    /// the termios image but not honoured yet — they need column
    /// tracking which v1 doesn't keep.
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        dtrace!(b"CW_IN", buf.len() as u64);
        let oflag = tty::live::output_oflag(self.vt);
        dtrace!(b"CW_OFL", oflag as u64);
        let post = (oflag & tty::pty::oflag::OPOST) != 0;
        let onlcr = post && (oflag & tty::pty::oflag::ONLCR) != 0;
        if !onlcr {
            console_emit(buf);
            dtrace!(b"CW_OUT_RAW", buf.len() as u64);
            return Ok(buf.len());
        }
        // ONLCR: emit each maximal NL-free run in one console_emit
        // call, with b"\r\n" between runs. Single lock_irqsave per
        // run + one per NL pair, so the BOOT_UART lock isn't taken
        // 56 separate times for a 56-byte write — the per-byte
        // loop variant tripped a wedge on the last NL of the CAT
        // smoke's /proc/version write (see project_login_hang_cat_smoke.md).
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            if b == b'\n' {
                if i > start {
                    dtrace!(b"CW_RUN", (i - start) as u64);
                    console_emit(&buf[start..i]);
                }
                dtrace!(b"CW_NL");
                console_emit(b"\r\n");
                start = i + 1;
            }
        }
        if start < buf.len() {
            dtrace!(b"CW_TAIL", (buf.len() - start) as u64);
            console_emit(&buf[start..]);
        }
        dtrace!(b"CW_OUT", buf.len() as u64);
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
