// `/dev/console` + `/dev/tty<N>` char-devices per docs/16 + docs/28.
// Multi-VT layout (post-B07):
//   - `/dev/tty1`..`/dev/tty6` each carry a distinct VT id and
//     read from that VT's ring (`tty::try_read_vt`).
//   - `/dev/console`, `/dev/tty`, `/dev/tty0` all carry vt=0,
//     which `tty::vt_index` resolves to the live foreground at
//     every read — they alias whatever VT the user is "looking
//     at" without holding stale references.
// Writes still go to the single UART path via `klog::write_raw`;
// per-VT TX framebuffers are out of scope for v1.
//
// init's fd 0/1/2 install a vt=0 (foreground-alias) ConsoleInode
// — backwards-compatible with the pre-B07 single-VT behavior.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use alloc::sync::Arc;

// Use-aliased import per R06 carve-out (same pattern as
// `crates/syscall::dispatch::sys_write`): the user-console
// byte-emit path is intentionally not gated under a
// `debug-<sub>` feature because writing user TTY output is
// the device's purpose, not diagnostic logging.
use klog::write_raw as console_emit;
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

    /// Block-and-retry read from this VT's ringbuffer per
    /// `28§3` console semantics. Returns `Ok(1)` on success
    /// (one byte at a time — line discipline lands later).
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            if let Some(b) = crate::tty::try_read_vt(self.vt) {
                buf[0] = b;
                return Ok(1);
            }
            // SAFETY: we are the running task on this CPU; preempt-off; park before yielding.
            unsafe { crate::tty::park_current_for_tty_vt(self.vt); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is now Sleeping so schedule() won't re-enqueue us — only the wake from `tick_poll_uart` (or future kbd→VT route) will.
            unsafe { crate::sched::schedule(); }
        }
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
        let oflag = crate::tty::output_oflag(self.vt);
        let post = (oflag & tty::pty::oflag::OPOST) != 0;
        let onlcr = post && (oflag & tty::pty::oflag::ONLCR) != 0;
        if !onlcr {
            console_emit(buf);
            return Ok(buf.len());
        }
        // Emit byte-by-byte applying NL → CRLF. Buffered batching
        // would be faster but interactive output is at human pace.
        for &b in buf {
            if b == b'\n' { console_emit(b"\r\n"); }
            else          { console_emit(core::slice::from_ref(&b)); }
        }
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
    let dentry = Dentry::new(None, "console".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    // alloc returns the lowest-free fd; first three calls give
    // 0, 1, 2 in order.
    let _fd0 = table.alloc(file.clone());
    let _fd1 = table.alloc(file.clone());
    let _fd2 = table.alloc(file);
    table
}
