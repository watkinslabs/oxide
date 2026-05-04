// `/dev/console` char-device per docs/16 + docs/28. v1 stub of
// the real /dev plumbing called out in `state.md` "TTY
// architecture note". Backed by:
//   - read:  blocks on `tty.rs`'s ringbuffer (timer-tick poll)
//   - write: emits via `klog::write_raw` (UART path)
//
// Once VFS + devfs land (P2-30), this becomes a registered
// char-device under `/dev/console`, and `/dev/tty0..6` get
// distinct instances. For now `init` (the boot user task)
// installs three references to a single `ConsoleInode`-backed
// `File` at fd 0, 1, 2 in its `FdTable` so the existing user
// programs reach it via the standard fd indirection rather than
// kernel-side hard-wiring.

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

/// `/dev/console` inode. Single global instance; reads block on
/// `tty::try_read` + WaitQueue, writes go to UART via `klog`.
pub struct ConsoleInode;

impl Inode for ConsoleInode {
    fn ino(&self) -> Ino { 1 }
    fn file_type(&self) -> FileType { FileType::CharDev }
    fn size(&self) -> u64 { 0 }

    fn lookup(&self, _name: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }

    /// Block-and-retry read from the kernel TTY ringbuffer per
    /// `28§3` console semantics. Returns `Ok(1)` on success
    /// (one byte at a time — line discipline lands later).
    /// arm v1: ringbuffer + RX wiring not yet implemented (PL011
    /// driver lands with P2-30c follow-up); returns Eagain so
    /// userspace polls.
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        #[cfg(target_arch = "x86_64")]
        loop {
            if let Some(b) = crate::tty::try_read() {
                buf[0] = b;
                return Ok(1);
            }
            // SAFETY: we are the running task on this CPU; preempt-off; park before yielding.
            unsafe { crate::tty::park_current_for_tty(); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is now Sleeping so schedule() won't re-enqueue us — only the wake from `tick_poll_uart` will.
            unsafe { crate::sched::schedule(); }
        }
        #[cfg(target_arch = "aarch64")]
        loop {
            if let Some(b) = crate::tty::try_read() {
                buf[0] = b;
                return Ok(1);
            }
            // SAFETY: we are the running task on this CPU; preempt-off; park before yielding.
            unsafe { crate::tty::park_current_for_tty(); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is now Sleeping so schedule() won't re-enqueue us — only the wake from `tick_poll_uart` will.
            unsafe { crate::sched::schedule(); }
        }
    }

    /// Emit `buf` via the kernel UART path. `klog::write_raw`
    /// only accepts `&'static str` for format strings, but
    /// raw byte writes are exactly what the UART path needs;
    /// we bypass the format-checked klog macros and call the
    /// raw byte sink directly per the R06 console-output carve-out.
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        console_emit(buf);
        Ok(buf.len())
    }
}

/// Build the `init`-process fd table with fd 0/1/2 all pointing
/// at `/dev/console`. Returns an `Arc<FdTable>` ready to install
/// on the spawned user task.
///
/// v1 stub: a single `ConsoleInode` instance is shared across the
/// three fds so reads go to one ringbuffer + writes converge on
/// one UART. Full /dev/tty0..6 + foreground-VT alias rides P2-30.
/// # C: O(1)
pub fn init_console_fd_table() -> Arc<FdTable> {
    let table = Arc::new(FdTable::new());
    let inode: InodeRef = Arc::new(ConsoleInode);
    let dentry = Dentry::new(None, "console".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    // alloc returns the lowest-free fd; first three calls give
    // 0, 1, 2 in order.
    let _fd0 = table.alloc(file.clone());
    let _fd1 = table.alloc(file.clone());
    let _fd2 = table.alloc(file);
    table
}
