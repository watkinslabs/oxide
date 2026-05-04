// Anonymous pipe per docs/16 + docs/24. v1 implementation:
// fixed-capacity 4 KiB ringbuffer behind a `Spinlock`, with a
// `vfs::Inode` impl that backs both the read and write ends.
//
// `sys_pipe2(pipefd, flags)` creates a `PipeInode`, wraps it in
// two `File`s with `O_RDONLY` / `O_WRONLY` flags, allocates
// fds in the current task's fd_table, and writes the two fd
// numbers to the user `pipefd[2]` array.
//
// v1 minimal: non-blocking on empty/full (returns Eagain).
// Blocking with a `WaitQueue` rides P3-01b once docs/24 fully
// freezes the wait-queue contract. For the canonical
// `cmd1 | cmd2` shell pipeline this is sufficient as long as
// the pipeline is serialised (cmd1 runs to completion before
// cmd2 starts) — full overlapped pipes need blocking.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sync::{Spinlock, Tty as TtyClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

const PIPE_CAP: usize = 4096;

struct PipeBuf {
    data: [u8; PIPE_CAP],
    head: usize,
    tail: usize,
    len:  usize,
}

impl PipeBuf {
    const fn new() -> Self {
        Self { data: [0; PIPE_CAP], head: 0, tail: 0, len: 0 }
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len == PIPE_CAP { return false; }
        self.data[self.tail] = b;
        self.tail = (self.tail + 1) % PIPE_CAP;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 { return None; }
        let b = self.data[self.head];
        self.head = (self.head + 1) % PIPE_CAP;
        self.len -= 1;
        Some(b)
    }
}

/// `Inode`-backed anonymous pipe. One instance is shared by both
/// the read-end and the write-end `File` wrappers.
pub struct PipeInode {
    buf: Spinlock<PipeBuf, TtyClass>,
    /// Inode number — globally unique among pipes; allocated from
    /// a monotonic counter per `01§4`.
    ino: Ino,
}

static NEXT_PIPE_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0x1000_0000);

impl PipeInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let ino = NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { buf: Spinlock::new(PipeBuf::new()), ino })
    }
}

impl Inode for PipeInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Fifo }
    fn size(&self) -> u64 { 0 }

    fn lookup(&self, _name: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }

    /// Non-blocking read: copies up to `buf.len()` bytes from the
    /// ringbuffer. Returns `Ok(0)` (treated as EOF by some callers
    /// or EAGAIN by others) if the buffer is empty. Real Linux
    /// blocks unless `O_NONBLOCK`; v1 stub returns 0.
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut g = self.buf.lock();
        let mut n = 0;
        while n < buf.len() {
            match g.pop() {
                Some(b) => { buf[n] = b; n += 1; }
                None    => break,
            }
        }
        Ok(n)
    }

    /// Non-blocking write: copies up to `buf.len()` bytes into the
    /// ringbuffer. Returns the count actually written; `0` if
    /// the buffer is full (caller's choice to retry / EAGAIN).
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        let mut g = self.buf.lock();
        let mut n = 0;
        while n < buf.len() {
            if !g.push(buf[n]) { break; }
            n += 1;
        }
        Ok(n)
    }
}
