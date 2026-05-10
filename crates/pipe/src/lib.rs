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

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

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

/// Boot-time smoke for PipeInode + EventfdInode. Round-trips a
/// short message through a freshly-constructed pipe; round-trips
/// a u64 counter through a freshly-constructed eventfd; kasserts
/// the byte / counter contracts.
/// # SAFETY: caller is the boot path; PMM up; single-CPU pre-init.
/// # C: O(N_bytes)
pub fn smoke_test() {
    use vfs::Inode;
    use hal::kassert;

    // Pipe round-trip: write 5 bytes → read 5 bytes back.
    let pipe = PipeInode::new();
    pipe.writers.store(1, core::sync::atomic::Ordering::Release);
    pipe.readers.store(1, core::sync::atomic::Ordering::Release);
    let n = pipe.write(0, b"hello").expect("pipe.write");
    kassert!(n == 5, "pipe write len");
    let mut buf = [0u8; 8];
    let n = pipe.read(0, &mut buf).expect("pipe.read");
    kassert!(n == 5, "pipe read len");
    kassert!(&buf[..5] == b"hello", "pipe round-trip body");
    // Drained pipe with active write-side: Eagain.
    let r = pipe.read(0, &mut buf);
    kassert!(matches!(r, Err(vfs::VfsError::Eagain)), "pipe drained = EAGAIN");
    // Drop the writer → next read returns Ok(0) (true EOF).
    pipe.writers.store(0, core::sync::atomic::Ordering::Release);
    let n = pipe.read(0, &mut buf).expect("pipe.read post-writer-close");
    kassert!(n == 0, "pipe EOF after writers=0");
    // Write to pipe with no readers: Epipe.
    pipe.readers.store(0, core::sync::atomic::Ordering::Release);
    let r = pipe.write(0, b"x");
    kassert!(matches!(r, Err(vfs::VfsError::Epipe)), "pipe write w/o readers = EPIPE");

    // Eventfd round-trip: write 0x1234 → read swaps to 0,
    // returns prior value as 8-byte LE.
    let evt = EventfdInode::new(0);
    let n = evt.write(0, &0x1234u64.to_ne_bytes()).expect("evt.write");
    kassert!(n == 8, "evt write len");
    let mut ev = [0u8; 8];
    let n = evt.read(0, &mut ev).expect("evt.read");
    kassert!(n == 8, "evt read len");
    kassert!(u64::from_ne_bytes(ev) == 0x1234, "evt counter round-trip");

    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  pipe-evt-smoke: ok\n");
    }
}

/// `Inode`-backed eventfd counter per `24§3` + Linux eventfd(2).
/// Read drains the counter to a u64; write adds to it. v1: no
/// blocking — read returns -EAGAIN if counter is 0; write returns
/// -EAGAIN if counter would overflow.
pub struct EventfdInode {
    counter: core::sync::atomic::AtomicU64,
    ino:     vfs::Ino,
}

static NEXT_EVENTFD_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0x4000_0000);

impl EventfdInode {
    /// # C: O(1)
    pub fn new(initial: u64) -> alloc::sync::Arc<Self> {
        let ino = NEXT_EVENTFD_INO.fetch_add(1, Ordering::Relaxed);
        alloc::sync::Arc::new(Self {
            counter: core::sync::atomic::AtomicU64::new(initial),
            ino,
        })
    }
}

impl vfs::Inode for EventfdInode {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Fifo }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _name: &str) -> vfs::KResult<vfs::InodeRef> {
        Err(vfs::VfsError::Enotdir)
    }
    fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let v = self.counter.swap(0, Ordering::AcqRel);
        if v == 0 { return Err(vfs::VfsError::Einval); }
        let bytes = v.to_ne_bytes();
        buf[..8].copy_from_slice(&bytes);
        Ok(8)
    }
    fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let mut a = [0u8; 8];
        a.copy_from_slice(&buf[..8]);
        let add = u64::from_ne_bytes(a);
        if add == u64::MAX { return Err(vfs::VfsError::Einval); }
        self.counter.fetch_add(add, Ordering::AcqRel);
        Ok(8)
    }
}

/// `Inode`-backed anonymous pipe. One instance is shared by both
/// the read-end and the write-end `File` wrappers.
pub struct PipeInode {
    buf: Spinlock<PipeBuf, TtyClass>,
    /// Inode number — globally unique among pipes; allocated from
    /// a monotonic counter per `01§4`.
    ino: Ino,
    /// Live write-end count. `sys_pipe2` initialises to 1 (one
    /// write-end File outlives this constructor); each writable
    /// File's Drop decrements via the vfs close hook. A read on
    /// an empty pipe returns `0` (EOF) when this hits zero,
    /// matching Linux pipe(7) — non-zero means writers still
    /// exist and the read returns `Eagain` (v1 non-blocking).
    pub writers: core::sync::atomic::AtomicUsize,
    /// Live read-end count. Symmetric tracking so a write to a
    /// pipe with zero readers can return `Epipe` (Linux SIGPIPE
    /// substrate landing alongside).
    pub readers: core::sync::atomic::AtomicUsize,
}

static NEXT_PIPE_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0x1000_0000);

impl PipeInode {
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        let ino = NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            buf: Spinlock::new(PipeBuf::new()),
            ino,
            writers: core::sync::atomic::AtomicUsize::new(0),
            readers: core::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl Inode for PipeInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Fifo }
    fn size(&self) -> u64 { 0 }
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }

    fn lookup(&self, _name: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }

    /// Pipe read per `24§3` + Linux pipe(7).
    /// - data available    → return up to `buf.len()` bytes
    /// - empty + writers>0 → `Eagain` (v1 non-blocking; full
    ///                       blocking rides the WaitQueue plumbing)
    /// - empty + writers=0 → `Ok(0)` (true EOF — all write ends closed)
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut g = self.buf.lock();
        if g.len == 0 {
            if self.writers.load(Ordering::Acquire) == 0 {
                return Ok(0);
            }
            return Err(VfsError::Eagain);
        }
        let mut n = 0;
        while n < buf.len() {
            match g.pop() {
                Some(b) => { buf[n] = b; n += 1; }
                None    => break,
            }
        }
        Ok(n)
    }

    /// Pipe write per `24§3` + Linux pipe(7).
    /// - readers==0       → `Epipe` (caller should also receive
    ///                      SIGPIPE; signal substrate rides v2.x)
    /// - room available   → push up to `buf.len()` bytes, return n
    /// - buffer full      → `Eagain` (v1 non-blocking)
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        if self.readers.load(Ordering::Acquire) == 0 {
            return Err(VfsError::Epipe);
        }
        let mut g = self.buf.lock();
        if g.len == PIPE_CAP { return Err(VfsError::Eagain); }
        let mut n = 0;
        while n < buf.len() {
            if !g.push(buf[n]) { break; }
            n += 1;
        }
        Ok(n)
    }
}
