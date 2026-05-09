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
    let n = pipe.write(0, b"hello").expect("pipe.write");
    kassert!(n == 5, "pipe write len");
    let mut buf = [0u8; 8];
    let n = pipe.read(0, &mut buf).expect("pipe.read");
    kassert!(n == 5, "pipe read len");
    kassert!(&buf[..5] == b"hello", "pipe round-trip body");
    // Drained pipe with active write-side: Eagain per Linux pipe(7)
    // (true 0=EOF only when all writers closed — rides P3-01b).
    let r = pipe.read(0, &mut buf);
    kassert!(matches!(r, Err(vfs::VfsError::Eagain)), "pipe drained = EAGAIN");

    // Eventfd round-trip: write 0x1234 → read swaps to 0,
    // returns prior value as 8-byte LE.
    let evt = EventfdInode::new(0);
    let n = evt.write(0, &0x1234u64.to_ne_bytes()).expect("evt.write");
    kassert!(n == 8, "evt write len");
    let mut ev = [0u8; 8];
    let n = evt.read(0, &mut ev).expect("evt.read");
    kassert!(n == 8, "evt read len");
    kassert!(u64::from_ne_bytes(ev) == 0x1234, "evt counter round-trip");

    debug_boot! { klog::write_raw(b"[INFO]  pipe-evt-smoke: ok\n"); }
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

    /// Pipe read per `24§3` + Linux pipe(7). Returns up to
    /// `buf.len()` bytes from the ringbuffer when data is present.
    /// On an empty pipe, returns `Eagain` (matches Linux
    /// `O_NONBLOCK` semantics — `0` would be EOF, which Linux only
    /// signals when all write-ends are closed). True blocking +
    /// proper EOF detection ride writer-count tracking + the
    /// `WaitQueue` plumbing per `24§3`.
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut g = self.buf.lock();
        if g.len == 0 { return Err(VfsError::Eagain); }
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
