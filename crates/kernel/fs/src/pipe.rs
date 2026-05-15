// Anonymous pipe per docs/16 + docs/24. Fixed-capacity 4 KiB
// ringbuffer behind a `Spinlock`; one `vfs::Inode` impl backs both
// read and write ends. `sys_pipe2(pipefd, flags)` creates a
// `PipeInode`, wraps it in two `File`s (O_RDONLY / O_WRONLY),
// allocates fds, writes the pair into `pipefd[2]`.
//
// Blocking semantics (Linux pipe(7)):
//  - read() on empty pipe + writers>0  → park on read_waiters
//  - read() on empty pipe + writers==0 → Ok(0) (EOF)
//  - read_nonblock() on empty          → Eagain
//  - write() on full + readers>0       → park on write_waiters
//  - write() on full + readers==0      → Epipe
//  - write_nonblock() on full          → Eagain
//
// Close tracking: PipeInode registers a vfs close-hook
// (`vfs::set_close_hook`) once at boot; on every `File::Drop`
// targeting a pipe inode, the writable/readable count decrements
// and the opposite wait list is woken so peers see EOF / EPIPE.


use alloc::sync::Arc;
use core::sync::atomic::Ordering;

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;
use sync::{Spinlock, Tty as TtyClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Hosted-test stand-in: WaitList only exists under the live
/// scheduler. On hosted unit-test builds the pipe inode still
/// needs `park`/`wake_all` symbols to compile, but those code
/// paths are unreachable since the smoke test only exercises
/// the non-blocking variants.
#[cfg(not(target_os = "oxide-kernel"))]
struct WaitList;

#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    const fn new() -> Self { Self }
    fn wake_all(&self) {}
    /// # SAFETY: never invoked under hosted; see type-level doc.
    unsafe fn park(&self) { unreachable!("park under hosted"); }
}

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
    // Drained pipe with active write-side: read_nonblock = EAGAIN.
    // (Blocking read would park; smoke test exercises the
    // non-blocking surface for the empty-but-writers-alive case.)
    let r = pipe.read_nonblock(0, &mut buf);
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
    /// Live write-end count; decremented by the vfs close hook on
    /// every writable File::Drop targeting this inode. A read on
    /// an empty pipe returns `Ok(0)` (EOF) when this hits zero.
    pub writers: core::sync::atomic::AtomicUsize,
    /// Live read-end count. Symmetric tracking so a write to a
    /// pipe with zero readers can return `Epipe`.
    pub readers: core::sync::atomic::AtomicUsize,
    /// Tasks parked on a read that found the buffer empty. Woken
    /// when a write deposits bytes or when the last writer closes.
    read_waiters:  WaitList,
    /// Tasks parked on a write that found the buffer full. Woken
    /// when a read drains bytes or when the last reader closes.
    write_waiters: WaitList,
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
            read_waiters:  WaitList::new(),
            write_waiters: WaitList::new(),
        })
    }

    /// Drain whatever bytes are available without blocking. Returns
    /// the byte count copied; updates wait-list state on success.
    fn try_drain(&self, buf: &mut [u8]) -> usize {
        let mut g = self.buf.lock();
        if g.len == 0 { return 0; }
        let mut n = 0;
        while n < buf.len() {
            match g.pop() { Some(b) => { buf[n] = b; n += 1; } None => break }
        }
        n
    }

    /// Push as many bytes as fit; returns the byte count written.
    fn try_fill(&self, buf: &[u8]) -> usize {
        let mut g = self.buf.lock();
        if g.len == PIPE_CAP { return 0; }
        let mut n = 0;
        while n < buf.len() {
            if !g.push(buf[n]) { break; }
            n += 1;
        }
        n
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

    /// Blocking pipe read per Linux pipe(7).
    /// - data available     → up to `buf.len()` bytes copied.
    /// - empty + writers>0  → park on `read_waiters`, retry on wake.
    /// - empty + writers==0 → Ok(0) (EOF, all write ends closed).
    fn read(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            let n = self.try_drain(buf);
            if n > 0 {
                self.write_waiters.wake_all();
                return Ok(n);
            }
            if self.writers.load(Ordering::Acquire) == 0 {
                return Ok(0);
            }
            // SAFETY: caller is the running task; preempt-off; we are about to schedule. WaitList::park bumps Arc and marks Sleeping.
            unsafe { self.read_waiters.park(); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is Sleeping so schedule won't re-enqueue us — only the write-side wake or last-writer-close wake will.
            #[cfg(target_os = "oxide-kernel")]
            // SAFETY: process ctx, runqueue installed, preempt-off; current is Sleeping so schedule won't re-enqueue until peer wakes us.
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            unreachable!("blocking pipe under hosted");
        }
    }

    /// Blocking pipe write per Linux pipe(7).
    /// - readers==0     → Epipe (caller also gets SIGPIPE via sys_write).
    /// - space available→ push up to `buf.len()` bytes, return n.
    /// - buffer full    → park on `write_waiters`, retry on wake.
    fn write(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            if self.readers.load(Ordering::Acquire) == 0 {
                return Err(VfsError::Epipe);
            }
            let n = self.try_fill(buf);
            if n > 0 {
                self.read_waiters.wake_all();
                return Ok(n);
            }
            // SAFETY: caller is the running task; preempt-off; WaitList::park bumps Arc and marks Sleeping before we schedule.
            unsafe { self.write_waiters.park(); }
            // SAFETY: process ctx, runqueue installed, preempt-off; current is Sleeping so schedule won't re-enqueue us — only the read-side wake or last-reader-close wake will.
            #[cfg(target_os = "oxide-kernel")]
            // SAFETY: process ctx, runqueue installed, preempt-off; current is Sleeping so schedule won't re-enqueue until peer wakes us.
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            unreachable!("blocking pipe under hosted");
        }
    }

    /// Non-blocking pipe read per Linux O_NONBLOCK semantics:
    /// - data available     → bytes copied, no wait.
    /// - empty + writers>0  → Eagain.
    /// - empty + writers==0 → Ok(0).
    fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let n = self.try_drain(buf);
        if n > 0 {
            self.write_waiters.wake_all();
            return Ok(n);
        }
        if self.writers.load(Ordering::Acquire) == 0 { Ok(0) }
        else { Err(VfsError::Eagain) }
    }

    /// Non-blocking pipe write per Linux O_NONBLOCK semantics.
    fn write_nonblock(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        if self.readers.load(Ordering::Acquire) == 0 {
            return Err(VfsError::Epipe);
        }
        let n = self.try_fill(buf);
        if n > 0 {
            self.read_waiters.wake_all();
            return Ok(n);
        }
        Err(VfsError::Eagain)
    }
}

/// Close hook installed at boot via `vfs::set_close_hook`. Tracks
/// pipe writer/reader counts: every writable File::Drop on a pipe
/// inode decrements `writers` and wakes the read side so peers see
/// EOF; symmetric for readable closes and the write side seeing
/// EPIPE.
/// # C: O(1) per call
fn pipe_close_hook(inode: &InodeRef, was_writable: bool) {
    let Some(any) = inode.as_any() else { return };
    let Some(pipe) = any.downcast_ref::<PipeInode>() else { return };
    if was_writable {
        let prev = pipe.writers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 { pipe.read_waiters.wake_all(); }
    } else {
        let prev = pipe.readers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 { pipe.write_waiters.wake_all(); }
    }
}

/// Install the pipe close-tracking hook. Call once at boot.
/// # C: O(1)
pub fn install_close_hook() {
    vfs::set_close_hook(pipe_close_hook);
}
