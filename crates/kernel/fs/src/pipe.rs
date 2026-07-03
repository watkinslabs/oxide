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
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;
use sync::{Spinlock, Tty as TtyClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, PollSubscribers, default_inode_ops, mk_mode};

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
    use hal::kassert;

    // Pipe round-trip: write 5 bytes → read 5 bytes back.
    let pipe = make_pipe_inode();
    let pd = pipe_data(&pipe).expect("pipe data");
    pd.writers.store(1, core::sync::atomic::Ordering::Release);
    pd.readers.store(1, core::sync::atomic::Ordering::Release);
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
    pd.writers.store(0, core::sync::atomic::Ordering::Release);
    let n = pipe.read(0, &mut buf).expect("pipe.read post-writer-close");
    kassert!(n == 0, "pipe EOF after writers=0");
    // Write to pipe with no readers: Epipe.
    pd.readers.store(0, core::sync::atomic::Ordering::Release);
    let r = pipe.write(0, b"x");
    kassert!(matches!(r, Err(vfs::VfsError::Epipe)), "pipe write w/o readers = EPIPE");

    // Eventfd round-trip: write 0x1234 → read swaps to 0,
    // returns prior value as 8-byte LE.
    let evt = make_eventfd_inode(0);
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
/// Read drains the counter to a u64; write adds to it. A BLOCKING read on a
/// zero counter PARKS on `read_waiters` until a write makes it non-zero (Linux
/// eventfd(2) blocks; a non-blocking read returns EAGAIN — NEVER EINVAL). The
/// counter lives in `i_private`.
pub struct EventfdData {
    counter: core::sync::atomic::AtomicU64,
    /// Tasks parked in a blocking `read` that found the counter 0; woken by
    /// `write`. (No blocking-write parking: a u64 counter effectively never
    /// fills in these control-fd uses.)
    read_waiters: WaitList,
}

static NEXT_EVENTFD_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0x4000_0000);

/// `make_eventfd_inode(initial)` — a Fifo pseudo-inode whose counter drains on
/// read and accumulates on write. # C: O(1)
pub fn make_eventfd_inode(initial: u64) -> InodeRef {
    let ino = NEXT_EVENTFD_INO.fetch_add(1, Ordering::Relaxed);
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(EventfdFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(EventfdData {
            counter: core::sync::atomic::AtomicU64::new(initial),
            read_waiters: WaitList::new(),
        }))
        .build()
}

/// `i_fop` for an eventfd inode. # C: O(1)
struct EventfdFileOps;
impl FileOps for EventfdFileOps {
    /// POLLIN when the counter is nonzero (read won't block); POLLOUT
    /// when it can still accept a write (< u64::MAX-1). Default
    /// always-ready poll busy-looped systemd's sd-event epoll — see
    /// signalfd::poll.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let v = match inode.private::<EventfdData>() { Some(d) => d.counter.load(Ordering::Acquire), None => return 0 };
        let mut m = 0;
        if v > 0 { m |= vfs::POLL_IN; }
        if v < u64::MAX - 1 { m |= vfs::POLL_OUT; }
        m
    }
    /// BLOCKING read (Linux eventfd(2)): drain the counter; if it is 0, PARK
    /// until a write makes it non-zero (interruptible by a deliverable signal →
    /// EINTR). NEVER EINVAL on an empty counter — that broke systemd's
    /// `setup_private_users` `(sd-userns)` helper, whose blocking
    /// `read(unshare_ready_fd)` barrier got EINVAL and reported it to the
    /// executor → EXIT_USER(217) for every PrivateUsers= unit (upower, …).
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        loop {
            let v = d.counter.swap(0, Ordering::AcqRel);
            if v != 0 {
                buf[..8].copy_from_slice(&v.to_ne_bytes());
                return Ok(8);
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                // On UP with preempt-off nothing runs between the swap above and
                // the park below, so a writer cannot slip a wake in unseen.
                if sched::live::deliverable_signals_self() != 0 { return Err(vfs::VfsError::Eintr); }
                // SAFETY: running task; preempt-off; park marks Sleeping + bumps the Arc before we schedule.
                unsafe { d.read_waiters.park(); }
                // SAFETY: process ctx; runqueue installed; preempt-off; Sleeping so schedule won't re-enqueue until a write wakes us.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(vfs::VfsError::Eagain);
        }
    }
    /// Non-blocking read (O_NONBLOCK): EAGAIN on an empty counter (Linux), not
    /// EINVAL and not a park.
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        let v = d.counter.swap(0, Ordering::AcqRel);
        if v == 0 { return Err(vfs::VfsError::Eagain); }
        buf[..8].copy_from_slice(&v.to_ne_bytes());
        Ok(8)
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.len() < 8 { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        let mut a = [0u8; 8];
        a.copy_from_slice(&buf[..8]);
        let add = u64::from_ne_bytes(a);
        if add == u64::MAX { return Err(vfs::VfsError::Einval); }
        d.counter.fetch_add(add, Ordering::AcqRel);
        // Counter went nonzero → wake blocking readers parked on it, AND poll/
        // epoll waiters (sd-event drives eventfds via epoll_wait).
        d.read_waiters.wake_all();
        if let Some(s) = inode.poll_subscribers() { s.notify(); }
        Ok(8)
    }
}

/// `Inode`-backed anonymous pipe state (Linux `i_private`). One instance is
/// shared by both the read-end and the write-end `File` wrappers.
pub struct PipeData {
    buf: Spinlock<PipeBuf, TtyClass>,
    /// Inode number — globally unique among pipes; allocated from
    /// a monotonic counter per `01§4`.
    pub ino: Ino,
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
    capacity: AtomicUsize,
}

static NEXT_PIPE_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0x1000_0000);

/// `make_pipe_inode()` — a Fifo pseudo-inode backing both ends of an anonymous
/// pipe. The per-fd poll/select/epoll wait queue lives on the inode's
/// `poll_subscribers`; the ring + waiters live in `i_private`. # C: O(1)
pub fn make_pipe_inode() -> InodeRef {
    let ino = NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed);
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(PipeFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(PipeData {
            buf: Spinlock::new(PipeBuf::new()),
            ino,
            writers: core::sync::atomic::AtomicUsize::new(0),
            readers: core::sync::atomic::AtomicUsize::new(0),
            read_waiters:  WaitList::new(),
            write_waiters: WaitList::new(),
            capacity: AtomicUsize::new(PIPE_CAP),
        }))
        .build()
}

/// Recover the `PipeData` behind a pipe inode. # C: O(1)
pub fn pipe_data(inode: &Inode) -> Option<&PipeData> { inode.private::<PipeData>() }

/// `fcntl(F_GETPIPE_SZ)`. # C: O(1)
pub fn pipe_size(inode: &Inode) -> Option<usize> {
    pipe_data(inode).map(|p| p.capacity.load(Ordering::Acquire))
}

/// `fcntl(F_SETPIPE_SZ)`. # C: O(1)
pub fn set_pipe_size(inode: &Inode, requested: usize) -> Result<usize, VfsError> {
    let p = pipe_data(inode).ok_or(VfsError::Einval)?;
    let new_cap = requested.clamp(1, PIPE_CAP);
    let len = p.buf.lock().len;
    if new_cap < len { return Err(VfsError::Ebusy); }
    if requested > PIPE_CAP { return Err(VfsError::Eperm); }
    p.capacity.store(new_cap, Ordering::Release);
    Ok(new_cap)
}

impl PipeData {
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
        let cap = self.capacity.load(Ordering::Acquire);
        if g.len >= cap { return 0; }
        let mut n = 0;
        while n < buf.len() {
            if g.len >= cap { break; }
            if !g.push(buf[n]) { break; }
            n += 1;
        }
        n
    }
}

/// `i_fop` for an anonymous-pipe inode. Reads `PipeData` off `i_private`.
struct PipeFileOps;
impl FileOps for PipeFileOps {
    /// Blocking pipe read per Linux pipe(7).
    /// - data available     → up to `buf.len()` bytes copied.
    /// - empty + writers>0  → park on `read_waiters`, retry on wake.
    /// - empty + writers==0 → Ok(0) (EOF, all write ends closed).
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let this = match pipe_data(inode) { Some(p) => p, None => return Err(VfsError::Einval) };
        let subs = inode.poll_subscribers();
        loop {
            let n = this.try_drain(buf);
            if n > 0 {
                this.write_waiters.wake_all();
                if let Some(s) = subs { s.notify(); }
                return Ok(n);
            }
            if this.writers.load(Ordering::Acquire) == 0 {
                return Ok(0);
            }
            // Signal-interruptible per pipe(7): a blocked read with a
            // deliverable signal pending returns EINTR so the libc
            // handler runs (and the caller can restart). Without this
            // a blocked pipe read ignores signals entirely — e.g. a
            // read under a SIGCHLD/SIGALRM handler never wakes.
            #[cfg(target_os = "oxide-kernel")]
            if sched::live::deliverable_signals_self() != 0 {
                return Err(VfsError::Eintr);
            }
            // SAFETY: caller is the running task; preempt-off; we are about to schedule. WaitList::park bumps Arc and marks Sleeping.
            unsafe { this.read_waiters.park(); }
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
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let this = match pipe_data(inode) { Some(p) => p, None => return Err(VfsError::Einval) };
        let subs = inode.poll_subscribers();
        loop {
            if this.readers.load(Ordering::Acquire) == 0 {
                return Err(VfsError::Epipe);
            }
            let n = this.try_fill(buf);
            if n > 0 {
                this.read_waiters.wake_all();
                if let Some(s) = subs { s.notify(); }
                return Ok(n);
            }
            // Signal-interruptible per pipe(7): a blocked write with a
            // deliverable signal pending returns EINTR (Linux semantic).
            #[cfg(target_os = "oxide-kernel")]
            if sched::live::deliverable_signals_self() != 0 {
                return Err(VfsError::Eintr);
            }
            // SAFETY: caller is the running task; preempt-off; WaitList::park bumps Arc and marks Sleeping before we schedule.
            unsafe { this.write_waiters.park(); }
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
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let this = match pipe_data(inode) { Some(p) => p, None => return Err(VfsError::Einval) };
        let n = this.try_drain(buf);
        if n > 0 {
            this.write_waiters.wake_all();
            if let Some(s) = inode.poll_subscribers() { s.notify(); }
            return Ok(n);
        }
        if this.writers.load(Ordering::Acquire) == 0 { Ok(0) }
        else { Err(VfsError::Eagain) }
    }

    /// Readiness for select/poll per Linux pipe(7):
    /// - POLLIN  when bytes are buffered, or when the last writer
    ///   has closed (read returns EOF immediately, not a block).
    /// - POLLHUP when readers==0 (write side will get EPIPE).
    /// - POLLOUT when buffer has room AND at least one reader.
    fn poll(&self, inode: &Inode) -> u32 {
        let this = match pipe_data(inode) { Some(p) => p, None => return 0 };
        let len = this.buf.lock().len;
        let writers = this.writers.load(Ordering::Acquire);
        let readers = this.readers.load(Ordering::Acquire);
        let mut mask = 0u32;
        if len > 0 || writers == 0 { mask |= vfs::POLL_IN; }
        if readers == 0 { mask |= vfs::POLL_HUP; }
        if len < PIPE_CAP && readers > 0 { mask |= vfs::POLL_OUT; }
        mask
    }

    /// Non-blocking pipe write per Linux O_NONBLOCK semantics.
    fn write_nonblock(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let this = match pipe_data(inode) { Some(p) => p, None => return Err(VfsError::Einval) };
        if this.readers.load(Ordering::Acquire) == 0 {
            return Err(VfsError::Epipe);
        }
        let n = this.try_fill(buf);
        if n > 0 {
            this.read_waiters.wake_all();
            if let Some(s) = inode.poll_subscribers() { s.notify(); }
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
    let Some(pipe) = pipe_data(inode) else {
        #[cfg(feature = "debug-ssh")]
        {
            klog::write_raw(b"[INFO]  ssh-trace: pipe_close non-pipe-inode ino=");
            klog::write_dec_u64(inode.ino());
            klog::write_raw(b" was_writable=");
            klog::write_dec_u64(if was_writable { 1 } else { 0 });
            klog::write_raw(b"\n");
        }
        return;
    };
    let subs = inode.poll_subscribers();
    if was_writable {
        #[cfg(feature = "debug-ssh")]
        let pre = pipe.writers.load(Ordering::Acquire);
        let prev = pipe.writers.fetch_sub(1, Ordering::AcqRel);
        if prev == 0 {
            pipe.writers.store(0, Ordering::Release);
        }
        #[cfg(feature = "debug-ssh")]
        {
            klog::write_raw(b"[INFO]  ssh-trace: pipe_close ino=");
            klog::write_dec_u64(pipe.ino);
            klog::write_raw(b" writer pre_load=");
            klog::write_dec_u64(pre as u64);
            klog::write_raw(b" fs_prev=");
            klog::write_dec_u64(prev as u64);
            klog::write_raw(b"\n");
        }
        if prev <= 1 { pipe.read_waiters.wake_all(); if let Some(s) = subs { s.notify(); } }
    } else {
        let prev = pipe.readers.fetch_sub(1, Ordering::AcqRel);
        if prev == 0 {
            pipe.readers.store(0, Ordering::Release);
        }
        #[cfg(feature = "debug-ssh")]
        {
            klog::write_raw(b"[INFO]  ssh-trace: pipe_close ino=");
            klog::write_dec_u64(pipe.ino);
            klog::write_raw(b" reader prev=");
            klog::write_dec_u64(prev as u64);
            klog::write_raw(b" writers=");
            klog::write_dec_u64(pipe.writers.load(Ordering::Acquire) as u64);
            klog::write_raw(b"\n");
        }
        if prev <= 1 { pipe.write_waiters.wake_all(); if let Some(s) = subs { s.notify(); } }
    }
}

/// Install the pipe close-tracking hook. Call once at boot.
/// # C: O(1)
pub fn install_close_hook() {
    vfs::set_close_hook(pipe_close_hook);
}
