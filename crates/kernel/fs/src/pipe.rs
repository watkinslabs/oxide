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


use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;
use sync::{Spinlock, Tty as TtyClass};
use vfs::{File, FileType, Fmode, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, PollSubscribers, default_inode_ops, mk_mode};

mod smoke;
#[cfg(test)]
mod fifo_tests;

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
    smoke::smoke_test();
}

/// `Inode`-backed eventfd counter per `24§3` + Linux eventfd(2).
/// Read drains the counter to a u64; write adds to it. A BLOCKING read on a
/// zero counter PARKS on `read_waiters` until a write makes it non-zero (Linux
/// eventfd(2) blocks; a non-blocking read returns EAGAIN — NEVER EINVAL). The
/// counter lives in `i_private`.
pub struct EventfdData {
    counter: core::sync::atomic::AtomicU64,
    semaphore: bool,
    /// Tasks parked in a blocking `read` that found the counter 0; woken by
    /// `write`. (No blocking-write parking: a u64 counter effectively never
    /// fills in these control-fd uses.)
    read_waiters: WaitList,
}

static NEXT_EVENTFD_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(0x4000_0000);

/// `make_eventfd_inode(initial, semaphore)` — a Fifo pseudo-inode whose counter
/// drains on read and accumulates on write. # C: O(1)
pub fn make_eventfd_inode(initial: u64, semaphore: bool) -> InodeRef {
    let ino = NEXT_EVENTFD_INO.fetch_add(1, Ordering::Relaxed);
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(EventfdFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(EventfdData {
            counter: core::sync::atomic::AtomicU64::new(initial),
            semaphore,
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
            let v = eventfd_do_read(d);
            if v != 0 {
                buf[..8].copy_from_slice(&v.to_ne_bytes());
                if let Some(s) = inode.poll_subscribers() { s.notify(); }
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
        let v = eventfd_do_read(d);
        if v == 0 { return Err(vfs::VfsError::Eagain); }
        buf[..8].copy_from_slice(&v.to_ne_bytes());
        if let Some(s) = inode.poll_subscribers() { s.notify(); }
        Ok(8)
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        if buf.len() != 8 { return Err(vfs::VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(vfs::VfsError::Einval) };
        let mut a = [0u8; 8];
        a.copy_from_slice(buf);
        let add = u64::from_ne_bytes(a);
        if add == u64::MAX { return Err(vfs::VfsError::Einval); }
        loop {
            let cur = d.counter.load(Ordering::Acquire);
            if u64::MAX - cur <= add { return Err(vfs::VfsError::Eagain); }
            if d.counter.compare_exchange(cur, cur + add, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                break;
            }
        }
        // Counter went nonzero → wake blocking readers parked on it, AND poll/
        // epoll waiters (sd-event drives eventfds via epoll_wait).
        d.read_waiters.wake_all();
        if let Some(s) = inode.poll_subscribers() { s.notify(); }
        Ok(8)
    }
}

fn eventfd_do_read(d: &EventfdData) -> u64 {
    if d.semaphore {
        loop {
            let cur = d.counter.load(Ordering::Acquire);
            if cur == 0 { return 0; }
            if d.counter.compare_exchange(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                return 1;
            }
        }
    }
    d.counter.swap(0, Ordering::AcqRel)
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

    /// Blocking ring read shared by the anonymous-pipe (`PipeFileOps`) and
    /// named-FIFO (`FifoFileOps`) data paths — Linux `pipe_read`. `subs` is the
    /// inode's epoll subscriber set (`None` when the backing inode carries no
    /// poll queue). Semantics per pipe(7): data available → up to `buf.len()`
    /// bytes; empty + writers>0 → park on `read_waiters`; empty + writers==0 →
    /// `Ok(0)` (EOF, all write ends closed); a deliverable signal → `Eintr`.
    /// # C: O(bytes) + park
    fn read_blocking(&self, subs: Option<&PollSubscribers>, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            let n = self.try_drain(buf);
            if n > 0 {
                self.write_waiters.wake_all();
                if let Some(s) = subs { s.notify(); }
                return Ok(n);
            }
            if self.writers.load(Ordering::Acquire) == 0 { return Ok(0); }
            #[cfg(target_os = "oxide-kernel")]
            if sched::live::deliverable_signals_self() != 0 { return Err(VfsError::Eintr); }
            // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping before we schedule, and there is >=1 writer to wake us.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { self.read_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; preempt-off; current is Sleeping so schedule won't re-enqueue until a writer wake fires.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// Blocking ring write shared by both data paths — Linux `pipe_write`.
    /// readers==0 → `Epipe` (caller also gets SIGPIPE); space → push up to
    /// `buf.len()`; full + readers>0 → park on `write_waiters`; signal → `Eintr`.
    /// # C: O(bytes) + park
    fn write_blocking(&self, subs: Option<&PollSubscribers>, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            if self.readers.load(Ordering::Acquire) == 0 { return Err(VfsError::Epipe); }
            let n = self.try_fill(buf);
            if n > 0 {
                self.read_waiters.wake_all();
                if let Some(s) = subs { s.notify(); }
                return Ok(n);
            }
            #[cfg(target_os = "oxide-kernel")]
            if sched::live::deliverable_signals_self() != 0 { return Err(VfsError::Eintr); }
            // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping before we schedule, and a reader wake / last-reader-close will resume us.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { self.write_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; preempt-off; current is Sleeping so schedule won't re-enqueue until a read-side wake fires.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// Non-blocking ring read (`O_NONBLOCK`): data → bytes; empty + writers>0 →
    /// `Eagain`; empty + writers==0 → `Ok(0)`. # C: O(bytes)
    fn read_nb(&self, subs: Option<&PollSubscribers>, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let n = self.try_drain(buf);
        if n > 0 {
            self.write_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
            return Ok(n);
        }
        if self.writers.load(Ordering::Acquire) == 0 { Ok(0) } else { Err(VfsError::Eagain) }
    }

    /// Non-blocking ring write (`O_NONBLOCK`): readers==0 → `Epipe`; space →
    /// bytes; full → `Eagain`. # C: O(bytes)
    fn write_nb(&self, subs: Option<&PollSubscribers>, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        if self.readers.load(Ordering::Acquire) == 0 { return Err(VfsError::Epipe); }
        let n = self.try_fill(buf);
        if n > 0 {
            self.read_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
            return Ok(n);
        }
        Err(VfsError::Eagain)
    }

    /// `poll`/`select` readiness bitmask per pipe(7): POLLIN when bytes buffered
    /// OR the last writer closed (read returns EOF, not a block); POLLHUP when
    /// readers==0; POLLOUT when the ring has room AND a reader exists. # C: O(1)
    fn poll_mask(&self) -> u32 {
        let len = self.buf.lock().len;
        let writers = self.writers.load(Ordering::Acquire);
        let readers = self.readers.load(Ordering::Acquire);
        let mut mask = 0u32;
        if len > 0 || writers == 0 { mask |= vfs::POLL_IN; }
        if readers == 0 { mask |= vfs::POLL_HUP; }
        if len < PIPE_CAP && readers > 0 { mask |= vfs::POLL_OUT; }
        mask
    }
}

/// `i_fop` for an anonymous-pipe inode. Reads `PipeData` off `i_private` and
/// delegates to the shared ring core (also used by `FifoFileOps`).
struct PipeFileOps;
impl FileOps for PipeFileOps {
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        pipe_data(inode).ok_or(VfsError::Einval)?.read_blocking(inode.poll_subscribers(), buf)
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        pipe_data(inode).ok_or(VfsError::Einval)?.write_blocking(inode.poll_subscribers(), buf)
    }
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        pipe_data(inode).ok_or(VfsError::Einval)?.read_nb(inode.poll_subscribers(), buf)
    }
    fn write_nonblock(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        pipe_data(inode).ok_or(VfsError::Einval)?.write_nb(inode.poll_subscribers(), buf)
    }
    fn poll(&self, inode: &Inode) -> u32 {
        pipe_data(inode).map(|p| p.poll_mask()).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Named FIFO (S_IFIFO) — Linux `fs/pipe.c` `fifo_open` + `pipefifo_fops`.
//
// A named pipe is a filesystem inode (tmpfs/ext4/devnode `mknod`) whose on-disk
// `i_fop` is a metadata-only / EIO stub — a bare read/write of a FIFO inode is
// meaningless. On `open(2)`, `fifo_open` attaches ONE shared `PipeData` ring to
// the inode (created on first open, reused by every later open of the SAME
// path/inode so a reader process and a writer process rendezvous on one ring),
// does the access-mode reader/writer rendezvous, and swaps THIS open's
// `file->f_op` to `FifoFileOps` so its data path goes through the ring.
//
// Linux stores the ring on `inode->i_pipe`. The oxide `Inode` is immutable
// post-build and its `i_private` slot is already owned by the backend (tmpfs
// stores nothing, devnode stores `DeviceNodeData`), so the shared ring lives in
// a per-inode side table keyed by inode identity, created on first open and
// dropped when the last end closes (Linux `free_pipe_info`).
// ---------------------------------------------------------------------------

/// Lock class for the FIFO side table. Taken standalone — every access copies an
/// `Arc<PipeData>` out (or inserts/removes one) and releases the lock BEFORE any
/// ring/wait-list work, so it never nests under `buf`/wait-list locks. # C: O(1)
struct FifoReg;
impl sync::LockClass for FifoReg { fn rank() -> u16 { 34 } }

/// `inode->i_pipe` side table: FIFO inode identity → its shared pipe ring. An
/// entry exists only while the FIFO has at least one open end.
static FIFO_PIPES: Spinlock<BTreeMap<usize, Arc<PipeData>>, FifoReg>
    = Spinlock::new(BTreeMap::new());

/// Inode identity key for the FIFO side table — the `Inode` allocation address.
/// Every `open`/read/write/release of the same named FIFO derives it from the
/// SAME `Arc<Inode>` (the dcache caches one inode per path), so the key is
/// stable while the FIFO is open. # C: O(1)
fn fifo_key(inode: &Inode) -> usize { inode as *const Inode as usize }

/// `true` iff `inode` is a NAMED FIFO (a filesystem S_IFIFO node), as opposed to
/// an anonymous pipe (`PipeData` in `i_private`) or an eventfd (`EventfdData`) —
/// both of which are also `FileType::Fifo` but are born via `pipe2`/`eventfd`
/// with their ring/counter already bound and are never opened by path. # C: O(1)
pub fn is_named_fifo(inode: &Inode) -> bool {
    inode.file_type() == FileType::Fifo
        && inode.private::<PipeData>().is_none()
        && inode.private::<EventfdData>().is_none()
}

/// Get (or create on first open) the shared ring for a FIFO inode. # C: O(log N)
fn fifo_pipe_get_or_create(inode: &Inode) -> Arc<PipeData> {
    let key = fifo_key(inode);
    let mut g = FIFO_PIPES.lock();
    if let Some(p) = g.get(&key) { return p.clone(); }
    let p = Arc::new(PipeData {
        buf: Spinlock::new(PipeBuf::new()),
        ino: inode.ino(),
        writers: AtomicUsize::new(0),
        readers: AtomicUsize::new(0),
        read_waiters:  WaitList::new(),
        write_waiters: WaitList::new(),
        capacity: AtomicUsize::new(PIPE_CAP),
    });
    g.insert(key, p.clone());
    p
}

/// Look up the shared ring for an already-open FIFO inode. # C: O(log N)
fn fifo_pipe_lookup(inode: &Inode) -> Option<Arc<PipeData>> {
    FIFO_PIPES.lock().get(&fifo_key(inode)).cloned()
}

/// Drop the shared ring once BOTH ends are closed (Linux `free_pipe_info`); the
/// next open re-creates it (buffered bytes are lost, as on Linux). # C: O(log N)
fn fifo_gc(inode: &Inode, p: &PipeData) {
    if p.readers.load(Ordering::Acquire) == 0 && p.writers.load(Ordering::Acquire) == 0 {
        FIFO_PIPES.lock().remove(&fifo_key(inode));
    }
}

/// `i_fop` OVERRIDE installed on a FIFO's open `File` by [`fifo_open`]. Recovers
/// the shared ring from the side table and delegates to the same core as
/// `PipeFileOps`. `Einval` if the ring is gone (should not happen while open).
struct FifoFileOps;
impl FileOps for FifoFileOps {
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        fifo_pipe_lookup(inode).ok_or(VfsError::Einval)?.read_blocking(inode.poll_subscribers(), buf)
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        fifo_pipe_lookup(inode).ok_or(VfsError::Einval)?.write_blocking(inode.poll_subscribers(), buf)
    }
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        fifo_pipe_lookup(inode).ok_or(VfsError::Einval)?.read_nb(inode.poll_subscribers(), buf)
    }
    fn write_nonblock(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        fifo_pipe_lookup(inode).ok_or(VfsError::Einval)?.write_nb(inode.poll_subscribers(), buf)
    }
    fn poll(&self, inode: &Inode) -> u32 {
        fifo_pipe_lookup(inode).map(|p| p.poll_mask()).unwrap_or(0)
    }
    /// Last-close of THIS FIFO open description (Linux `pipe_release`): drop the
    /// reader and/or writer count this open took in `fifo_open` (per its
    /// `f_mode`), wake the opposite side so a peer sees EOF / EPIPE, and GC the
    /// ring when both ends are gone. Runs from `File::Drop`. # C: O(log N)
    fn on_release_file(&self, file: &File) {
        let fm = file.f_mode();
        fifo_release(file.inode(), fm.contains(Fmode::READ), fm.contains(Fmode::WRITE));
    }
}

/// Release the reader (`dec_read`) and/or writer (`dec_write`) count a FIFO open
/// took in [`fifo_open`], waking the opposite side when a count reaches 0 so a
/// peer sees EOF / EPIPE, and GC-ing the shared ring once both ends are gone
/// (Linux `pipe_release` + `free_pipe_info`). # C: O(log N)
fn fifo_release(inode: &Inode, dec_read: bool, dec_write: bool) {
    let Some(p) = fifo_pipe_lookup(inode) else { return; };
    let subs = inode.poll_subscribers();
    if dec_read {
        let prev = p.readers.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            p.readers.store(0, Ordering::Release);
            p.write_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
        }
    }
    if dec_write {
        let prev = p.writers.fetch_sub(1, Ordering::AcqRel);
        if prev <= 1 {
            p.writers.store(0, Ordering::Release);
            p.read_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
        }
    }
    fifo_gc(inode, &p);
}

/// FIFO `open(2)` — Linux `fs/pipe.c` `fifo_open`. Attaches/looks up the shared
/// ring, runs the access-mode reader/writer rendezvous, and returns the `f_op`
/// the caller installs on this open's `File` (Linux `filp->f_op =
/// &pipefifo_fops`). Reader/writer counts taken here are released by
/// `FifoFileOps::on_release_file` at last close.
///
/// Rendezvous (Linux, `is_pipe == false`):
/// - `O_RDONLY`: `readers++`, wake writers. No writer yet and NOT `O_NONBLOCK` →
///   BLOCK until a writer opens; `O_NONBLOCK` → succeed immediately.
/// - `O_WRONLY`: no reader yet and `O_NONBLOCK` → `ENXIO` (no count taken).
///   Else `writers++`, wake readers; no reader yet and NOT `O_NONBLOCK` → BLOCK
///   until a reader opens.
/// - `O_RDWR`: `readers++` and `writers++`, wake both; NEVER blocks (Linux FIFO
///   quirk).
/// A blocking wait is interruptible by a deliverable signal → `Eintr`
/// (`-ERESTARTSYS`), which undoes the count it took.
///
/// Hosted builds have no scheduler: the block loops are `oxide-kernel`-gated, so
/// a would-block open returns immediately (only the never-blocking / `O_NONBLOCK`
/// matrix is exercised in hosted tests). # C: O(log N) + rendezvous wait
pub fn fifo_open(inode: &InodeRef, flags: u32) -> KResult<Arc<dyn FileOps>> {
    const O_ACCMODE: u32 = 0o3;
    const O_WRONLY:  u32 = 0o1;
    const O_RDWR:    u32 = 0o2;
    const O_NONBLOCK: u32 = 0o4000;
    let accmode  = flags & O_ACCMODE;
    let nonblock = (flags & O_NONBLOCK) != 0;
    let subs = inode.poll_subscribers();
    let p = fifo_pipe_get_or_create(inode);
    match accmode {
        O_WRONLY => {
            // ENXIO BEFORE taking a writer count (Linux: `!pipe->readers` +
            // O_NONBLOCK → -ENXIO at `err`, having incremented nothing).
            if nonblock && p.readers.load(Ordering::Acquire) == 0 {
                fifo_gc(inode, &p);
                return Err(VfsError::Enxio);
            }
            p.writers.fetch_add(1, Ordering::AcqRel);
            p.read_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
            if !nonblock && p.readers.load(Ordering::Acquire) == 0 {
                #[cfg(target_os = "oxide-kernel")]
                loop {
                    if p.readers.load(Ordering::Acquire) != 0 { break; }
                    if sched::live::deliverable_signals_self() != 0 {
                        let prev = p.writers.fetch_sub(1, Ordering::AcqRel);
                        if prev <= 1 { p.read_waiters.wake_all(); }
                        fifo_gc(inode, &p);
                        return Err(VfsError::Eintr);
                    }
                    // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping; a reader open (or its close) will wake write_waiters.
                    unsafe { p.write_waiters.park(); }
                    // SAFETY: process ctx; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until a reader wake fires.
                    unsafe { sched::live::schedule::schedule(); }
                }
            }
        }
        O_RDWR => {
            // O_RDWR on a FIFO takes BOTH ends and never blocks (Linux quirk).
            p.readers.fetch_add(1, Ordering::AcqRel);
            p.writers.fetch_add(1, Ordering::AcqRel);
            p.read_waiters.wake_all();
            p.write_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
        }
        _ => {
            // O_RDONLY (access mode 0).
            p.readers.fetch_add(1, Ordering::AcqRel);
            p.write_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
            if !nonblock && p.writers.load(Ordering::Acquire) == 0 {
                #[cfg(target_os = "oxide-kernel")]
                loop {
                    if p.writers.load(Ordering::Acquire) != 0 { break; }
                    if sched::live::deliverable_signals_self() != 0 {
                        let prev = p.readers.fetch_sub(1, Ordering::AcqRel);
                        if prev <= 1 { p.write_waiters.wake_all(); }
                        fifo_gc(inode, &p);
                        return Err(VfsError::Eintr);
                    }
                    // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping; a writer open (or its close) will wake read_waiters.
                    unsafe { p.read_waiters.park(); }
                    // SAFETY: process ctx; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until a writer wake fires.
                    unsafe { sched::live::schedule::schedule(); }
                }
            }
        }
    }
    Ok(Arc::new(FifoFileOps))
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
