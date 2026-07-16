use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use sync::{Spinlock, Tty as TtyClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{InodeBuilder, PollSubscribers, default_inode_ops, mk_mode};

use super::{PipeFileOps, WaitList};

pub(super) const PIPE_CAP: usize = 4096;

struct PipeBuf {
    data: [u8; PIPE_CAP],
    packet: [bool; PIPE_CAP],
    packet_end: [bool; PIPE_CAP],
    head: usize,
    tail: usize,
    len:  usize,
}

impl PipeBuf {
    const fn new() -> Self {
        Self { data: [0; PIPE_CAP], packet: [false; PIPE_CAP], packet_end: [false; PIPE_CAP],
            head: 0, tail: 0, len: 0 }
    }

    fn push(&mut self, b: u8, packet: bool, packet_end: bool) -> bool {
        if self.len == PIPE_CAP { return false; }
        self.data[self.tail] = b;
        self.packet[self.tail] = packet;
        self.packet_end[self.tail] = packet_end;
        self.tail = (self.tail + 1) % PIPE_CAP;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<(u8, bool, bool)> {
        if self.len == 0 { return None; }
        let b = self.data[self.head];
        let packet = self.packet[self.head];
        let packet_end = self.packet_end[self.head];
        self.packet[self.head] = false;
        self.packet_end[self.head] = false;
        self.head = (self.head + 1) % PIPE_CAP;
        self.len -= 1;
        Some((b, packet, packet_end))
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
    pub writers: AtomicUsize,
    /// Live read-end count. Symmetric tracking so a write to a
    /// pipe with zero readers can return `Epipe`.
    pub readers: AtomicUsize,
    /// Tasks parked on a read that found the buffer empty. Woken
    /// when a write deposits bytes or when the last writer closes.
    pub(super) read_waiters:  WaitList,
    /// Tasks parked on a write that found the buffer full. Woken
    /// when a read drains bytes or when the last reader closes.
    pub(super) write_waiters: WaitList,
    capacity: AtomicUsize,
}

impl PipeData {
    pub(super) fn new(ino: Ino) -> Self {
        Self {
            buf: Spinlock::new(PipeBuf::new()),
            ino,
            writers: AtomicUsize::new(0),
            readers: AtomicUsize::new(0),
            read_waiters:  WaitList::new(),
            write_waiters: WaitList::new(),
            capacity: AtomicUsize::new(PIPE_CAP),
        }
    }

    /// Drain whatever bytes are available without blocking. Returns
    /// the byte count copied; updates wait-list state on success.
    fn try_drain(&self, buf: &mut [u8]) -> usize {
        let mut g = self.buf.lock();
        if g.len == 0 { return 0; }
        let mut n = 0;
        while n < buf.len() {
            match g.pop() {
                Some((b, packet, packet_end)) => {
                    buf[n] = b;
                    n += 1;
                    if packet {
                        if packet_end { break; }
                        if n == buf.len() {
                            while let Some((_, more_packet, more_end)) = g.pop() {
                                if !more_packet || more_end { break; }
                            }
                            break;
                        }
                    }
                }
                None => break,
            }
        }
        n
    }

    fn iov_len(bufs: &[&[u8]]) -> KResult<usize> {
        bufs.iter().try_fold(0usize, |n, buf| n.checked_add(buf.len()).ok_or(VfsError::Einval))
    }

    /// Push one scatter write while holding the ring lock. Writes no bytes when
    /// the complete PIPE_BUF-sized operation does not fit. # C: O(bytes)
    fn try_fill_iter(&self, bufs: &[&[u8]], total: usize, packetized: bool) -> usize {
        let mut g = self.buf.lock();
        let cap = self.capacity.load(Ordering::Acquire);
        if g.len >= cap { return 0; }
        if total <= PIPE_CAP && total <= cap && cap - g.len < total { return 0; }
        let mut n = 0;
        for buf in bufs {
            for &b in *buf {
                if g.len >= cap { return n; }
                let packet_end = packetized && (n + 1 == total || g.len + 1 == cap || (n + 1) % PIPE_CAP == 0);
                if !g.push(b, packetized, packet_end) { return n; }
                n += 1;
            }
        }
        n
    }

    /// Blocking ring read shared by the anonymous-pipe and named-FIFO data paths.
    /// # C: O(bytes) + park
    pub(super) fn read_blocking(&self, subs: Option<&PollSubscribers>, buf: &mut [u8]) -> KResult<usize> {
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
            // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping before scheduling.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { self.read_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; current is Sleeping until a writer wake fires.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// Blocking ring write shared by anonymous pipes and named FIFOs.
    /// # C: O(bytes) + park
    pub(super) fn write_blocking(&self, subs: Option<&PollSubscribers>, buf: &[u8], packetized: bool) -> KResult<usize> {
        self.write_iter_blocking(subs, &[buf], packetized)
    }

    /// Blocking scatter write shared by anonymous pipes and named FIFOs.
    /// # C: O(bytes) + park
    pub(super) fn write_iter_blocking(&self, subs: Option<&PollSubscribers>, bufs: &[&[u8]], packetized: bool) -> KResult<usize> {
        let total = Self::iov_len(bufs)?;
        if total == 0 { return Ok(0); }
        loop {
            if self.readers.load(Ordering::Acquire) == 0 { return Err(VfsError::Epipe); }
            let n = self.try_fill_iter(bufs, total, packetized);
            if n > 0 {
                self.read_waiters.wake_all();
                if let Some(s) = subs { s.notify(); }
                return Ok(n);
            }
            #[cfg(target_os = "oxide-kernel")]
            if sched::live::deliverable_signals_self() != 0 { return Err(VfsError::Eintr); }
            // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping before scheduling.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { self.write_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; current is Sleeping until a read-side wake fires.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }

    /// Non-blocking ring read (`O_NONBLOCK`). # C: O(bytes)
    pub(super) fn read_nb(&self, subs: Option<&PollSubscribers>, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        let n = self.try_drain(buf);
        if n > 0 {
            self.write_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
            return Ok(n);
        }
        if self.writers.load(Ordering::Acquire) == 0 { Ok(0) } else { Err(VfsError::Eagain) }
    }

    /// Non-blocking ring write (`O_NONBLOCK`). # C: O(bytes)
    pub(super) fn write_nb(&self, subs: Option<&PollSubscribers>, buf: &[u8], packetized: bool) -> KResult<usize> {
        self.write_iter_nb(subs, &[buf], packetized)
    }

    /// Non-blocking scatter write (`O_NONBLOCK`). # C: O(bytes)
    pub(super) fn write_iter_nb(&self, subs: Option<&PollSubscribers>, bufs: &[&[u8]], packetized: bool) -> KResult<usize> {
        let total = Self::iov_len(bufs)?;
        if total == 0 { return Ok(0); }
        if self.readers.load(Ordering::Acquire) == 0 { return Err(VfsError::Epipe); }
        let n = self.try_fill_iter(bufs, total, packetized);
        if n > 0 {
            self.read_waiters.wake_all();
            if let Some(s) = subs { s.notify(); }
            return Ok(n);
        }
        Err(VfsError::Eagain)
    }

    /// `poll`/`select` readiness bitmask per pipe(7). # C: O(1)
    pub(super) fn poll_mask(&self) -> u32 {
        let len = self.buf.lock().len;
        let cap = self.capacity.load(Ordering::Acquire);
        let writers = self.writers.load(Ordering::Acquire);
        let readers = self.readers.load(Ordering::Acquire);
        let mut mask = 0u32;
        if len > 0 || writers == 0 { mask |= vfs::POLL_IN; }
        if readers == 0 { mask |= vfs::POLL_HUP; }
        if len < cap && readers > 0 { mask |= vfs::POLL_OUT; }
        mask
    }

    /// Bytes currently queued for `FIONREAD`. # C: O(1)
    pub(super) fn queued_bytes(&self) -> usize { self.buf.lock().len }
}

mod ids {
    pub(super) const PIPE_INO_BASE: u64 = 0x1000_0000;
}

static NEXT_PIPE_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(ids::PIPE_INO_BASE);

/// `make_pipe_inode()` — a Fifo pseudo-inode backing both ends of an anonymous pipe. # C: O(1)
pub fn make_pipe_inode() -> InodeRef {
    let ino = NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed);
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(PipeFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(PipeData::new(ino)))
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
