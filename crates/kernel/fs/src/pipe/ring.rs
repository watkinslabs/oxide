use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use sync::{Spinlock, Tty as TtyClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use vfs::{InodeBuilder, PollSubscribers, default_inode_ops, mk_mode};

use vfs::pipe_limits;
use super::limits::{round_pipe_size, PIPE_BUF, PIPE_GROW_STEP};
use super::{PipeFileOps, WaitList};

#[cfg(test)]
mod tests;

/// What ends a blocking write that ran out of room and has to wait.
///
/// A `write(2)` gives up as soon as ANY signal is deliverable, so the C library
/// can restart it after the handler runs. The thread writing a core dump cannot
/// use that rule: it is already inside the delivery of the signal that killed
/// it, so "a signal is deliverable" is permanently true and the very first wait
/// would abandon the dump. It stops only for a kill it cannot survive, which is
/// what makes a dump larger than the ring reach its destination at all.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WriteAbort {
    /// Ordinary `write(2)`: any deliverable signal ends the wait.
    OnDeliverableSignal,
    /// The core dumper: only an unsurvivable kill ends the wait.
    OnFatalKill,
}

pub(super) struct PipeBuf {
    /// Backing store, grown on demand up to `cap`. Its length is what the ring
    /// indices wrap on; `cap` is only the ceiling it may grow to.
    pub(super) data: Vec<u8>,
    pub(super) packet: Vec<bool>,
    pub(super) packet_end: Vec<bool>,
    pub(super) head: usize,
    pub(super) tail: usize,
    pub(super) len:  usize,
    /// `F_GETPIPE_SZ`: how many bytes this pipe may hold.
    pub(super) cap:  usize,
}

impl PipeBuf {
    fn new(cap: usize) -> Self {
        Self { data: Vec::new(), packet: Vec::new(), packet_end: Vec::new(),
            head: 0, tail: 0, len: 0, cap }
    }

    /// Next ring index after `i`. Wraps on the ALLOCATED length, not on the
    /// capacity — an unfilled pipe holds fewer bytes than it may grow to.
    /// # C: O(1)
    pub(super) fn next_idx(&self, i: usize) -> usize {
        if i + 1 >= self.data.len() { 0 } else { i + 1 }
    }

    /// Rotate the queued bytes to the front so the backing store can be
    /// extended without the new slots landing inside the queue.
    fn normalize(&mut self) {
        if self.head == 0 { return; }
        self.data.rotate_left(self.head);
        self.packet.rotate_left(self.head);
        self.packet_end.rotate_left(self.head);
        self.head = 0;
        self.tail = if self.len >= self.data.len() { 0 } else { self.len };
    }

    /// Extend the backing store by one allocation unit. False when the pipe is
    /// already at its capacity or the memory is not there — either way the
    /// caller treats it as a full ring and waits.
    fn grow(&mut self) -> bool {
        let cur = self.data.len();
        if cur >= self.cap { return false; }
        let want = (cur + PIPE_GROW_STEP).min(self.cap);
        let add = want - cur;
        if self.data.try_reserve_exact(add).is_err() { return false; }
        if self.packet.try_reserve_exact(add).is_err() { return false; }
        if self.packet_end.try_reserve_exact(add).is_err() { return false; }
        self.normalize();
        self.data.resize(want, 0);
        self.packet.resize(want, false);
        self.packet_end.resize(want, false);
        self.tail = self.len;
        true
    }

    pub(super) fn push(&mut self, b: u8, packet: bool, packet_end: bool) -> bool {
        if self.len >= self.cap { return false; }
        if self.len >= self.data.len() && !self.grow() { return false; }
        self.data[self.tail] = b;
        self.packet[self.tail] = packet;
        self.packet_end[self.tail] = packet_end;
        self.tail = self.next_idx(self.tail);
        self.len += 1;
        true
    }

    pub(super) fn pop(&mut self) -> Option<(u8, bool, bool)> {
        if self.len == 0 { return None; }
        let b = self.data[self.head];
        let packet = self.packet[self.head];
        let packet_end = self.packet_end[self.head];
        self.packet[self.head] = false;
        self.packet_end[self.head] = false;
        self.head = self.next_idx(self.head);
        self.len -= 1;
        Some((b, packet, packet_end))
    }
}

/// `Inode`-backed anonymous pipe state (Linux `i_private`). One instance is
/// shared by both the read-end and the write-end `File` wrappers.
pub struct PipeData {
    pub(super) buf: Spinlock<PipeBuf, TtyClass>,
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
    /// Account this ring's pages are charged to, and how many are charged.
    /// Both halves live here so the release on teardown cannot be booked
    /// against a different user than the charge was.
    pub(super) owner_uid: u32,
    pub(super) accounted: AtomicUsize,
}

impl PipeData {
    /// Allocate a ring, charging its pages to the running task's account.
    ///
    /// The size is whatever the per-user ladder allows: the default, the
    /// minimum once the owner is past the soft limit, and no pipe at all once
    /// it is past the hard limit — which is `ENOMEM`, the same refusal the
    /// reference's failed ring allocation produces. # C: O(N_users)
    pub(super) fn try_new(ino: Ino) -> Result<Self, VfsError> {
        let (uid, caps) = super::acct::current_account();
        let pages = pipe_limits::alloc_pages(pipe_limits::charged(uid), caps)
            .ok_or(VfsError::Enomem)?;
        pipe_limits::account(uid, 0, pages);
        Ok(Self {
            buf: Spinlock::new(PipeBuf::new(pages as usize * pipe_limits::PIPE_PAGE_BYTES as usize)),
            ino,
            writers: AtomicUsize::new(0),
            readers: AtomicUsize::new(0),
            read_waiters:  WaitList::new(),
            write_waiters: WaitList::new(),
            owner_uid: uid,
            accounted: AtomicUsize::new(pages as usize),
        })
    }

    /// Drain whatever bytes are available into `buf`, given the ring lock
    /// already held. Split out of `try_drain` so `read_blocking` can run the
    /// SAME drain inside the single critical section it uses for the
    /// recheck-then-park decision (B1422). # C: O(bytes)
    fn drain_locked(g: &mut PipeBuf, buf: &mut [u8]) -> usize {
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

    /// Drain whatever bytes are available without blocking. Returns
    /// the byte count copied; updates wait-list state on success.
    fn try_drain(&self, buf: &mut [u8]) -> usize {
        let mut g = self.buf.lock();
        if g.len == 0 { return 0; }
        Self::drain_locked(&mut g, buf)
    }

    fn iov_len(bufs: &[&[u8]]) -> KResult<usize> {
        bufs.iter().try_fold(0usize, |n, buf| n.checked_add(buf.len()).ok_or(VfsError::Einval))
    }

    /// Push one scatter write while holding the ring lock. Writes no bytes when
    /// the complete `PIPE_BUF`-sized operation does not fit, which is the POSIX
    /// atomicity guarantee: a write of at most `PIPE_BUF` bytes is never split
    /// across another writer's bytes. # C: O(bytes)
    fn try_fill_iter(&self, bufs: &[&[u8]], total: usize, packetized: bool) -> usize {
        let mut g = self.buf.lock();
        let cap = g.cap;
        if g.len >= cap { return 0; }
        if total <= PIPE_BUF && total <= cap && cap - g.len < total { return 0; }
        let mut n = 0;
        for buf in bufs {
            for &b in *buf {
                if g.len >= cap { return n; }
                let packet_end = packetized && (n + 1 == total || g.len + 1 == cap || (n + 1) % PIPE_BUF == 0);
                if !g.push(b, packetized, packet_end) { return n; }
                n += 1;
            }
        }
        n
    }

    /// Blocking ring read shared by the anonymous-pipe and named-FIFO data paths.
    ///
    /// B1422: "is there data" and the park enqueue are ONE critical section
    /// over `self.buf` — a concurrent write takes this SAME lock to push
    /// bytes before it wakes (`write_iter_blocking`/`try_fill_iter`: mutate
    /// under lock, drop, then wake), so its push+wake can never land between
    /// "we saw empty" and "we're on the wait list". Same shape as
    /// `sched::live::Mutex::lock` / `net::unix_sock::listener::arm_accept_wait`.
    /// # C: O(bytes) + park
    pub(super) fn read_blocking(&self, subs: Option<&PollSubscribers>, buf: &mut [u8]) -> KResult<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            let mut g = self.buf.lock();
            if g.len != 0 {
                let n = Self::drain_locked(&mut g, buf);
                drop(g);
                self.write_waiters.wake_all();
                if let Some(s) = subs { s.notify(); }
                return Ok(n);
            }
            if self.writers.load(Ordering::Acquire) == 0 { return Ok(0); }
            #[cfg(target_os = "oxide-kernel")]
            {
                // A read that has copied nothing returns straight out on a
                // deliverable signal, having done every wakeup it owed.
                if sched::live::deliverable_signals_self() != 0 {
                    return Err(VfsError::Erestartsys);
                }
                // SAFETY: running task; preempt-off; park bumps the Arc + marks
                // Sleeping while we still hold the ring lock, so a racing
                // write's push+wake_all cannot land between this recheck and
                // our enqueue.
                unsafe { self.read_waiters.park(); }
            }
            drop(g);
            // SAFETY: process ctx; runqueue installed; preempt-off; current is
            // Sleeping until a writer wake fires. Ring lock already dropped
            // above, before schedule.
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
        self.write_iter_abort(subs, bufs, packetized, WriteAbort::OnDeliverableSignal)
    }

    /// Blocking scatter write with an explicit rule for what ends the wait.
    /// # C: O(bytes) + park
    pub(super) fn write_iter_abort(&self, subs: Option<&PollSubscribers>, bufs: &[&[u8]],
                                   packetized: bool, abort: WriteAbort) -> KResult<usize> {
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
            // A write that has placed no bytes reports the interruption; the
            // dumper's rule keeps it waiting for room instead.
            if write_wait_aborted(abort, sched::live::deliverable_signals_self() != 0,
                                  sched::live::fatal_kill_pending_self(), sched::live::frozen_self()) {
                return Err(VfsError::Erestartsys);
            }
            // SAFETY: running task; preempt-off; park bumps the Arc + marks Sleeping before scheduling.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { self.write_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; current is Sleeping until a read-side wake fires.
            #[cfg(target_os = "oxide-kernel")]
            unsafe { sched::live::schedule::schedule(); }
            #[cfg(not(target_os = "oxide-kernel"))]
            { let _ = abort; return Err(VfsError::Eagain); }
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
        let (len, cap) = { let g = self.buf.lock(); (g.len, g.cap) };
        let writers = self.writers.load(Ordering::Acquire);
        let readers = self.readers.load(Ordering::Acquire);
        let mut mask = 0u32;
        if len > 0 || writers == 0 { mask |= vfs::POLL_IN; }
        if readers == 0 { mask |= vfs::POLL_HUP; }
        if len < cap && readers > 0 { mask |= vfs::POLL_OUT; }
        mask
    }

    /// Enqueue the running task on this pipe's read wait list without
    /// scheduling. The caller holds whatever lock makes its "nothing to read"
    /// observation atomic with this enqueue, and schedules once that lock is
    /// dropped. # C: O(1)
    ///
    /// # Safety
    /// Process context, preemption off, and the caller MUST schedule after
    /// dropping its lock — a task marked Sleeping that never schedules would
    /// keep running with the wrong state.
    #[cfg(target_os = "oxide-kernel")]
    pub unsafe fn arm_read_wait(&self) {
        // SAFETY: forwarded from this function's own contract — process context, preempt-off, caller schedules next.
        unsafe { self.read_waiters.park(); }
    }

    /// Bytes currently queued for `FIONREAD`. # C: O(1)
    pub(super) fn queued_bytes(&self) -> usize { self.buf.lock().len }

    /// Bytes this pipe may hold (`F_GETPIPE_SZ`). # C: O(1)
    pub fn capacity(&self) -> usize { self.buf.lock().cap }

    /// Park until every reader has closed its end.
    ///
    /// The core dumper uses this to keep the crashing process alive until the
    /// helper it fed has finished, so the helper can still read `/proc/<pid>`
    /// of the process whose dump it is holding. The check runs AFTER the park
    /// enqueue, and a close observed in the window between them un-parks us, so
    /// a reader that closes while we are arming cannot leave us asleep.
    /// # C: O(1) + park
    #[cfg(target_os = "oxide-kernel")]
    pub fn wait_for_readers_gone(&self) {
        while self.readers.load(Ordering::Acquire) != 0 {
            if sched::live::fatal_kill_pending_self() { return; }
            // SAFETY: running task; preempt-off; park bumps the Arc and marks the task Sleeping before the recheck below.
            unsafe { self.write_waiters.park(); }
            if self.readers.load(Ordering::Acquire) == 0 { self.write_waiters.cancel_current_park(); }
            // SAFETY: process ctx; runqueue installed; current is Sleeping until the last reader's close wakes the write side.
            unsafe { sched::live::schedule::schedule(); }
        }
    }
}

/// Whether a blocking write that found no room gives up now.
fn write_wait_aborted(abort: WriteAbort, deliverable_signal: bool, fatal_kill: bool, frozen: bool) -> bool {
    match abort {
        WriteAbort::OnDeliverableSignal => deliverable_signal,
        WriteAbort::OnFatalKill => fatal_kill || frozen,
    }
}

/// Pipe inode numbers come out of the one range `vfs::pseudo_ino` reserves for
/// them, and wrap inside it rather than counting on into the next owner's.
static NEXT_PIPE_INO: vfs::pseudo_ino::RegionAllocator
    = vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::PIPE);

/// `make_pipe_inode()` — a Fifo pseudo-inode backing both ends of an anonymous
/// pipe. `ENOMEM` once the owner's pipe pages are past the hard limit.
/// # C: O(N_users)
pub fn make_pipe_inode() -> KResult<InodeRef> {
    let ino = NEXT_PIPE_INO.alloc();
    Ok(InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(PipeFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(PipeData::try_new(ino)?))
        .build())
}

/// Recover the `PipeData` behind a pipe inode. # C: O(1)
pub fn pipe_data(inode: &Inode) -> Option<&PipeData> { inode.private::<PipeData>() }

/// `fcntl(F_GETPIPE_SZ)`. # C: O(1)
pub fn pipe_size(inode: &Inode) -> Option<usize> { pipe_data(inode).map(|p| p.capacity()) }

/// `fcntl(F_SETPIPE_SZ)`.
///
/// The request is rounded UP to whole allocation units, so the size reported
/// back is never smaller than what was asked for. A request past the tunable
/// ceiling is refused rather than clamped, and a request below what is already
/// queued is `EBUSY` — shrinking a pipe may not discard bytes a reader has not
/// collected. # C: O(1)
pub fn set_pipe_size(inode: &Inode, requested: usize) -> Result<usize, VfsError> {
    let p = pipe_data(inode).ok_or(VfsError::Einval)?;
    let new_cap = round_pipe_size(requested);
    let new_pages = (new_cap / pipe_limits::PIPE_PAGE_BYTES as usize) as i64;
    let old_pages = p.accounted.load(Ordering::Acquire) as i64;
    let (_, caps) = super::acct::current_account();
    pipe_limits::resize_ok(old_pages, new_pages, pipe_limits::charged(p.owner_uid), caps)?;
    let mut g = p.buf.lock();
    if new_cap < g.len { return Err(VfsError::Ebusy); }
    g.cap = new_cap;
    drop(g);
    pipe_limits::account(p.owner_uid, old_pages, new_pages);
    p.accounted.store(new_pages as usize, Ordering::Release);
    Ok(new_cap)
}

/// Move a pipe's page charge to `new_pages` on behalf of a subsystem that
/// reserves memory against the pipe without changing the byte ring — the
/// notification queue's depth. Refused with `EPERM` on the same rungs a
/// `F_SETPIPE_SZ` growth is, and a refusal leaves the account untouched.
/// # C: O(N_users)
pub fn charge_pipe_pages(inode: &Inode, new_pages: i64) -> Result<(), VfsError> {
    let p = pipe_data(inode).ok_or(VfsError::Einval)?;
    let old_pages = p.accounted.load(Ordering::Acquire) as i64;
    let (_, caps) = super::acct::current_account();
    pipe_limits::resize_ok(old_pages, new_pages, pipe_limits::charged(p.owner_uid), caps)?;
    pipe_limits::account(p.owner_uid, old_pages, new_pages);
    p.accounted.store(new_pages as usize, Ordering::Release);
    Ok(())
}

/// Release the ring's page charge with the ring itself (`free_pipe_info`).
impl Drop for PipeData {
    fn drop(&mut self) {
        pipe_limits::account(self.owner_uid, self.accounted.load(Ordering::Acquire) as i64, 0);
    }
}

/// Push `buf` into a pipe on behalf of the core dumper: the wait for room ends
/// only on an unsurvivable kill, never on the fatal signal already being
/// delivered to the crashing thread. # C: O(bytes) + park
pub fn write_dump(inode: &Inode, buf: &[u8]) -> KResult<usize> {
    let p = pipe_data(inode).ok_or(VfsError::Einval)?;
    p.write_iter_abort(inode.poll_subscribers(), &[buf], false, WriteAbort::OnFatalKill)
}
