// Eventfd (`24§3`, Linux eventfd(2)) — counter-based blocking primitive
// backing `sys_eventfd2`. Split out of `pipe.rs` (`08§7` file-length cap):
// the counter is unrelated to the byte-ring FIFO/anon-pipe core in
// `ring.rs`, so `pipe.rs` stays a manifest for the FIFO/anon-pipe surface.
//
// B1422: the counter lives behind `EventfdGate` (a `Spinlock<u64, _>`), not a
// bare `AtomicU64` CASed lock-free. A blocking `read` that found the counter
// 0 used to check-then-`park()` with no lock held across both steps, while
// `write` mutated the counter and called `wake_all()` lock-free — the
// classic lost wakeup: if the write's CAS+wake_all landed between the read
// seeing zero and the read's `park()`, the wait list was still empty, the
// wake was dropped, and the reader parked forever. Now "counter==0 → enqueue
// on read_waiters" is ONE critical section over `EventfdGate`, and `write`
// takes the SAME lock to bump the counter before it wakes — same shape as
// `sched::live::Mutex::lock` / `net::unix_sock::listener::arm_accept_wait`.
// A blocking WRITE that finds no capacity uses the mirror of that protocol on
// `write_waiters`, woken by the read that frees the capacity.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::Spinlock;
use vfs::{FileType, Inode, InodeRef, KResult, VfsError};
use vfs::{FileOps, InodeBuilder, PollSubscribers, default_inode_ops, mk_mode};

use super::super::WaitList;
use super::counter::{self, EVENTFD_RECORD};

/// `Inode`-backed eventfd counter per `24§3` + Linux eventfd(2).
/// Read drains the counter to a u64; write adds to it. A BLOCKING read on a
/// zero counter PARKS on `read_waiters` until a write makes it non-zero (Linux
/// eventfd(2) blocks; a non-blocking read returns EAGAIN — NEVER EINVAL). The
/// counter lives in `i_private`.
pub struct EventfdData {
    counter: Spinlock<u64, EventfdGate>,
    semaphore: bool,
    /// `eventfd-id` as `fdinfo` reports it — the allocation ordinal, not the
    /// inode number.
    id: u32,
    /// Tasks parked in a blocking `read` that found the counter 0; woken by
    /// `write`.
    read_waiters: WaitList,
    /// Tasks parked in a blocking `write` whose value did not fit; woken by
    /// the `read` that frees capacity.
    write_waiters: WaitList,
}

/// Gates an eventfd's counter (`06§3.6`). Held only to decide "act now or
/// park" — the same shape as `sched::live::Mutex`'s `MutexGate`: the park
/// enqueues on a wait list (`TaskList`, rank 100) while holding this, so it
/// ranks strictly below that, and is never held across `schedule()` itself.
struct EventfdGate;
impl sync::LockClass for EventfdGate { fn rank() -> u16 { 94 } fn name() -> &'static str { "EventfdGate" } }

mod ids {
    pub(crate) const EVENTFD_INO_BASE: u64 = 0x4000_0000;
}

static NEXT_EVENTFD_INO: core::sync::atomic::AtomicU64
    = core::sync::atomic::AtomicU64::new(ids::EVENTFD_INO_BASE);

/// `make_eventfd_inode(initial, semaphore)` — a Fifo pseudo-inode whose counter
/// drains on read and accumulates on write. # C: O(1)
pub fn make_eventfd_inode(initial: u64, semaphore: bool) -> InodeRef {
    let ino = NEXT_EVENTFD_INO.fetch_add(1, Ordering::Relaxed);
    InodeBuilder::new(ino, mk_mode(FileType::Fifo, 0), default_inode_ops(), Arc::new(EventfdFileOps))
        .poll_subs(PollSubscribers::new())
        .private(Arc::new(EventfdData {
            counter: Spinlock::new(initial),
            semaphore,
            id: (ino - ids::EVENTFD_INO_BASE) as u32,
            read_waiters: WaitList::new(),
            write_waiters: WaitList::new(),
        }))
        .build()
}

/// Whether an inode really is an eventfd. `eventfd_ctx_fdget` answers EINVAL —
/// not EBADF — for a live fd whose file is something else, so any caller that
/// takes an eventfd as a parameter (aio `IOCB_FLAG_RESFD`) needs this to
/// separate the two verdicts. Identity comes from the private counter object,
/// not the ino: ino ranges are per-filesystem and would alias.
/// # C: O(1)
pub fn is_eventfd(inode: &InodeRef) -> bool { inode.private::<EventfdData>().is_some() }

/// `i_fop` for an eventfd inode. # C: O(1)
struct EventfdFileOps;
impl FileOps for EventfdFileOps {
    /// POLLIN when the counter is nonzero, POLLOUT while a write can still
    /// fit, POLLERR once the counter sits at its overflow sentinel. Default
    /// always-ready poll busy-looped an sd-event epoll — see signalfd::poll.
    /// # C: O(1)
    fn poll(&self, inode: &Inode) -> u32 {
        let v = match inode.private::<EventfdData>() { Some(d) => *d.counter.lock(), None => return 0 };
        counter::poll_mask(v)
    }
    /// BLOCKING read (Linux eventfd(2)): drain the counter; if it is 0, PARK
    /// until a write makes it non-zero (interruptible by a deliverable signal →
    /// ERESTARTSYS). NEVER EINVAL on an empty counter — that broke a
    /// `setup_private_users` helper whose blocking `read(unshare_ready_fd)`
    /// barrier got EINVAL and reported it to the executor.
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < EVENTFD_RECORD { return Err(VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        loop {
            if let Some(v) = try_drain(d) { return Ok(finish_read(inode, d, v, buf)); }
            #[cfg(target_os = "oxide-kernel")]
            {
                // ONE critical section covers "counter is zero" and the park
                // enqueue: `write` takes this SAME counter lock to bump the
                // counter before it wakes (see `write` below), so a
                // concurrent bump+wake_all can never land between "we saw
                // zero" and "we're on the wait list" (B1422).
                let g = d.counter.lock();
                if *g != 0 { drop(g); continue; }
                if sched::live::deliverable_signals_self() != 0 {
                    drop(g);
                    return Err(VfsError::Erestartsys);
                }
                // SAFETY: running task; preempt-off; park bumps the Arc +
                // marks Sleeping while we still hold the counter lock, so a
                // racing write's bump+wake_all cannot land between this
                // recheck and our enqueue.
                unsafe { d.read_waiters.park(); }
                drop(g);
                // SAFETY: process ctx; runqueue installed; preempt-off;
                // Sleeping so schedule won't re-enqueue until a write wakes
                // us. Counter lock already dropped above, before schedule.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }
    /// Non-blocking read (O_NONBLOCK): EAGAIN on an empty counter (Linux), not
    /// EINVAL and not a park.
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < EVENTFD_RECORD { return Err(VfsError::Einval); }
        let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        match try_drain(d) {
            Some(v) => Ok(finish_read(inode, d, v, buf)),
            None => Err(VfsError::Eagain),
        }
    }
    /// BLOCKING write: park on `write_waiters` until the value fits, rather
    /// than reporting EAGAIN on a description that never asked for it.
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let (d, add) = decode_write(inode, buf)?;
        loop {
            if try_add(d, add) { return Ok(finish_write(inode, d)); }
            #[cfg(target_os = "oxide-kernel")]
            {
                // Mirror of the read gate: recheck capacity and enqueue on
                // `write_waiters` inside ONE critical section, so the read
                // that frees capacity cannot wake an empty list.
                let g = d.counter.lock();
                if counter::write_fits(*g, add) { drop(g); continue; }
                if sched::live::deliverable_signals_self() != 0 {
                    drop(g);
                    return Err(VfsError::Erestartsys);
                }
                // SAFETY: running task; preempt-off; the park publishes
                // Sleeping while the counter lock is still held, so a racing
                // read's drain+wake cannot land in the gap.
                unsafe { d.write_waiters.park(); }
                drop(g);
                // SAFETY: process ctx; runqueue installed; Sleeping until a
                // read frees capacity. Counter lock dropped before schedule.
                unsafe { sched::live::schedule::schedule(); }
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            return Err(VfsError::Eagain);
        }
    }
    /// Non-blocking write (O_NONBLOCK): EAGAIN when the value does not fit.
    fn write_nonblock(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let (d, add) = decode_write(inode, buf)?;
        if try_add(d, add) { Ok(finish_write(inode, d)) } else { Err(VfsError::Eagain) }
    }
    /// `show_fdinfo`: counter, allocation id, semaphore mode. # C: O(1)
    fn fdinfo_extra(&self, inode: &Inode, out: &mut Vec<u8>) {
        let Some(d) = inode.private::<EventfdData>() else { return };
        let count = *d.counter.lock();
        out.extend_from_slice(b"eventfd-count: ");
        push_hex_width16(out, count);
        out.extend_from_slice(b"\neventfd-id: ");
        push_dec(out, d.id as u64);
        out.extend_from_slice(b"\neventfd-semaphore: ");
        out.push(if d.semaphore { b'1' } else { b'0' });
        out.push(b'\n');
    }
}

/// Validate a write's shape and value before any counter is touched:
/// wrong length → EINVAL, sentinel value → EINVAL. # C: O(1)
fn decode_write<'a>(inode: &'a Inode, buf: &[u8]) -> KResult<(&'a EventfdData, u64)> {
    if buf.len() != EVENTFD_RECORD { return Err(VfsError::Einval); }
    let d = match inode.private::<EventfdData>() { Some(d) => d, None => return Err(VfsError::Einval) };
    let mut a = [0u8; EVENTFD_RECORD];
    a.copy_from_slice(buf);
    let add = u64::from_ne_bytes(a);
    if !counter::write_value_valid(add) { return Err(VfsError::Einval); }
    Ok((d, add))
}

/// Publish a completed read: emit the value, wake a blocked writer, poke poll.
/// # C: O(waiters)
fn finish_read(inode: &Inode, d: &EventfdData, v: u64, buf: &mut [u8]) -> usize {
    buf[..EVENTFD_RECORD].copy_from_slice(&v.to_ne_bytes());
    // A read always frees capacity, so a writer parked for room can proceed.
    d.write_waiters.wake_all();
    if let Some(s) = inode.poll_subscribers() { s.notify(); }
    EVENTFD_RECORD
}

/// Publish a completed write: wake a blocked reader, poke poll. Waking runs
/// AFTER the counter lock is dropped (matches `Mutex::unlock`): the woken
/// reader's first act is to take the SAME lock, so waking under it would just
/// make it spin on us. # C: O(waiters)
fn finish_write(inode: &Inode, d: &EventfdData) -> usize {
    d.read_waiters.wake_all();
    if let Some(s) = inode.poll_subscribers() { s.notify(); }
    EVENTFD_RECORD
}

/// Drain the counter without blocking, under the gate. `None` when zero
/// (caller EAGAINs or parks). # C: O(1)
fn try_drain(d: &EventfdData) -> Option<u64> {
    let mut g = d.counter.lock();
    let (transferred, remaining) = counter::do_read(*g, d.semaphore)?;
    *g = remaining;
    Some(transferred)
}

/// Add `add` under the gate when it fits. `false` = no capacity (caller
/// EAGAINs or parks). # C: O(1)
fn try_add(d: &EventfdData, add: u64) -> bool {
    let mut g = d.counter.lock();
    if !counter::write_fits(*g, add) { return false; }
    *g += add;
    true
}

/// Lowercase hex right-aligned in a 16-column field — the width `fdinfo`
/// states for `eventfd-count`, space-padded rather than zero-padded.
/// # C: O(1)
fn push_hex_width16(out: &mut Vec<u8>, v: u64) {
    let mut digits = [0u8; 16];
    let mut n = 0;
    let mut v = v;
    loop {
        let nib = (v & 0xf) as u8;
        digits[n] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
        v >>= 4; n += 1;
        if v == 0 { break }
    }
    for _ in n..16 { out.push(b' '); }
    for i in (0..n).rev() { out.push(digits[i]); }
}

/// Unpadded decimal. # C: O(digits)
fn push_dec(out: &mut Vec<u8>, v: u64) {
    let mut digits = [0u8; 20];
    let mut n = 0;
    let mut v = v;
    loop { digits[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; if v == 0 { break } }
    for i in (0..n).rev() { out.push(digits[i]); }
}

#[cfg(test)]
mod tests;
