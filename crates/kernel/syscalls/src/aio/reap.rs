// `io_getevents(2)` / `io_pgetevents(2)`: drain the shared ring into the
// caller's `io_event[]`, blocking until `min_nr` events exist, the timeout
// elapses, or a signal arrives.
//
// `head` is read back out of the shared page on every pass because userspace
// advances it itself when libaio reaps without entering the kernel; the tail
// is the kernel's own, never trusted from the mapping.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::aio_abi::events::{until_from_timespec, validate_reap_counts, Until};
use crate::aio_abi::ring::read_plan;
use crate::aio_abi::uapi::{IOEV_SIZE, RING_OFF_HEAD, RING_OFF_TAIL};
use crate::aio::ctx::AioContext;
use crate::poll::poll_common::{monotonic_ns, PollWaiter};
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// `struct __kernel_timespec` is two 64-bit words.
const TIMESPEC_BYTES: u64 = 16;
/// Byte offset of `tv_nsec`.
const TIMESPEC_NSEC_OFF: u64 = 8;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read the caller's relative timeout. `None` pointer means "wait forever";
/// the fields themselves are never validated.
/// # C: O(1)
pub fn read_timeout(tsp: u64) -> Result<Until, i64> {
    if tsp == 0 { return Ok(Until::Forever); }
    if validate_user_buf_readable(tsp, TIMESPEC_BYTES, 1).is_err() { return Err(err(Errno::Efault)); }
    // SAFETY: tsp validated readable for the whole 16-byte timespec below USER_VA_END; CPL=0 reads it through the caller's address space.
    let (sec, nsec) = unsafe {
        (core::ptr::read_unaligned(tsp as *const i64),
         core::ptr::read_unaligned((tsp + TIMESPEC_NSEC_OFF) as *const i64))
    };
    Ok(until_from_timespec(sec, nsec))
}

/// Copy up to `nr` queued completions into the caller's array, publishing the
/// new `head` afterwards. Returns the count delivered, or `-EFAULT` when the
/// destination cannot take them — in which case nothing is consumed, so a
/// later call can still reap.
/// # C: O(nr)
fn drain(c: &Arc<AioContext>, nr: i64, events: u64) -> i64 {
    let head = c.load_hdr(RING_OFF_HEAD);
    let tail = *c.tail.lock();
    let (chunks, new_head) = read_plan(head, tail, c.nr_events, nr);
    let total: u32 = chunks.iter().map(|&(_, n)| n).sum();
    if total == 0 { return 0; }
    let out_bytes = total as u64 * IOEV_SIZE;
    if validate_user_buf_writable(events, out_bytes, 1).is_err() { return err(Errno::Efault); }
    let mut written: u64 = 0;
    for &(start, count) in &chunks {
        let src = c.slot_kva(start);
        let dst = events + written * IOEV_SIZE;
        let bytes = count as usize * IOEV_SIZE as usize;
        // SAFETY: src spans `count` slots inside the ring run (read_plan never crosses the slot count), dst was validated writable for the whole batch; the two never overlap because one is the HHDM alias of kernel-owned frames and the other is a user array.
        unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, bytes); }
        written += count as u64;
    }
    c.store_hdr(RING_OFF_HEAD, new_head);
    c.put_reqs(total);
    total as i64
}

/// The blocking reap shared by both slots. `signalled` reports whether a
/// deliverable signal is pending, which the callers fold into their own
/// (different) interrupted return.
/// # C: O(nr + N_active x N_loop)
pub fn read_events(ctx_id: u64, min_nr: i64, nr: i64, events: u64, until: Until) -> (i64, bool) {
    let c = match crate::aio::ctx::lookup(ctx_id) { Some(c) => c, None => return (err(Errno::Einval), false) };
    if let Err(e) = validate_reap_counts(min_nr, nr) { return (err(e), false); }
    let cur = sched::live::current();
    let signalled = || cur.map(|t| t.deliverable_signals() != 0).unwrap_or(false);

    let deadline = match until {
        Until::Forever => None,
        Until::Immediate => Some(0u64),
        Until::Relative(ns) => Some(monotonic_ns().saturating_add(ns)),
    };
    // Completions — from a submit, or from a poll request's wait-queue
    // callback — notify this list, so the reaper needs no registration on the
    // polled files themselves.
    let waiter = PollWaiter::new();
    waiter.subscribe(&c.waiters);
    let mut got: i64 = 0;
    let rv = loop {
        let observed = waiter.generation();
        // Safety net for a source that emits no wake at all; the wait-queue
        // callback is what normally completes a poll request.
        crate::aio::ctx::service_ready(&c, 0);
        if got < nr {
            let r = drain(&c, nr - got, events + got as u64 * IOEV_SIZE);
            if r < 0 { break if got > 0 { got } else { r }; }
            got += r;
        }
        // Enough events, or the caller never wanted to wait.
        if got >= min_nr || matches!(until, Until::Immediate) { break got; }
        if signalled() { break got; }
        let timed_out = deadline.map(|dl| dl != 0 && monotonic_ns() >= dl).unwrap_or(false);
        if timed_out { break got; }
        // A context destroyed underneath us must not park forever.
        if crate::aio::ctx::lookup(ctx_id).is_none() { break got; }
        // SAFETY: process ctx; preempt-off across the syscall; park+yield per `13§8`.
        unsafe { waiter.park_until(observed, deadline.unwrap_or(0)); }
    };
    waiter.unsubscribe(&c.waiters);
    // The ring's tail word is the kernel's publication point; keep the shared
    // copy in step for a userspace reaper that bypasses this syscall.
    c.store_hdr(RING_OFF_TAIL, *c.tail.lock());
    (rv, signalled())
}
