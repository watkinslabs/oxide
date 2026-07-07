// Linux libaio (io_setup/io_submit/io_getevents/io_cancel/io_destroy/
// io_pgetevents — nrs 206-210,333). Mirrors the io_uring SYNCHRONOUS model:
// each iocb submitted via io_submit is executed inline through the same
// per-op work fns (pread64/pwrite64/preadv/pwritev/fsync), and its completion
// is queued immediately on the context. io_getevents therefore never has an
// in-flight request to wait on — completions are ready the moment submit
// returns.
//
// No userspace ring is mapped (unlike Linux, where io_setup mmaps an
// aio_ring): `aio_context_t` is an opaque registry key, not a pointer.
// Completions live in a kernel-side `VecDeque<IoEvent>` on the context and are
// copied out to the caller's `io_event[]` array by io_getevents.
//
// Deferred vs Linux (each honest, not a fake-success):
//   - io_cancel always returns EINVAL: every iocb completes synchronously at
//     submit, so nothing is ever in-flight to cancel (Linux itself returns
//     EINVAL for an already-complete iocb).
//   - io_getevents/io_pgetevents do not block for min_nr: no async in-flight
//     state exists to wait on; the available count is returned immediately.
//   - io_pgetevents ignores the sigmask arg (no in-kernel blocking window it
//     could guard).

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as AioLockClass};
use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

#[cfg(test)]
mod tests;

// ── struct iocb (64 bytes) field offsets — Linux `aio_abi.h`. ──────────────
const IOCB_OFF_DATA:       u64 = 0;   // aio_data       u64 — echoed to io_event.data
const IOCB_OFF_KEY:        u64 = 8;   // aio_key        u32
const IOCB_OFF_RW_FLAGS:   u64 = 12;  // aio_rw_flags   u32
const IOCB_OFF_LIO_OPCODE: u64 = 16;  // aio_lio_opcode u16
const IOCB_OFF_REQPRIO:    u64 = 18;  // aio_reqprio    i16
const IOCB_OFF_FILDES:     u64 = 20;  // aio_fildes     u32
const IOCB_OFF_BUF:        u64 = 24;  // aio_buf        u64
const IOCB_OFF_NBYTES:     u64 = 32;  // aio_nbytes     u64
const IOCB_OFF_OFFSET:     u64 = 40;  // aio_offset     i64
const IOCB_OFF_FLAGS:      u64 = 56;  // aio_flags      u32
const IOCB_OFF_RESFD:      u64 = 60;  // aio_resfd      u32
const IOCB_SIZE:           u64 = 64;

// ── struct io_event (32 bytes). ────────────────────────────────────────────
const IOEV_OFF_DATA: u64 = 0;   // data u64
const IOEV_OFF_OBJ:  u64 = 8;   // obj  u64 — user pointer to the iocb
const IOEV_OFF_RES:  u64 = 16;  // res  i64 — primary result (bytes / -errno)
const IOEV_OFF_RES2: u64 = 24;  // res2 i64 — secondary (always 0 here)
const IOEV_SIZE:     u64 = 32;

// ── aio_lio_opcode values. ─────────────────────────────────────────────────
const IOCB_CMD_PREAD:   u16 = 0;
const IOCB_CMD_PWRITE:  u16 = 1;
const IOCB_CMD_FSYNC:   u16 = 2;
const IOCB_CMD_FDSYNC:  u16 = 3;
const IOCB_CMD_PREADV:  u16 = 7;
const IOCB_CMD_PWRITEV: u16 = 8;

// ── aio_flags bits. ────────────────────────────────────────────────────────
const IOCB_FLAG_RESFD: u32 = 1 << 0;  // aio_resfd carries an eventfd to signal

/// Pointer size for the `io_submit` `iocbpp` array (array of user `*iocb`).
const PTR_SIZE: u64 = 8;

/// `-errno` in the i64 shape a syscall handler returns.
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// One queued completion — the kernel-side form of `struct io_event`.
#[derive(Clone, Copy)]
pub(crate) struct IoEvent {
    pub data: u64,
    pub obj:  u64,
    pub res:  i64,
    pub res2: i64,
}

/// One `io_setup` context. Synchronous model: `events` holds completions that
/// io_submit already produced; there is no separate in-flight set.
pub(crate) struct AioContext {
    events:     Spinlock<VecDeque<IoEvent>, AioLockClass>,
    max_events: u32,
}

impl AioContext {
    fn new(max_events: u32) -> Self {
        Self { events: Spinlock::new(VecDeque::new()), max_events }
    }
    /// Push a completion. Returns false (rejected) if the ring is full —
    /// mirrors Linux `EAGAIN` when the completion ring would overflow.
    /// # C: O(1)
    pub(crate) fn push(&self, ev: IoEvent) -> bool {
        let mut q = self.events.lock();
        if q.len() >= self.max_events as usize { return false; }
        q.push_back(ev);
        true
    }
    /// Pop up to `n` completions into a Vec. # C: O(n)
    pub(crate) fn drain(&self, n: usize) -> alloc::vec::Vec<IoEvent> {
        let mut q = self.events.lock();
        let take = core::cmp::min(n, q.len());
        (0..take).filter_map(|_| q.pop_front()).collect()
    }
    /// Queued completion count. # C: O(1)
    pub(crate) fn len(&self) -> usize { self.events.lock().len() }
}

/// Process-global context registry keyed by the opaque `aio_context_t` id.
static REG: Spinlock<BTreeMap<u64, Arc<AioContext>>, AioLockClass> = Spinlock::new(BTreeMap::new());
/// Monotonic context-id allocator (ids start at 1; 0 is reserved / invalid).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Look up a live context by id. # C: O(log N)
fn lookup(id: u64) -> Option<Arc<AioContext>> { REG.lock().get(&id).cloned() }

/// `sys_io_setup(nr_events, *ctxp)` — slot 206. Allocate a context sized for
/// `nr_events` completions, register it, write its id to `*ctxp`. Linux gate:
/// `*ctxp` must be zero on entry.
/// # C: O(log N)
pub fn sys_io_setup(args: &SyscallArgs) -> i64 {
    let nr_events = args.a0 as u32;
    let ctxp = args.a1;
    if nr_events == 0 { return err(Errno::Einval); }
    if let Err(e) = validate_user_buf_writable(ctxp, 8, 8) { return e; }
    // SAFETY: ctxp validated writable+aligned for 8 bytes below USER_VA_END; CPL=0 reads via caller's active AS to enforce the must-be-zero gate.
    let prev = unsafe { core::ptr::read_volatile(ctxp as *const u64) };
    if prev != 0 { return err(Errno::Einval); }
    let ctx = Arc::new(AioContext::new(nr_events));
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    REG.lock().insert(id, ctx);
    // SAFETY: ctxp validated writable+aligned for 8 bytes below USER_VA_END; CPL=0 writes the opaque context id back through caller's AS.
    unsafe { core::ptr::write_volatile(ctxp as *mut u64, id); }
    0
}

/// `sys_io_destroy(ctx_id)` — slot 207. Remove the context. Linux: EINVAL if
/// no such context. # C: O(log N)
pub fn sys_io_destroy(args: &SyscallArgs) -> i64 {
    let id = args.a0;
    match REG.lock().remove(&id) { Some(_) => 0, None => err(Errno::Einval) }
}

/// Invoke a per-op work fn with the iocb operand mapping
/// (`fildes,buf,nbytes,offset` → `a0,a1,a2,a3`). The work fn resolves fd→File,
/// validates the user buffer, and runs the full Linux gate chain, returning
/// bytes transferred or `-errno`. # C: one work-fn call
fn run(fd: u32, buf: u64, nbytes: u64, offset: u64, f: fn(&SyscallArgs) -> i64) -> i64 {
    let sa = SyscallArgs { a0: fd as u64, a1: buf, a2: nbytes, a3: offset, a4: 0, a5: 0 };
    f(&sa)
}

/// Invoke a vectored work fn (`preadv`/`pwritev`) with the iocb operands.
/// Unlike pread64/pwrite64 (full 64-bit offset in `a3`), the p{read,write}v
/// handlers split the offset into `pos_l`/`pos_h` on x86_64 (`a3`/`a4`) but
/// take the full offset in `a3` on aarch64 — so the offset must be packed to
/// match `offset_from_args`, else an aio PREADV past 4 GiB truncates.
/// `buf` = iovec base, `nbytes` = iovcnt. # C: one work-fn call
fn run_vectored(fd: u32, iov: u64, iovcnt: u64, offset: u64, f: fn(&SyscallArgs) -> i64) -> i64 {
    #[cfg(target_arch = "x86_64")]
    let (a3, a4) = (offset & 0xffff_ffff, offset >> 32);
    #[cfg(target_arch = "aarch64")]
    let (a3, a4) = (offset, 0u64);
    let sa = SyscallArgs { a0: fd as u64, a1: iov, a2: iovcnt, a3, a4, a5: 0 };
    f(&sa)
}

/// Execute one decoded iocb through its work fn. Unknown opcode = submit-level
/// failure (Err), matching Linux `io_submit_one` returning `-EINVAL` for a bad
/// opcode rather than queuing a completion. # C: one work-fn call
fn dispatch_iocb(opcode: u16, fd: u32, buf: u64, nbytes: u64, offset: u64) -> Result<i64, i64> {
    let res = match opcode {
        IOCB_CMD_PREAD   => run(fd, buf, nbytes, offset, crate::s017_pread64::sys_pread64),
        IOCB_CMD_PWRITE  => run(fd, buf, nbytes, offset, crate::s018_pwrite64::sys_pwrite64),
        IOCB_CMD_PREADV  => run_vectored(fd, buf, nbytes, offset, crate::s295_preadv::sys_preadv),
        IOCB_CMD_PWRITEV => run_vectored(fd, buf, nbytes, offset, crate::s296_pwritev::sys_pwritev),
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => run(fd, 0, 0, 0, crate::misc::sys_fsync),
        _ => return Err(err(Errno::Einval)),
    };
    Ok(res)
}

/// Signal the eventfd named by `aio_resfd` (+1), mirroring io_uring's
/// completion-eventfd wake so an epoll/read waiter unblocks. # C: O(1)
fn signal_resfd(resfd: u32) {
    let cur = match sched::live::current() { Some(c) => c, None => return };
    // SAFETY: running task on this CPU; preempt-off through the syscall; sole reader cloning the fd_table Arc for the resfd eventfd lookup.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return };
    if let Ok(f) = fdt.get(resfd as i32) {
        let one = 1u64.to_ne_bytes();
        let _ = f.inode().write(0, &one);
    }
}

/// `sys_io_submit(ctx_id, nr, iocbpp)` — slot 209. For each of `nr` user iocb
/// pointers: read the pointer, read the 64-byte iocb, execute it, queue the
/// completion. Return the count submitted. If the FIRST iocb fails to
/// read/validate/decode, return `-errno`; a later failure returns the count
/// submitted so far (Linux io_submit semantics). # C: O(nr)
pub fn sys_io_submit(args: &SyscallArgs) -> i64 {
    let id     = args.a0;
    let nr     = args.a1 as i64;
    let iocbpp = args.a2;
    let ctx = match lookup(id) { Some(c) => c, None => return err(Errno::Einval) };
    if nr < 0 { return err(Errno::Einval); }
    if nr == 0 { return 0; }

    let mut submitted: i64 = 0;
    for i in 0..nr as u64 {
        // Read the i-th user pointer out of the iocbpp array.
        let slot = iocbpp + i * PTR_SIZE;
        if validate_user_buf(slot, PTR_SIZE, PTR_SIZE).is_err() {
            return if submitted == 0 { err(Errno::Efault) } else { submitted };
        }
        // SAFETY: slot validated aligned+in-range below USER_VA_END; CPL=0 reads one user pointer from the iocbpp array via caller's AS.
        let iocb_ptr = unsafe { core::ptr::read_volatile(slot as *const u64) };
        if validate_user_buf(iocb_ptr, IOCB_SIZE, PTR_SIZE).is_err() {
            return if submitted == 0 { err(Errno::Efault) } else { submitted };
        }
        // Read the fields we consume from the 64-byte iocb.
        // SAFETY: iocb_ptr validated for 64 bytes below USER_VA_END; CPL=0 reads the fixed-offset ABI fields via caller's AS.
        let (data, opcode, fildes, buf, nbytes, offset, flags, resfd) = unsafe {
            (
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_DATA)       as *const u64),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_LIO_OPCODE) as *const u16),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_FILDES)     as *const u32),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_BUF)        as *const u64),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_NBYTES)     as *const u64),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_OFFSET)     as *const i64),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_FLAGS)      as *const u32),
                core::ptr::read_volatile((iocb_ptr + IOCB_OFF_RESFD)      as *const u32),
            )
        };
        // Capacity gate before doing work — Linux EAGAIN when the ring is full.
        if ctx.len() >= ctx.max_events as usize {
            return if submitted == 0 { err(Errno::Eagain) } else { submitted };
        }
        let res = match dispatch_iocb(opcode, fildes, buf, nbytes, offset as u64) {
            Ok(r)  => r,
            Err(e) => return if submitted == 0 { e } else { submitted },
        };
        if !ctx.push(IoEvent { data, obj: iocb_ptr, res, res2: 0 }) {
            return if submitted == 0 { err(Errno::Eagain) } else { submitted };
        }
        if flags & IOCB_FLAG_RESFD != 0 { signal_resfd(resfd); }
        submitted += 1;
    }
    submitted
}

/// Copy up to `nr` completions into the user `events[]` array. Shared by
/// io_getevents and io_pgetevents. Does not block for `min_nr`: synchronous
/// completion means events are already queued before this call, so the only
/// time fewer than `min_nr` exist is when nothing was submitted — return the
/// available count immediately. # C: O(nr)
fn getevents_common(id: u64, nr: i64, events: u64) -> i64 {
    let ctx = match lookup(id) { Some(c) => c, None => return err(Errno::Einval) };
    if nr < 0 { return err(Errno::Einval); }
    if nr == 0 { return 0; }
    // Validate the output array for the events we will actually deliver BEFORE
    // dequeuing, so a bad user pointer returns EFAULT without losing queued
    // completions (a later io_getevents can still reap them).
    let want = core::cmp::min(nr as usize, ctx.len());
    if want == 0 { return 0; }
    let out_bytes = (want as u64) * IOEV_SIZE;
    if let Err(e) = validate_user_buf_writable(events, out_bytes, 8) { return e; }
    let batch = ctx.drain(want);
    for (i, ev) in batch.iter().enumerate() {
        let base = events + i as u64 * IOEV_SIZE;
        // SAFETY: events validated writable for batch.len()*32 bytes below USER_VA_END; CPL=0 writes one io_event's four ABI fields via caller's AS.
        unsafe {
            core::ptr::write_volatile((base + IOEV_OFF_DATA) as *mut u64, ev.data);
            core::ptr::write_volatile((base + IOEV_OFF_OBJ)  as *mut u64, ev.obj);
            core::ptr::write_volatile((base + IOEV_OFF_RES)  as *mut i64, ev.res);
            core::ptr::write_volatile((base + IOEV_OFF_RES2) as *mut i64, ev.res2);
        }
    }
    batch.len() as i64
}

/// `sys_io_getevents(ctx_id, min_nr, nr, events, timeout)` — slot 208.
/// `timeout` ignored (no in-flight state to wait on). # C: O(nr)
pub fn sys_io_getevents(args: &SyscallArgs) -> i64 {
    getevents_common(args.a0, args.a2 as i64, args.a3)
}

/// `sys_io_pgetevents(ctx_id, min_nr, nr, events, timeout, sigset)` — slot 333.
/// Same as io_getevents; `timeout` and `sigset` ignored (no blocking window to
/// guard). # C: O(nr)
pub fn sys_io_pgetevents(args: &SyscallArgs) -> i64 {
    getevents_common(args.a0, args.a2 as i64, args.a3)
}

/// `sys_io_cancel(ctx_id, iocb, result)` — slot 210. Every iocb completes
/// synchronously at submit, so none is ever in-flight → EINVAL, matching Linux
/// for an already-complete / non-cancellable iocb. `ctx_id` is still validated
/// so a bogus context is EINVAL too. # C: O(log N)
pub fn sys_io_cancel(args: &SyscallArgs) -> i64 {
    let _ = lookup(args.a0);
    err(Errno::Einval)
}
