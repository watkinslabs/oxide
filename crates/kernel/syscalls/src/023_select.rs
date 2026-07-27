// 023 select — one syscall, one file (docs/53 §0). Moved verbatim from select.rs.
#![cfg(any(target_os = "oxide-kernel", test))]

extern crate alloc;
use alloc::sync::Arc;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::poll::poll_common::monotonic_ns;
use crate::pselect_ppoll::{TimeoutWriteback, copies_out_fd_sets, finish_return, remaining_timespec,
                           timeout_writeback_plan, wait_verdict};
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> {
    #[cfg(test)]
    {
        let p = TEST_CURRENT.load(core::sync::atomic::Ordering::Acquire);
        if p != 0 {
            // SAFETY: ownership tests leak the Task and clear this pointer only after the syscall returns.
            return Some(unsafe { &*(p as *const sched::Task) });
        }
    }
    sched::current()
}

#[cfg(test)]
static TEST_CURRENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static POST_SNAPSHOT_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
/// Install the hosted task used by ownership schedules. # C: O(1)
pub(crate) fn set_test_current(task: Option<&'static sched::Task>) {
    TEST_CURRENT.store(task.map_or(0, |t| t as *const sched::Task as usize), core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
/// Install the one-shot post-snapshot schedule hook. # C: O(1)
pub(crate) fn set_post_snapshot_hook(hook: Option<fn()>) {
    POST_SNAPSHOT_HOOK.store(hook.map_or(0, |f| f as usize), core::sync::atomic::Ordering::Release);
}

#[cfg(test)]
fn run_post_snapshot_hook() {
    let p = POST_SNAPSHOT_HOOK.swap(0, core::sync::atomic::Ordering::AcqRel);
    if p != 0 {
        // SAFETY: set_post_snapshot_hook stores only a `fn()` pointer and swap gives this call sole use.
        let hook: fn() = unsafe { core::mem::transmute(p) };
        hook();
    }
}

const FDSET_BITS_PER_WORD: u64 = 64;
const FDSET_WORD_BYTES: u64 = 8;
/// `sizeof(struct __kernel_old_timeval)` — `{ i64 tv_sec, i64 tv_usec }`.
/// Same width as pselect6's timespec, different unit in the second field.
const TIMEVAL_BYTES: u64 = 16;
/// Byte offset of `tv_usec` inside `struct __kernel_old_timeval`.
const TIMEVAL_USEC_OFF: u64 = 8;
const USEC_PER_SEC: i64 = 1_000_000;
const NSEC_PER_USEC: i64 = 1_000;

struct SelectedFile {
    fd: u64,
    file: Arc<vfs::File>,
    read: bool,
    write: bool,
    except: bool,
}

fn fdset_bytes(nfds: u64) -> u64 {
    ((nfds + FDSET_BITS_PER_WORD - 1) / FDSET_BITS_PER_WORD) * FDSET_WORD_BYTES
}

fn timeval_from_user(p: u64) -> Result<(i64, i64), i64> {
    validate_user_buf_readable(p, TIMEVAL_BYTES, 1)?;
    // SAFETY: p validated readable for the 16-byte timeval.
    let s = unsafe { core::ptr::read_unaligned(p as *const i64) };
    // SAFETY: p+TIMEVAL_USEC_OFF lies inside the validated 16-byte timeval.
    let u = unsafe { core::ptr::read_unaligned((p + TIMEVAL_USEC_OFF) as *const i64) };
    Ok((s, u))
}

fn copy_fdset_from_user(p: u64, len: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    let mut out = alloc::vec![0u8; len as usize];
    if p == 0 || len == 0 { return Ok(out); }
    validate_user_buf_readable(p, len, 1)?;
    // SAFETY: p validated readable for len bytes; out has len bytes.
    unsafe { core::ptr::copy_nonoverlapping(p as *const u8, out.as_mut_ptr(), len as usize); }
    Ok(out)
}

fn copy_fdset_to_user(p: u64, buf: &[u8]) -> Result<(), i64> {
    if p == 0 || buf.is_empty() { return Ok(()); }
    validate_user_buf_writable(p, buf.len() as u64, 1)?;
    // SAFETY: p validated writable for buf.len() bytes; source is a live slice.
    unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), p as *mut u8, buf.len()); }
    Ok(())
}

fn bit_at(buf: &[u8], i: u64) -> bool {
    let byte_off = (i / 8) as usize;
    if byte_off >= buf.len() { return false; }
    (buf[byte_off] & (1u8 << (i & 7))) != 0
}

fn set_bit_buf(buf: &mut [u8], i: u64) {
    let byte_off = (i / 8) as usize;
    if byte_off < buf.len() { buf[byte_off] |= 1u8 << (i & 7); }
}

fn snapshot_selected(fdt: &vfs::FdTable, nfds: u64, read: &[u8], write: &[u8],
                     except: &[u8]) -> Result<alloc::vec::Vec<SelectedFile>, i64> {
    let mut selected = alloc::vec::Vec::new();
    for fd in 0..nfds {
        let want_read = bit_at(read, fd);
        let want_write = bit_at(write, fd);
        let want_except = bit_at(except, fd);
        if !want_read && !want_write && !want_except { continue; }
        let file = fdt.get(fd as i32).map_err(|_| -(Errno::Ebadf.as_i32() as i64))?;
        selected.push(SelectedFile {
            fd, file, read: want_read, write: want_write, except: want_except,
        });
    }
    Ok(selected)
}

/// `sys_select(nfds, readfds, writefds, exceptfds, timeout)` — slot 23.
/// # C: O(nfds)
pub fn sys_select(args: &SyscallArgs) -> i64 {
    let timeout_p   = args.a4;
    // Decode timeout (struct timeval { tv_sec: i64, tv_usec: i64 }
    // = 16 B). NULL = block forever; {0,0} = non-block.
    let (deadline_ns, req_sec, req_usec) = if timeout_p == 0 {
        (None, 0, 0)
    } else {
        let (s, u) = match timeval_from_user(timeout_p) { Ok(v) => v, Err(e) => return e };
        if u < 0 || u >= USEC_PER_SEC { return -(Errno::Einval.as_i32() as i64); }
        // `ktime_set`-clamped decode: a huge-but-valid tv_sec clamps to
        // KTIME_MAX_NS instead of an unbounded relative timeout.
        let total_ns = match ::syscall::time::timespec_to_ns(s, u.saturating_mul(NSEC_PER_USEC)) {
            Ok(ns) => ns,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        (Some(monotonic_ns().saturating_add(total_ns)), s, u)
    };
    let rv = sys_select_with_deadline(args, deadline_ns);
    // Linux `poll_select_finish` PT_TIMEVAL: select(2) reports the time left,
    // skipping the update for a zero timeout and for a `STICKY_TIMEOUTS`
    // persona — the same rule pselect6/ppoll apply to their timespec, and the
    // same `sticky:` fold of `-ERESTARTNOHAND` to `-EINTR` when the residual
    // timeout could not be written back.
    if timeout_p == 0 { return rv; }
    let persona = current_task()
        .map(|c| c.personality.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    let plan = timeout_writeback_plan(persona, req_sec, req_usec);
    if plan != TimeoutWriteback::Wrote { return finish_return(rv, plan); }
    let Some(deadline) = deadline_ns else { return finish_return(rv, TimeoutWriteback::Skipped) };
    let (sec, nsec) = remaining_timespec(deadline, monotonic_ns());
    let done = if validate_user_buf_writable(timeout_p, TIMEVAL_BYTES, 1).is_ok() {
        // SAFETY: timeout_p validated writable for the 16-byte timeval.
        unsafe {
            core::ptr::write_unaligned(timeout_p as *mut i64, sec);
            core::ptr::write_unaligned((timeout_p + TIMEVAL_USEC_OFF) as *mut i64,
                                       nsec / NSEC_PER_USEC);
        }
        TimeoutWriteback::Wrote
    } else {
        TimeoutWriteback::Faulted
    };
    finish_return(rv, done)
}

/// Shared select engine for select/pselect after timeout conversion.
/// # C: O(nfds)
pub(crate) fn sys_select_with_deadline(args: &SyscallArgs, deadline_ns: Option<u64>) -> i64 {
    let n_arg       = args.a0 as i32;
    let readfds_p   = args.a1;
    let writefds_p  = args.a2;
    let exceptfds_p = args.a3;
    if n_arg < 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let nfds = core::cmp::min(n_arg as u64, vfs::FD_TABLE_MAX as u64);
    let fdset_len = fdset_bytes(nfds);
    let in_set  = match copy_fdset_from_user(readfds_p, fdset_len) { Ok(v) => v, Err(e) => return e };
    let out_set = match copy_fdset_from_user(writefds_p, fdset_len) { Ok(v) => v, Err(e) => return e };
    let ex_set  = match copy_fdset_from_user(exceptfds_p, fdset_len) { Ok(v) => v, Err(e) => return e };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // Snapshot Oxide's requested open-file descriptions before waiting.
    // Retention prevents close/reuse in another task sharing this table from
    // retargeting an in-flight select.
    let selected = match snapshot_selected(&fdt, nfds, &in_set, &out_set, &ex_set) {
        Ok(files) => files,
        Err(rv) => return rv,
    };
    #[cfg(test)]
    run_post_snapshot_hook();
    // Linux `->poll`: register this call's waiter on each selected fd's OWN
    // wait queue (PollSubscribers). The fd's readiness transition `notify()`s
    // only its subscribers — no global broadcast.
    let waiter = crate::poll::poll_common::PollWaiter::new();
    let mut subbed: alloc::vec::Vec<Arc<vfs::PollSubscribers>> = alloc::vec::Vec::new();
    for entry in &selected {
        if let Some(s) = entry.file.poll_subscribers() {
            waiter.subscribe(&s);
            subbed.push(s);
        }
    }
    let rv: i64 = loop {
        let observed = waiter.generation();
        let mut res_in  = alloc::vec![0u8; fdset_len as usize];
        let mut res_out = alloc::vec![0u8; fdset_len as usize];
        let mut res_ex  = alloc::vec![0u8; fdset_len as usize];
        let mut ready: i64 = 0;
        for entry in &selected {
            // F202: consult inode.poll() — was special-casing pty and
            // returning (true,true) for everything else, so dropbear's
            // pipe-driven exec channel never woke on actual readiness.
            let mask = entry.file.poll();
            let got_read  = (mask & vfs::POLL_IN)  != 0
                         || (mask & vfs::POLL_HUP) != 0
                         || (mask & vfs::POLL_ERR) != 0;
            let got_write = (mask & vfs::POLL_OUT) != 0
                         || (mask & vfs::POLL_ERR) != 0;
            let got_except = (mask & vfs::POLL_PRI) != 0;
            if entry.read && got_read { set_bit_buf(&mut res_in, entry.fd); ready += 1; }
            if entry.write && got_write { set_bit_buf(&mut res_out, entry.fd); ready += 1; }
            if entry.except && got_except { set_bit_buf(&mut res_ex, entry.fd); ready += 1; }
        }
        // Linux `do_select` + `core_sys_select` break order, owned by
        // `crate::pselect_ppoll::wait_verdict`: readiness, then a deliverable
        // signal (`-ERESTARTNOHAND`), then the expired deadline. F205: without
        // the signal arm the loop sits in tick_yield forever when the only
        // thing about to break the wait is a pending signal (e.g. SIGCHLD
        // waking dropbear's pselect-style relay so it can wait4 the shell
        // child and let the pipe close-hook fire).
        let timed_out = deadline_ns.map(|dl| monotonic_ns() >= dl).unwrap_or(false);
        let sig = cur.deliverable_signals() != 0;
        if let Some(out) = wait_verdict(ready, timed_out, sig) {
            debug_ssh! {
                klog::write_raw(b"[INFO]  ssh-trace: select out=");
                klog::write_dec_u64(out as u64);
                klog::write_raw(b"\n");
            }
            // `core_sys_select`: `if (ret < 0) goto out;` — an interrupted
            // select leaves the caller's fd sets exactly as they were.
            if copies_out_fd_sets(out) {
                if let Err(e) = copy_fdset_to_user(readfds_p, &res_in) { break e; }
                if let Err(e) = copy_fdset_to_user(writefds_p, &res_out) { break e; }
                if let Err(e) = copy_fdset_to_user(exceptfds_p, &res_ex) { break e; }
            }
            break out;
        }
        let source_deadline = selected.iter()
            .filter_map(|entry| entry.file.poll_deadline_ns()).min();
        let park_dl = min_deadline(deadline_ns, source_deadline).unwrap_or(0);
        // SAFETY: process ctx; preempt-off across the syscall; park+yield per `13§8`.
        unsafe { waiter.park_until(observed, park_dl); }
    };
    // Drop our registration from every fd we subscribed to.
    for s in &subbed { waiter.unsubscribe(s); }
    rv
}

fn min_deadline(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(core::cmp::min(x, y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}
