// ABI shim for slots 206/207/208/209/210/333 (docs/53): unpack the register
// arguments, run the argument reads in the order the kernel does, call one
// work fn, encode the result.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::aio_abi::events::{getevents_return, pgetevents_return, restores_sigmask};
use crate::aio_abi::uapi::{AIO_SIGSET_OFF_SIGMASK, AIO_SIGSET_OFF_SIGSETSIZE, AIO_SIGSET_SIZE,
    IOCB_OFF_KEY, KIOCB_KEY};
use crate::aio::{ctx, reap, setup, submit};
use crate::userbuf::validate_user_buf_readable;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_io_setup(nr_events, ctxp)` — slot 206. # C: O(nr_pages)
pub fn sys_io_setup(args: &SyscallArgs) -> i64 { setup::sys_io_setup(args.a0 as u32, args.a1) }

/// `sys_io_destroy(ctx_id)` — slot 207. # C: O(N_active + nr_pages)
pub fn sys_io_destroy(args: &SyscallArgs) -> i64 { setup::sys_io_destroy(args.a0) }

/// `sys_io_submit(ctx_id, nr, iocbpp)` — slot 209. # C: O(nr x per-op cost)
pub fn sys_io_submit(args: &SyscallArgs) -> i64 {
    submit::sys_io_submit(args.a0, args.a1 as i64, args.a2)
}

/// `sys_io_getevents(ctx_id, min_nr, nr, events, timeout)` — slot 208.
/// The timeout is read before anything else, so an unreadable pointer is
/// `EFAULT` even for a bogus context.
/// # C: O(nr x N_loop)
pub fn sys_io_getevents(args: &SyscallArgs) -> i64 {
    let until = match reap::read_timeout(args.a4) { Ok(u) => u, Err(e) => return e };
    let (rv, signalled) = reap::read_events(args.a0, args.a1 as i64, args.a2 as i64, args.a3, until);
    getevents_return(rv, signalled)
}

/// `sys_io_pgetevents(ctx_id, min_nr, nr, events, timeout, usig)` — slot 333.
///
/// Same reap, wrapped in the atomic sigmask swap: the timeout is read first,
/// then the `__aio_sigset` pair, then the mask is installed with the
/// restore flag armed. An interrupted empty reap keeps the temporary mask and
/// reports the restart code; every other outcome puts the caller's mask back.
/// # C: O(nr x N_loop)
pub fn sys_io_pgetevents(args: &SyscallArgs) -> i64 {
    let until = match reap::read_timeout(args.a4) { Ok(u) => u, Err(e) => return e };
    let usig = args.a5;
    let (ss_ptr, ss_len) = if usig == 0 { (0u64, 0u64) } else {
        if validate_user_buf_readable(usig, AIO_SIGSET_SIZE, 1).is_err() { return err(Errno::Efault); }
        // SAFETY: usig validated readable for the whole 16-byte __aio_sigset below USER_VA_END; CPL=0 reads both words through the caller's address space.
        unsafe {
            (core::ptr::read_unaligned((usig + AIO_SIGSET_OFF_SIGMASK) as *const u64),
             core::ptr::read_unaligned((usig + AIO_SIGSET_OFF_SIGSETSIZE) as *const u64))
        }
    };
    let cur = sched::live::current();
    if let Err(e) = crate::pselect_ppoll_edge::set_user_sigmask(cur, ss_ptr, ss_len) { return e; }
    let (rv, signalled) = reap::read_events(args.a0, args.a1 as i64, args.a2 as i64, args.a3, until);
    let out = pgetevents_return(rv, signalled);
    if let Some(c) = cur {
        if restores_sigmask(out) { c.restore_saved_sigmask(); }
    }
    out
}

/// `sys_io_cancel(ctx_id, iocb, result)` — slot 210.
///
/// The request tag is read out of the caller's iocb BEFORE the context is
/// looked up, so an unreadable iocb is `EFAULT` and one that never went
/// through `io_submit` is `EINVAL` regardless of the context. A request that
/// is still outstanding is taken off the context and reported as
/// `EINPROGRESS`; anything already complete — which is every read, write and
/// sync, because those finish inside their submit — is `EINVAL`.
///
/// A cancelled request is NOT dropped: cancellation still delivers its
/// `io_event`, with `res` = 0 because the condition never became true. A caller
/// that reaps after a successful cancel therefore sees one event per cancelled
/// iocb, which is what lets it account for every submission it made.
///
/// The `result` argument is not used: completions are delivered through the
/// ring, never written back here.
/// # C: O(N_active)
pub fn sys_io_cancel(args: &SyscallArgs) -> i64 {
    let uiocb = args.a1;
    if validate_user_buf_readable(uiocb + IOCB_OFF_KEY, 4, 1).is_err() { return err(Errno::Efault); }
    // SAFETY: the aio_key word was validated readable below USER_VA_END; CPL=0 reads the request tag the kernel stamped at submit.
    let key = unsafe { core::ptr::read_unaligned((uiocb + IOCB_OFF_KEY) as *const u32) };
    if key != KIOCB_KEY { return err(Errno::Einval); }
    let c = match ctx::lookup(args.a0) { Some(c) => c, None => return err(Errno::Einval) };
    let taken = {
        let mut act = c.active.lock();
        act.iter().position(|r| r.obj == uiocb).map(|i| act.remove(i))
    };
    match taken {
        // The reserved ring slot is consumed by this completion, so it is not
        // returned here — the reap that collects the event returns it.
        Some(req) => { c.complete_active(&req, 0); err(Errno::Einprogress) }
        None => err(Errno::Einval),
    }
}
