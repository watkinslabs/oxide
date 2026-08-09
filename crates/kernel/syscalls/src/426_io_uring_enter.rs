// sys_io_uring_enter (NR_IO_URING_ENTER=426) per docs/53§0 — ABI shim only:
// validate the flags, resolve the ring, decode the extended argument, submit,
// wait, fold the two halves into one return value. The submission engine, the
// wait and every decision live below (`io_uring::submit`, `io_uring::wait`,
// `io_uring_abi::enter`), which the hosted suite compiles and tests.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::{state, IoUringInode};
use crate::io_uring::{ring_ctx, ring_of};
use crate::io_uring_abi::enter::*;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Resolve the ring behind the first argument — `IORING_ENTER_REGISTERED_RING`
/// indexes the calling task's registered-ring array instead of the fd table
/// (Linux `io_uring_ctx_get_file`). # C: O(1)
fn ring_for(fd: i32, registered: bool) -> Result<Arc<IoUringInode>, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    let file = if registered {
        match cur.io_uring_ring_lookup(fd as u32) { Ok(f) => f, Err(e) => return Err(err(e)) }
    } else {
        // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
        let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
        match fdt.clone().get(fd) { Ok(f) => f, Err(_) => return Err(err(Errno::Ebadf)) }
    };
    let inode = ring_of(&file).map_err(err)?;
    ring_ctx(&inode).ok_or(err(Errno::Eopnotsupp))
}

/// Read the caller's wait parameters, whichever argument shape it used.
/// # C: O(1)
fn ext_arg_of(inode: &IoUringInode, flags: u32, argp: u64, argsz: u64) -> Result<ExtArg, i64> {
    match arg_kind(flags, argsz).map_err(err)? {
        ArgKind::BareSigmask => Ok(bare_sigmask_arg(argp, argsz, flags)),
        ArgKind::Getevents => {
            let mut b = [0u8; GETEVENTS_ARG_BYTES as usize];
            if uaccess::copy_from_user(&mut b, argp).is_err() { return Err(err(Errno::Efault)); }
            let (sig, sigsz, min_wait_usec, ts_p) = decode_getevents(&b);
            let ts = if ts_p == 0 { None } else { Some(read_timespec(ts_p)?) };
            Ok(ExtArg {
                sig, sigsz,
                min_wait_ns: min_wait_usec.saturating_mul(NSEC_PER_USEC),
                ts,
                abs: flags & IORING_ENTER_ABS_TIMER != 0,
                iowait: flags & IORING_ENTER_NO_IOWAIT == 0,
            })
        }
        // The registered form: `argp` is a byte OFFSET into the wait area the
        // ring registered with `IORING_REGISTER_MEM_REGION`, not a user
        // pointer. Nothing is copied from userspace — the record is read
        // straight out of the region, which is the point of the flag.
        ArgKind::RegisteredWait => {
            let b = inode.reg_wait(argp).map_err(err)?;
            decode_reg_wait(&b, flags).map_err(err)
        }
    }
}

/// # C: O(1)
fn read_timespec(p: u64) -> Result<(i64, i64), i64> {
    let mut b = [0u8; 16];
    if uaccess::copy_from_user(&mut b, p).is_err() { return Err(err(Errno::Efault)); }
    let sec = i64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let nsec = i64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    Ok((sec, nsec))
}

/// Install the caller's temporary signal mask for the wait. Armed rather than
/// swapped, so a signal that arrives during the wait runs its handler under
/// the temporary mask and the caller's own mask comes back with the return.
/// # C: O(1)
fn arm_sigmask(ext: &ExtArg) -> Result<bool, i64> {
    if ext.sig == 0 { return Ok(false); }
    if syscall::sigset::check_exact(ext.sigsz).is_err() { return Err(err(Errno::Einval)); }
    let mut b = [0u8; 8];
    if uaccess::copy_from_user(&mut b, ext.sig).is_err() { return Err(err(Errno::Efault)); }
    if let Some(cur) = sched::live::current() { cur.arm_saved_sigmask(u64::from_ne_bytes(b)); }
    Ok(true)
}

/// `sys_io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz)`
/// — slot 426. # C: O(to_submit) + wait
pub fn sys_io_uring_enter(args: &syscall::SyscallArgs) -> i64 {
    let fd        = args.a0 as i32;
    let to_submit = args.a1 as u32;
    let min_cmpl  = args.a2 as u32;
    let flags     = args.a3 as u32;
    let argp      = args.a4;
    let argsz     = args.a5;

    if let Err(e) = validate_flags(flags) { return err(e); }
    let inode = match ring_for(fd, flags & IORING_ENTER_REGISTERED_RING != 0) {
        Ok(i) => i, Err(e) => return e,
    };
    // A ring created disabled submits nothing until it is enabled.
    if inode.test_state(state::DISABLED) { return err(Errno::Ebadfd); }
    if let Err(e) = inode.claim_issuer() { return err(e); }

    // A ring with a submission-poll thread submits nothing here: the thread
    // owns the SQ ring. All this call does is ring the doorbell the submitter
    // decided to ring, and report the count the submitter says it published.
    let submitted = match sqpoll_half(&inode, to_submit, flags) {
        Some(rv) => match rv { Ok(n) => n, Err(e) => return e },
        None if to_submit > 0 => crate::io_uring::submit::submit_sqes(&inode, to_submit),
        None => 0,
    };
    if !runs_getevents(submitted, to_submit, flags) { return submitted; }
    enter_result(submitted, wait_half(&inode, min_cmpl, flags, argp, argsz))
}

/// The submit half of an `IORING_SETUP_SQPOLL` ring. `None` means the ring has
/// no poll thread and the caller submits inline.
///
/// The wake is not re-decided here against `sq_flags`: the submitter already
/// made that decision when it read the word, and a poll thread that has since
/// retracted the doorbell may be on its way into `schedule()`.
/// # C: O(1) + the SQ_WAIT wait
fn sqpoll_half(inode: &Arc<IoUringInode>, to_submit: u32, flags: u32) -> Option<Result<i64, i64>> {
    use crate::io_uring_abi::sqpoll::{enter_action, enter_submitted};
    let sqd = crate::io_uring::sqpoll::of(inode)?;
    // The thread is what submits; without it nothing ever will, and reporting
    // a submission that cannot happen would hang the caller instead.
    if sqd.dead() { return Some(Err(err(Errno::Eownerdead))); }
    let act = enter_action(flags);
    if act.wake { sqd.wake(); }
    if act.wait_room { crate::io_uring::sqpoll::wait_sq_room(&sqd, inode); }
    Some(Ok(enter_submitted(to_submit)))
}

/// The wait half, kept out of the submission frame: the deepest operations run
/// close to the kernel stack budget, so the wait's own bookkeeping must not be
/// charged to their depth. # C: wait
#[inline(never)]
fn wait_half(inode: &Arc<IoUringInode>, min_cmpl: u32, flags: u32, argp: u64, argsz: u64) -> i64 {
    let ext = match ext_arg_of(inode, flags, argp, argsz) { Ok(e) => e, Err(e) => return e };
    let armed = match arm_sigmask(&ext) { Ok(a) => a, Err(e) => return e };
    let wait_rv = crate::io_uring::wait::cq_wait(inode, min_cmpl, &ext);
    // An interrupted wait KEEPS the temporary mask so the handler runs under
    // it; anything else restores the caller's own mask now.
    if armed && wait_rv != err(Errno::Eintr) {
        if let Some(cur) = sched::live::current() { cur.restore_saved_sigmask(); }
    }
    wait_rv
}
