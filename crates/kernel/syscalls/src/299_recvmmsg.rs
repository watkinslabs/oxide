// `sys_recvmmsg` — slot 299. Native mmsghdr import, pinned socket batch,
// pending-error publication, WAITFORONE, and relative timeout copyback.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::uapi::{MSG_CMSG_COMPAT, MSG_DONTWAIT, MSG_WAITFORONE};

use crate::recvmsg::layout::{MMSGHDR_LEN_OFFSET, MMSGHDR_SIZE, TIMESPEC_SIZE};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

struct BatchTimeout {
    user: u64,
    deadline: u64,
    remaining: u64,
}

fn timeout_import(user: u64) -> Result<Option<BatchTimeout>, i64> {
    if user == 0 { return Ok(None); }
    let mut raw = [0u8; TIMESPEC_SIZE];
    uaccess::copy_from_user(&mut raw, user).map_err(|_| err(Errno::Efault))?;
    let sec = i64::from_ne_bytes(raw[..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(raw[8..].try_into().unwrap());
    if sec < 0 || nsec < 0 || nsec >= crate::time_common::NS_PER_SEC as i64 { return Err(err(Errno::Einval)); }
    let total = (sec as u64).saturating_mul(crate::time_common::NS_PER_SEC).saturating_add(nsec as u64);
    Ok(Some(BatchTimeout { user, deadline: crate::time_common::monotonic_ns().saturating_add(total), remaining: total }))
}

fn timeout_update(timeout: &mut Option<BatchTimeout>) -> bool {
    let Some(timeout) = timeout else { return false };
    timeout.remaining = timeout.deadline.saturating_sub(crate::time_common::monotonic_ns());
    timeout.remaining == 0
}

fn timeout_copyback(timeout: &Option<BatchTimeout>) -> Result<(), i64> {
    let Some(timeout) = timeout else { return Ok(()) };
    let sec = timeout.remaining / crate::time_common::NS_PER_SEC;
    let nsec = timeout.remaining % crate::time_common::NS_PER_SEC;
    let mut raw = [0u8; TIMESPEC_SIZE];
    raw[..8].copy_from_slice(&(sec as i64).to_ne_bytes());
    raw[8..].copy_from_slice(&(nsec as i64).to_ne_bytes());
    uaccess::copy_to_user(timeout.user, &raw).map_err(|_| err(Errno::Efault))
}

fn partial(target: &crate::recvmsg::dispatch::RecvTarget, got: i64, failure: i64) -> i64 {
    if got == 0 { return failure; }
    if failure != err(Errno::Eagain) {
        if let Ok(errno) = i32::try_from(-failure) {
            if errno > 0 { target.set_pending_error(errno); }
        }
    }
    got
}

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — slot 299.
/// # C: O(vlen)
pub fn sys_recvmmsg(args: &SyscallArgs) -> i64 {
    let mmsg_ptr = args.a1;
    // Linux recvmmsg(2) BUGS: vlen above UIO_MAXIOV is silently truncated,
    // not rejected — mirrors sendmmsg's UIO_MAXIOV clamp.
    const UIO_MAXIOV: u64 = 1024;
    let vlen = (args.a2 as u32 as u64).min(UIO_MAXIOV);
    let mut flags = args.a3;
    if flags & MSG_CMSG_COMPAT != 0 { return err(Errno::Einval); }
    let mut timeout = match timeout_import(args.a4) { Ok(timeout) => timeout, Err(e) => return e };
    let target = match crate::recvmsg::lookup(args.a0) { Ok(target) => target, Err(e) => return e };
    if vlen == 0 { return 0; }
    flags &= !MSG_WAITFORONE;
    let mut got: i64 = 0;
    let result = 'batch: {
    for i in 0..vlen {
        let entry = match i.checked_mul(MMSGHDR_SIZE).and_then(|offset| mmsg_ptr.checked_add(offset)) {
            Some(entry) => entry,
            None => break 'batch partial(&target, got, err(Errno::Efault)),
        };
        let user = match crate::recv_user::import(entry) { Ok(user) => user, Err(e) => break 'batch partial(&target, got, e) };
        let r = crate::recvmsg::recv(&target, &user, flags);
        if r < 0 {
            break 'batch partial(&target, got, r);
        }
        let len_ptr = match entry.checked_add(MMSGHDR_LEN_OFFSET) {
            Some(len_ptr) => len_ptr,
            None => break 'batch partial(&target, got, err(Errno::Efault)),
        };
        if uaccess::copy_to_user(len_ptr, &(r as u32).to_ne_bytes()).is_err() {
            break 'batch partial(&target, got, err(Errno::Efault));
        }
        got += 1;
        if args.a3 & MSG_WAITFORONE != 0 { flags |= MSG_DONTWAIT; }
        let expired = timeout_update(&mut timeout);
        if expired { break; }
    }
    got
    };
    // Linux copies a supplied timeout back only after at least one completed
    // datagram. An empty nonblocking/error return must leave user memory alone.
    if result > 0 {
        if let Err(e) = timeout_copyback(&timeout) { return e; }
    }
    result
}
