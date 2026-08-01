// `sys_recvmmsg` — slot 299. ABI only: import one entry, run one receive,
// publish one length. Every batch DECISION — what admits a batch, what ends
// one, what a partly-delivered batch reports — belongs to `crate::mmsg_batch`,
// which is ungated and therefore tested.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use net::uapi::MSG_OOB;

use crate::mmsg_batch::{self, AfterDelivery, OnFailure};
use crate::recvmsg::layout::{MMSGHDR_FLAGS_OFFSET, MMSGHDR_LEN_OFFSET, MMSGHDR_SIZE, TIMESPEC_SIZE};

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
    let total = mmsg_batch::timeout_total_ns(sec, nsec).map_err(err)?;
    Ok(Some(BatchTimeout { user, deadline: crate::time_common::monotonic_ns().saturating_add(total), remaining: total }))
}

/// Re-read the supplied timeout, reporting what is left for the batch rule.
/// # C: O(1)
fn timeout_left(timeout: &mut Option<BatchTimeout>) -> Option<u64> {
    let timeout = timeout.as_mut()?;
    timeout.remaining = timeout.deadline.saturating_sub(crate::time_common::monotonic_ns());
    Some(timeout.remaining)
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

/// Whether the message just delivered into this entry carried `MSG_OOB`.
/// # C: O(1)
fn oob_received(entry: u64) -> bool {
    let Some(flags_ptr) = entry.checked_add(MMSGHDR_FLAGS_OFFSET) else { return false };
    let mut raw = [0u8; 4];
    if uaccess::copy_from_user(&mut raw, flags_ptr).is_err() { return false; }
    u32::from_ne_bytes(raw) as u64 & MSG_OOB != 0
}

/// Apply the batch's failure rule to one failed entry. # C: O(1)
fn partial(target: &crate::recvmsg::dispatch::RecvTarget, got: i64, failure: i64) -> i64 {
    match mmsg_batch::on_failure(got, failure) {
        OnFailure::Report(failure) => failure,
        OnFailure::Deliver { count, latch } => {
            if let Some(errno) = latch { target.set_pending_error(errno); }
            count
        }
    }
}

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — slot 299.
/// # C: O(vlen)
pub fn sys_recvmmsg(args: &SyscallArgs) -> i64 {
    let mmsg_ptr = args.a1;
    let vlen = mmsg_batch::batch_len(args.a2);
    let flags = args.a3;
    if let Err(e) = mmsg_batch::admit_flags(flags) { return err(e); }
    let mut timeout = match timeout_import(args.a4) { Ok(timeout) => timeout, Err(e) => return e };
    let target = match crate::recvmsg::lookup(args.a0) { Ok(target) => target, Err(e) => return e };
    if mmsg_batch::reports_pending_error(flags) {
        let pending = target.take_error();
        if pending != 0 { return -(pending as i64); }
    }
    if vlen == 0 { return 0; }
    let mut got: i64 = 0;
    let result = 'batch: {
    for i in 0..vlen {
        let entry = match i.checked_mul(MMSGHDR_SIZE).and_then(|offset| mmsg_ptr.checked_add(offset)) {
            Some(entry) => entry,
            None => break 'batch partial(&target, got, err(Errno::Efault)),
        };
        let user = match crate::recv_user::import(entry) { Ok(user) => user, Err(e) => break 'batch partial(&target, got, e) };
        let r = crate::recvmsg::recv(&target, &user, mmsg_batch::entry_flags(flags, got as u64));
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
        match mmsg_batch::after_delivery(timeout_left(&mut timeout), oob_received(entry)) {
            AfterDelivery::Continue => {}
            AfterDelivery::TimedOut | AfterDelivery::OutOfBand => break,
        }
    }
    got
    };
    if mmsg_batch::copies_timeout_back(result) {
        if let Err(e) = timeout_copyback(&timeout) { return e; }
    }
    result
}
