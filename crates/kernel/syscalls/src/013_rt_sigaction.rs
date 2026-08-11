// 013 rt_sigaction — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use crate::user_mem as um;

const KERNEL_SIGSET_SIZE: u64 = 8;
const USER_SIGACTION_SIZE: u64 = 32;
const SA_HANDLER_OFF: u64 = 0;
const SA_FLAGS_OFF: u64 = 8;
const SA_RESTORER_OFF: u64 = 16;
const SA_MASK_OFF: u64 = 24;

/// `sys_rt_sigaction(sig, act, oldact, sz)` — slot 13.
/// # C: O(1)
pub fn sys_rt_sigaction(args: &SyscallArgs) -> i64 {
    use sched::SaHandler;
    use syscall::errno::Errno;
    let sig = args.a0 as usize;
    let act    = args.a1;
    let oldact = args.a2;
    let sz     = args.a3;
    if sz != KERNEL_SIGSET_SIZE {
        return -(Errno::Einval.as_i32() as i64);
    }
    let new_action = if act != 0 {
        if let Err(rv) = validate_user_buf(act, USER_SIGACTION_SIZE, 1) { return rv; }
        let rd = |off: u64| um::get_u64(act + off);
        let (h, f, r, m) = match (rd(SA_HANDLER_OFF), rd(SA_FLAGS_OFF), rd(SA_RESTORER_OFF), rd(SA_MASK_OFF)) {
            (Ok(h), Ok(f), Ok(r), Ok(m)) => (h, f, r, m),
            _ => return um::EFAULT,
        };
        Some(SaHandler { handler: h, flags: f, restorer: r, mask: m })
    } else {
        None
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return 0,
    };
    let prior = match cur.rt_sigaction(sig, new_action) {
        Ok(old) => old,
        Err(()) => return -(Errno::Einval.as_i32() as i64),
    };
    if let Some(SaHandler { handler: h, flags: f, restorer: r, .. }) = new_action {
        let _ = (h, f, r);
        debug_ssh! { crate::signal_trace::sigaction(cur.tid, sig as u64, h, f, r); }
    }
    if oldact != 0 {
        if let Err(rv) = validate_user_buf_writable(oldact, USER_SIGACTION_SIZE, 1) { return rv; }
        let wr = |off: u64, v: u64| um::put_u64(oldact + off, v);
        if wr(SA_HANDLER_OFF, prior.handler).is_err() || wr(SA_FLAGS_OFF, prior.flags).is_err()
            || wr(SA_RESTORER_OFF, prior.restorer).is_err() || wr(SA_MASK_OFF, prior.mask).is_err() {
            return um::EFAULT;
        }
    }
    0
}
