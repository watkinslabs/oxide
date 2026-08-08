// 315 sched_getattr — one syscall, one file (docs/53 §0).
// `sched_getattr(pid, uattr, usize, flags)`: Linux's `sys_sched_getattr`.
// Thin shim over `crate::sched_attr` (the `copy_struct_to_user` size protocol)
// and `crate::sched_policy::get_params` (Linux `get_params`).
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::{errno::Errno, SyscallArgs};
use crate::sched_attr::{self as sa, SchedAttr};
use crate::sched_policy;
use crate::userbuf::validate_user_buf_writable;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_sched_getattr(pid, attr, size, flags)` — slot 315.
/// # C: O(1) self; O(N) for a foreign pid
pub fn sys_sched_getattr(args: &SyscallArgs) -> i64 {
    let uattr = args.a1;
    let user_size = args.a2 as u32;
    let flags = args.a3;
    if uattr == 0 || (args.a0 as i32) < 0 { return err(Errno::Einval); }
    let plan = match sa::copy_out_size(user_size) { Ok(p) => p, Err(rv) => return rv };
    let pid = args.a0 as u32;

    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let t = match task { Some(t) => t, None => return err(Errno::Esrch) };
    // `flags` is checked only AFTER the task exists: the sole legal flag is
    // SCHED_GETATTR_FLAG_DL_DYNAMIC, and only on a SCHED_DEADLINE task — a bad
    // pid still reports ESRCH first.
    if flags != 0 && (!sched_policy::dl_policy(sched_policy::task_policy(&t))
                      || flags != sa::GETATTR_FLAG_DL_DYNAMIC) {
        return err(Errno::Einval);
    }

    // Linux reports `p->policy` + `p->rt_priority` — the stored policy, not the
    // implementation class (NORMAL/BATCH/IDLE all share CFS).
    let (uc_min, uc_max) = sched_policy::uclamp_req(&t);
    let mut kattr = SchedAttr {
        size: plan.reported,
        policy: sched_policy::task_policy(&t),
        flags: if t.sched_reset_on_fork.load(Ordering::Acquire) { sa::FLAG_RESET_ON_FORK } else { 0 },
        util_min: uc_min.value,
        util_max: uc_max.value,
        ..Default::default()
    };
    sched_policy::get_params(&t, &mut kattr, flags == sa::GETATTR_FLAG_DL_DYNAMIC);
    kattr.flags &= sa::FLAG_ALL;
    let bytes = kattr.to_bytes();

    if let Err(rv) = validate_user_buf_writable(uattr, user_size as u64, 1) { return rv; }
    // `copy_struct_to_user`: the caller may declare a struct larger than this
    // kernel's, and the fields it knows about but we do not must read as zero
    // rather than as whatever was on its stack.
    if plan.zero != 0 && zero_user(uattr + plan.copy as u64, plan.zero).is_err() {
        return err(Errno::Efault);
    }
    match uaccess::copy_to_user(uattr, &bytes[..plan.copy as usize]) {
        Ok(()) => 0, Err(_) => err(Errno::Efault),
    }
}

/// Linux `clear_user()` over the trailing bytes of an oversized user struct.
/// # C: O(N)
fn zero_user(ptr: u64, len: u32) -> Result<(), ()> {
    /// One chunk of the at-most-`PAGE_SIZE` tail, kept off the kernel stack cap.
    const CHUNK: usize = 64;
    let zeros = [0u8; CHUNK];
    let mut done = 0u32;
    while done < len {
        let n = core::cmp::min(CHUNK, (len - done) as usize);
        uaccess::copy_to_user(ptr + done as u64, &zeros[..n]).map_err(|_| ())?;
        done += n as u32;
    }
    Ok(())
}
