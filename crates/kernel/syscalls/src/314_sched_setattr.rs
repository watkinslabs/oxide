// 314 sched_setattr — one syscall, one file (docs/53 §0).
// `sched_setattr(pid, uattr, flags)`: Linux `kernel/sched/syscalls.c:960`.
// Thin shim: the extensible-struct copy protocol is `crate::sched_attr`
// (Linux `sched_copy_attr` + `copy_struct_from_user`) and the policy/priority/
// permission rules are `crate::sched_policy` (`__sched_setscheduler`), shared
// verbatim with slots 142/144.
#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};
use crate::sched_attr::{self as sa, SchedAttr};
use crate::sched_policy;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Linux `sched_copy_attr`'s `err_size:` label — report the kernel's own
/// `sizeof(struct sched_attr)` through `uattr->size`, then `-E2BIG`. The
/// `put_user` failure is deliberately ignored, exactly as Linux ignores it.
/// # C: O(1)
fn err_size(uattr: u64) -> i64 {
    if validate_user_buf_writable(uattr, 4, 1).is_ok() {
        // SAFETY: uattr just validated writable for its leading u32 `size` field, which Linux's err_size path overwrites with the kernel's own sched_attr size.
        unsafe { core::ptr::write_unaligned(uattr as *mut u32, sa::KSIZE); }
    }
    err(Errno::E2big)
}

/// Linux `sched_copy_attr()` + `copy_struct_from_user()`: zero-fill a short
/// struct, and require every trailing byte this kernel does not understand to
/// read as zero.
/// # C: O(N_tail)
fn copy_attr_in(uattr: u64) -> Result<SchedAttr, i64> {
    validate_user_buf_readable(uattr, 4, 1)?;
    // SAFETY: uattr validated readable for the leading u32 `size` field of struct sched_attr, which is what Linux's get_user(size, &uattr->size) reads first.
    let raw = unsafe { core::ptr::read_unaligned(uattr as *const u32) };
    let plan = match sa::copy_in_size(raw) { Ok(p) => p, Err(()) => return Err(err_size(uattr)) };
    validate_user_buf_readable(uattr, plan.size as u64, 1)?;
    let mut buf = [0u8; sa::KSIZE as usize];
    uaccess::copy_from_user(&mut buf[..plan.copy as usize], uattr)
        .map_err(|_| err(Errno::Efault))?;
    if plan.tail != 0 && !tail_is_zero(uattr + plan.copy as u64, plan.tail)? {
        return Err(err_size(uattr));
    }
    let mut attr = SchedAttr::from_bytes(&buf);
    sa::finish_copy_in(&mut attr, plan.size)?;
    Ok(attr)
}

/// Linux `check_zeroed_user()` over the bytes past `sizeof(struct sched_attr)`.
/// # C: O(N)
fn tail_is_zero(ptr: u64, len: u32) -> Result<bool, i64> {
    /// One chunk of the at-most-`PAGE_SIZE` tail, kept off the kernel stack cap.
    const CHUNK: usize = 64;
    let mut buf = [0u8; CHUNK];
    let mut done = 0u32;
    while done < len {
        let n = core::cmp::min(CHUNK, (len - done) as usize);
        uaccess::copy_from_user(&mut buf[..n], ptr + done as u64).map_err(|_| err(Errno::Efault))?;
        if buf[..n].iter().any(|b| *b != 0) { return Ok(false); }
        done += n as u32;
    }
    Ok(true)
}

/// `sys_sched_setattr(pid, attr, flags)` — slot 314.
/// # C: O(log N) requeue
pub fn sys_sched_setattr(args: &SyscallArgs) -> i64 {
    let uattr = args.a1;
    if uattr == 0 || (args.a0 as i32) < 0 || args.a2 != 0 { return err(Errno::Einval); }
    let pid = args.a0 as u32;
    let mut attr = match copy_attr_in(uattr) { Ok(a) => a, Err(rv) => return rv };
    if (attr.policy as i32) < 0 { return err(Errno::Einval); }
    // SCHED_FLAG_KEEP_POLICY folds onto the SETPARAM_POLICY sentinel, which
    // `__sched_setscheduler` reads back as "keep the task's current policy".
    if attr.flags & sa::FLAG_KEEP_POLICY != 0 { attr.policy = sched_policy::SETPARAM_POLICY as u32; }

    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else { sched::live::registry::resolve_user_pid(pid) };
    let t = match task { Some(t) => t, None => return err(Errno::Esrch) };
    let caller = match sched::live::current() { Some(c) => c, None => return err(Errno::Esrch) };
    // SCHED_FLAG_KEEP_PARAMS asks for the task's own parameters back, so the
    // validation below sees values that are trivially self-consistent.
    if attr.flags & sa::FLAG_KEEP_PARAMS != 0 { sched_policy::get_params(&t, &mut attr); }
    sched_policy::setattr(caller, &t, &attr)
}
