// 302 prlimit64 — one syscall, one file (docs/53 §0). ABI shim only: target
// resolution + copy-in/copy-out; the decision ladder is
// `sched::Task::do_prlimit` (Linux `kernel/sys.c`), shared with 097/160.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::perm_common::prlimit_perm_check;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `sys_prlimit64(pid, resource, new, old)` — slot 302. Reads/writes the
/// target thread group's rlimit table (Linux `signal->rlim`).
///
/// A non-self target requires `check_prlimit_permission` (matching creds or
/// `CAP_SYS_RESOURCE` in the target's user namespace — `prlimit_perm_check`);
/// the resource-index, `cur <= max`, `fs.nr_open` and hard-limit-raise rules
/// all live in `do_prlimit`.
/// # C: O(1) self; O(N_tasks) for non-self lookup
pub fn sys_prlimit64(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let pid      = args.a0 as u32;
    let resource = args.a1 as usize;
    let new_ptr  = args.a2;
    let old_ptr  = args.a3;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    // Linux copies the NEW value in before resolving the target (EFAULT wins
    // over ESRCH/EPERM); `resource` is validated inside `do_prlimit`.
    let new = if new_ptr != 0 {
        if let Err(rv) = validate_user_buf(new_ptr, 16, 1) { return rv; }
        // SAFETY: new_ptr validated readable for the 16-byte struct rlimit64 input.
        let (c, m) = unsafe {
            (core::ptr::read_unaligned( new_ptr      as *const u64),
             core::ptr::read_unaligned((new_ptr + 8) as *const u64))
        };
        Some((c, m))
    } else { None };
    let task = if pid == 0 {
        sched::live::registry::lookup(cur.tid)
    } else {
        sched::live::registry::resolve_user_pid(pid)
    };
    let task = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };

    if task.tid != cur.tid && !prlimit_perm_check(&cur, &task) {
        return -(Errno::Eperm.as_i32() as i64);
    }

    // `task` may not be `current` (prlimit64 explicitly targets an arbitrary
    // pid); `do_prlimit` takes the target thread group's rlimit lock, so this
    // cross-task read-decide-write cannot race a reader/writer on another CPU.
    let old = match task.do_prlimit(resource, new, cur.has_cap(sched::cap::SYS_RESOURCE)) {
        Ok(old) => old,
        Err(e)  => return -(crate::rlimit_policy::errno_of(e).as_i32() as i64),
    };
    // Linux copies the old value out only after the whole ladder passed, so a
    // rejected call leaves `old_rlim` untouched.
    if old_ptr != 0 {
        if let Err(rv) = validate_user_buf_writable(old_ptr, 16, 1) { return rv; }
        // SAFETY: old_ptr validated writable for the 16-byte rlimit result.
        unsafe {
            core::ptr::write_unaligned( old_ptr       as *mut u64, old.0);
            core::ptr::write_unaligned((old_ptr + 8)  as *mut u64, old.1);
        }
    }
    0
}
