// 274 get_robust_list — one syscall, one file (docs/53 §0).
// `get_robust_list(pid, head_ptr, len_ptr)`: Linux `kernel/futex/syscalls.c:94`
// + `futex_get_robust_list_common` (`:47`).
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_get_robust_list(pid, head_out, len_out)` — slot 274. `pid == 0` means
/// the calling thread.
///
/// Two rules that are easy to get wrong and both matter:
///   * `len_ptr` receives `sizeof(struct robust_list_head)` — a CONSTANT, not
///     the length `set_robust_list(2)` was called with.
///   * reading ANOTHER task's head requires
///     `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)`; without it any process
///     could map out another's robust-mutex list.
///
/// The user pointers are written only after the lookup and the permission
/// check, so a bad pid is `ESRCH` and a denied peer is `EPERM` — never `EFAULT`.
/// # C: O(1) | O(N_tasks) when pid != 0 (registry walk)
pub fn sys_get_robust_list(args: &SyscallArgs) -> i64 {
    let pid      = args.a0 as i32;
    let head_out = args.a1;
    let len_out  = args.a2;
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Esrch) };
    let head = if pid == 0 {
        cur.robust_list_head.load(Ordering::Acquire)
    } else {
        let task = match sched::live::registry::resolve_user_pid(pid as u32) {
            Some(t) => t, None => return err(Errno::Esrch),
        };
        if crate::s101_ptrace_perm::may_access(cur, &task).is_err() { return err(Errno::Eperm); }
        task.robust_list_head.load(Ordering::Acquire)
    };
    // Linux writes the length first and returns EFAULT from either put_user.
    if let Err(rv) = validate_user_buf_writable(len_out, 8, 1) { return rv; }
    let len = ipc::robust_decode::ROBUST_LIST_HEAD_SIZE;
    if uaccess::copy_to_user(len_out, &len.to_ne_bytes()).is_err() { return err(Errno::Efault); }
    if let Err(rv) = validate_user_buf_writable(head_out, 8, 1) { return rv; }
    match uaccess::copy_to_user(head_out, &head.to_ne_bytes()) {
        Ok(()) => 0, Err(_) => err(Errno::Efault),
    }
}
