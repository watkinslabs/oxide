// `prctl(PR_SET_NAME / PR_GET_NAME / PR_SET_DUMPABLE / PR_GET_DUMPABLE)` —
// Linux `kernel/sys.c` (`strncpy_from_user` + `set_task_comm`,
// `get_task_comm` + `copy_to_user`, `task_exec_state_{set,get}_dumpable`).

use core::sync::atomic::Ordering;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::task::{Task, TASK_COMM_LEN};

/// `prctl(PR_SET_NAME, name)` — Linux
/// `strncpy_from_user(comm, arg2, TASK_COMM_LEN - 1)`. Copies up to
/// `TASK_COMM_LEN - 1` raw bytes from the user pointer, stopping at the first
/// NUL, into this THREAD's `comm` (per-thread, like `pthread_setname_np`, not
/// per-process). A bad pointer is EFAULT, never a silent no-op.
/// # C: O(TASK_COMM_LEN)
pub fn sys_set_name(cur: &Task, args: &SyscallArgs) -> i64 {
    let p = args.a1;
    let span = (TASK_COMM_LEN - 1) as u64;
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add(span).map_or(true, |e| e > hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut buf = [0u8; TASK_COMM_LEN - 1];
    for (i, b) in buf.iter_mut().enumerate() {
        // SAFETY: p..p+TASK_COMM_LEN-1 validated < USER_VA_END above; CPL=0 byte read through the caller's live AS at the prctl-supplied name pointer.
        *b = unsafe { core::ptr::read_volatile((p + i as u64) as *const u8) };
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    cur.set_comm_raw(&buf[..len]);
    0
}

/// `prctl(PR_GET_NAME, buf)` — Linux `copy_to_user(arg2, comm, TASK_COMM_LEN)`.
/// Always writes the full NUL-padded `TASK_COMM_LEN` bytes of THIS thread's
/// current `comm`.
/// # C: O(TASK_COMM_LEN)
pub fn sys_get_name(cur: &Task, args: &SyscallArgs) -> i64 {
    let p = args.a1;
    if p == 0 || p.checked_add(TASK_COMM_LEN as u64).map_or(true, |e| e > hal::USER_VA_END) {
        return -(Errno::Efault.as_i32() as i64);
    }
    let buf = cur.comm_bytes();
    // SAFETY: p..p+TASK_COMM_LEN validated < USER_VA_END above; CPL=0 write through the caller's live AS at the prctl-supplied name buffer.
    unsafe {
        for (i, b) in buf.iter().enumerate() {
            core::ptr::write_volatile((p + i as u64) as *mut u8, *b);
        }
    }
    0
}

/// `prctl(PR_SET_DUMPABLE, v)` — the argument rule lives in
/// `decide::classify` (Linux accepts only 0 and 1 here; 2 is a state the
/// kernel enters by itself on a privilege change).
/// # C: O(1)
pub fn set_dumpable(cur: &Task, v: u8) -> i64 {
    cur.dumpable.store(v, Ordering::Release);
    0
}

/// Compatibility entry for the pre-split hosted tests and any caller that
/// still hands over raw `SyscallArgs`. Applies the same Linux rule.
/// # C: O(1)
pub fn sys_set_dumpable(cur: &Task, args: &SyscallArgs) -> i64 {
    match super::decide::classify(super::uapi::PR_SET_DUMPABLE, args.a1, 0, 0, 0) {
        Ok(super::decide::Op::SetDumpable(v)) => set_dumpable(cur, v),
        Ok(_) => -(Errno::Einval.as_i32() as i64),
        Err(e) => -(e.as_i32() as i64),
    }
}
