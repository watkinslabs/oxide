// `prctl(PR_SET_NAME / PR_GET_NAME / PR_SET_DUMPABLE / PR_GET_DUMPABLE)` —
// Linux `strncpy_from_user` + `set_task_comm`, `get_task_comm` +
// `copy_to_user`, `task_exec_state_{set,get}_dumpable`.

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
    // `strncpy_from_user` stops at the first NUL, so a short name at the end
    // of a mapping is accepted; range-checking the whole span up front made
    // that EFAULT. Its copy carries the exception-table fixups, which a raw
    // byte read does not.
    match uaccess::strncpy_from_user(args.a1, (TASK_COMM_LEN - 1) as u64) {
        Ok(name) => { cur.set_comm_raw(&name); 0 }
        Err(e) => -(e.as_i32() as i64),
    }
}

/// `prctl(PR_GET_NAME, buf)` — Linux `copy_to_user(arg2, comm, TASK_COMM_LEN)`.
/// Always writes the full NUL-padded `TASK_COMM_LEN` bytes of THIS thread's
/// current `comm`.
/// # C: O(TASK_COMM_LEN)
pub fn sys_get_name(cur: &Task, args: &SyscallArgs) -> i64 {
    match uaccess::copy_to_user(args.a1, &cur.comm_bytes()) {
        Ok(()) => 0,
        Err(e) => -(e.as_i32() as i64),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::SchedClass;

    fn args1(a1: u64) -> SyscallArgs { SyscallArgs { a0: 0, a1, a2: 0, a3: 0, a4: 0, a5: 0 } }
    fn task() -> Task { Task::new(1, "name-test", SchedClass::Normal { weight: 1024 }) }
    fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

    /// `strncpy_from_user` stops at the NUL, so only the bytes up to it are
    /// the name — the tail of the caller's buffer is not part of it.
    #[test]
    fn set_name_takes_the_bytes_before_the_first_nul() {
        let t = task();
        let src = *b"init\0XXXXXXXXXX";
        assert_eq!(sys_set_name(&t, &args1(src.as_ptr() as u64)), 0);
        assert_eq!(t.comm_bytes(), *b"init\0\0\0\0\0\0\0\0\0\0\0\0");
    }

    /// A name that fills the span with no NUL keeps `TASK_COMM_LEN - 1`
    /// bytes; Linux reserves the last byte for the terminator.
    #[test]
    fn set_name_truncates_at_task_comm_len_minus_one() {
        let t = task();
        let src = *b"0123456789abcdefghij";
        assert_eq!(sys_set_name(&t, &args1(src.as_ptr() as u64)), 0);
        assert_eq!(&t.comm_bytes()[..TASK_COMM_LEN - 1], b"0123456789abcde");
        assert_eq!(t.comm_bytes()[TASK_COMM_LEN - 1], 0);
    }

    #[test]
    fn set_name_reports_efault_for_a_pointer_the_copy_refuses() {
        let t = task();
        assert_eq!(sys_set_name(&t, &args1(0)), efault());
        assert_eq!(sys_set_name(&t, &args1(hal::USER_VA_END)), efault());
        assert_eq!(t.comm_bytes(), *b"name-test\0\0\0\0\0\0\0", "the name is left alone");
    }

    /// `PR_GET_NAME` writes the whole NUL-padded `TASK_COMM_LEN`, never a
    /// trimmed string.
    #[test]
    fn get_name_writes_the_full_padded_comm() {
        let t = task();
        let mut out = [0xffu8; TASK_COMM_LEN];
        assert_eq!(sys_get_name(&t, &args1(out.as_mut_ptr() as u64)), 0);
        assert_eq!(out, *b"name-test\0\0\0\0\0\0\0");
    }

    #[test]
    fn get_name_reports_efault_for_a_pointer_the_copy_refuses() {
        let t = task();
        assert_eq!(sys_get_name(&t, &args1(0)), efault());
        assert_eq!(sys_get_name(&t, &args1(hal::USER_VA_END)), efault());
    }
}
