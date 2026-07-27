// 131 sigaltstack — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use sched::sigaltstack::{self as sas, AltStack, AltStackError};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `struct stack_t { void *ss_sp; int ss_flags; size_t ss_size; }` — 24 bytes
/// on both LP64 arches (4 bytes of tail padding after `ss_flags`).
const STACK_T_BYTES: u64 = 24;
/// Byte offset of `ss_flags` in `stack_t`.
const SS_FLAGS_OFF: u64 = 8;
/// Byte offset of `ss_size` in `stack_t`.
const SS_SIZE_OFF: u64 = 16;

/// `sys_sigaltstack(ss, oss)` — slot 131.
///
/// Linux `SYSCALL_DEFINE2(sigaltstack)` → `do_sigaltstack`, in that ORDER:
///   1. `copy_from_user(&new, uss)` → EFAULT. Reading `ss` comes FIRST.
///   2. `oss` is filled into a KERNEL local, not user memory yet.
///   3. `ss` is validated: EPERM if the caller is executing on the alternate
///      stack right now, then EINVAL for an `ss_flags` mode outside
///      `{0, SS_ONSTACK, SS_DISABLE}`, then ENOMEM for `ss_size <
///      MINSIGSTKSZ`. An unchanged request short-circuits before the size
///      check, so re-asserting a legacy undersized stack still succeeds.
///   4. ONLY on success is `oss` copied out → EFAULT.
///
/// Writing `oss` before validating `ss` — as a naive implementation does —
/// leaves the old stack reported even when the call is about to fail, and
/// silently accepts every rejected request.
///
/// `oss.ss_flags` is `sas_ss_flags()`: the LIVE mode (SS_DISABLE when
/// disarmed, SS_ONSTACK while executing on it) plus the stored SS_AUTODISARM
/// bit — not the flags word that was stored.
/// # C: O(1)
pub fn sys_sigaltstack(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let ss    = args.a0;
    let oss   = args.a1;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
    };
    let mut new = None;
    if ss != 0 {
        if let Err(rv) = validate_user_buf(ss, STACK_T_BYTES, 1) { return rv; }
        new = Some(read_stack_t(ss));
    }
    let user_sp = ::fs::sig_dispatch::current_user_sp();
    let old = cur.altstack();
    // `oss` is snapshotted BEFORE `ss` is applied — a call that both reads and
    // writes reports the stack as it was on entry.
    let old_reported = AltStack { flags: sas::sas_ss_flags(user_sp, old), ..old };
    if let Some(req) = new {
        match sas::apply(user_sp, old, req) {
            Ok(Some(store)) => cur.set_altstack(store),
            Ok(None) => {}
            Err(e) => return -(errno_for(e).as_i32() as i64),
        }
    }
    if oss != 0 {
        if let Err(rv) = validate_user_buf_writable(oss, STACK_T_BYTES, 1) { return rv; }
        write_stack_t(oss, old_reported);
    }
    0
}

/// Map a `do_sigaltstack` rejection onto its Linux errno. # C: O(1)
fn errno_for(e: AltStackError) -> syscall::errno::Errno {
    use syscall::errno::Errno;
    match e {
        AltStackError::Eperm  => Errno::Eperm,
        AltStackError::Einval => Errno::Einval,
        AltStackError::Enomem => Errno::Enomem,
    }
}

/// Decode a user `stack_t`. Caller must have validated `p` readable for
/// `STACK_T_BYTES`. # C: O(1)
fn read_stack_t(p: u64) -> AltStack {
    // SAFETY: caller validated p readable for STACK_T_BYTES, which covers all
    // three fields (highest is SS_SIZE_OFF + 8 = 24).
    unsafe {
        AltStack {
            sp:    core::ptr::read_unaligned(p as *const u64),
            flags: core::ptr::read_unaligned((p + SS_FLAGS_OFF) as *const i32),
            size:  core::ptr::read_unaligned((p + SS_SIZE_OFF) as *const u64),
        }
    }
}

/// Encode a user `stack_t`, zeroing the tail padding Linux's `memset(oss, 0,
/// sizeof(stack_t))` clears. Caller must have validated `p` writable for
/// `STACK_T_BYTES`. # C: O(1)
fn write_stack_t(p: u64, a: AltStack) {
    // SAFETY: caller validated p writable for STACK_T_BYTES, which covers the
    // zero-fill and all three field offsets.
    unsafe {
        core::ptr::write_bytes(p as *mut u8, 0, STACK_T_BYTES as usize);
        core::ptr::write_unaligned(p as *mut u64, a.sp);
        core::ptr::write_unaligned((p + SS_FLAGS_OFF) as *mut i32, a.flags);
        core::ptr::write_unaligned((p + SS_SIZE_OFF) as *mut u64, a.size);
    }
}
