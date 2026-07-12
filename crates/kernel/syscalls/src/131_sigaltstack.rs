// 131 sigaltstack — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `sys_sigaltstack(ss, oldss)` — slot 131.
/// # C: O(1)
pub fn sys_sigaltstack(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let ss    = args.a0;
    let oldss = args.a1;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
    };
    if oldss != 0 {
        if let Err(rv) = validate_user_buf_writable(oldss, 24, 1) { return rv; }
        let sp    = cur.sigaltstack_sp.load(Ordering::Acquire);
        let size  = cur.sigaltstack_size.load(Ordering::Acquire);
        let flags = cur.sigaltstack_flags.load(Ordering::Acquire);
        // SAFETY: oldss validated writable for the 24-byte sigaltstack result.
        unsafe {
            core::ptr::write_unaligned(oldss        as *mut u64, sp);
            core::ptr::write_unaligned((oldss + 8)  as *mut i32, flags as i32);
            core::ptr::write_unaligned((oldss + 16) as *mut u64, size);
        }
    }
    if ss != 0 {
        if let Err(rv) = validate_user_buf(ss, 24, 1) { return rv; }
        // SAFETY: ss validated readable for struct sigaltstack {sp, flags, size}.
        let sp:    u64 = unsafe { core::ptr::read_unaligned(ss as *const u64) };
        // SAFETY: ss+8 is inside the validated 24-byte struct sigaltstack.
        let flags: i32 = unsafe { core::ptr::read_unaligned((ss + 8) as *const i32) };
        // SAFETY: ss+16 is inside the validated 24-byte struct sigaltstack.
        let size:  u64 = unsafe { core::ptr::read_unaligned((ss + 16) as *const u64) };
        cur.sigaltstack_sp.store(sp, Ordering::Release);
        cur.sigaltstack_size.store(size, Ordering::Release);
        cur.sigaltstack_flags.store(flags as u32, Ordering::Release);
    }
    0
}
