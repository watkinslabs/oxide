// 131 sigaltstack — one syscall, one file (docs/53 §0). Moved verbatim from signal.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

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
        if oldss >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let sp    = cur.sigaltstack_sp.load(Ordering::Acquire);
        let size  = cur.sigaltstack_size.load(Ordering::Acquire);
        let flags = cur.sigaltstack_flags.load(Ordering::Acquire);
        // SAFETY: oldss validated < USER_VA_END; CPL=0 writes through caller's AS.
        unsafe {
            core::ptr::write_volatile(oldss        as *mut u64, sp);
            core::ptr::write_volatile((oldss + 8)  as *mut i32, flags as i32);
            core::ptr::write_volatile((oldss + 16) as *mut u64, size);
        }
    }
    if ss != 0 {
        if ss >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: ss validated < USER_VA_END; struct sigaltstack layout {sp, flags, size}; CPL=0 reads through caller's AS.
        let sp:    u64 = unsafe { core::ptr::read_volatile(ss as *const u64) };
        // SAFETY: ss+8 still inside 24-byte struct sigaltstack; aligned i32 read.
        let flags: i32 = unsafe { core::ptr::read_volatile((ss + 8) as *const i32) };
        // SAFETY: ss+16 still inside 24-byte struct sigaltstack; aligned u64 read.
        let size:  u64 = unsafe { core::ptr::read_volatile((ss + 16) as *const u64) };
        cur.sigaltstack_sp.store(sp, Ordering::Release);
        cur.sigaltstack_size.store(size, Ordering::Release);
        cur.sigaltstack_flags.store(flags as u32, Ordering::Release);
    }
    0
}
