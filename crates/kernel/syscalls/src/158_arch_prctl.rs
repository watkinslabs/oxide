// 158 arch_prctl — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// arch_prctl: ARCH_SET_FS=wrmsr, ARCH_GET_FS=rdmsr+writeback,
/// else EINVAL. GS-base is a follow-up (kernel GS-base reserved).
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let code = args.a0;
    let val  = args.a1;
    match code {
        syscall::nrs::ARCH_SET_FS => {
            // Reject non-canonical / kernel-VA addresses.
            if val >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: val is a user-canonical address per the check
            // above; wrmsr IA32_FS_BASE = val updates the per-CPU
            // segment base used by user-mode `fs:` accesses.
            unsafe { hal_x86_64::set_user_fs_base(val); }
            // B38: keep the saved arch_ctx.fs_base in sync with the
            // live MSR. Without this, a fork() that lands before the
            // next context switch reads a stale arch_ctx.fs_base (often
            // 0) for the child's inherited TLS pointer. The fork path
            // also now reads the live MSR directly (spawn.rs), but
            // mirroring here keeps the field a valid cache for any
            // other consumer that reads arch_ctx.
            if let Some(cur) = sched::live::current() {
                // SAFETY: current is the running task on this CPU;
                // arch_ctx is single-mutator per `13§5`; we are on
                // its own syscall path so no concurrent writer.
                unsafe {
                    let p: *mut hal_x86_64::ContextX86_64 = cur.arch_ctx_ptr();
                    (*p).fs_base = val;
                }
            }
            0
        }
        syscall::nrs::ARCH_GET_FS => {
            // val is a user pointer to a u64 receiving FS_BASE.
            if val == 0 || val >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: rdmsr IA32_FS_BASE is privileged; no memory effect.
            let base = unsafe { hal_x86_64::get_user_fs_base() };
            // SAFETY: val validated < USER_VA_END; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(val as *mut u64, base); }
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
