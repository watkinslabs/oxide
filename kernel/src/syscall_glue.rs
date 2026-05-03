// Glue between the x86_64 syscall asm stub (in `hal-x86_64/syscall.rs`)
// and the architecture-neutral `syscall::dispatch` table per `15§4`.
//
// The asm stub references `oxide_syscall_dispatch` by symbol;
// `extern "C"` + `#[no_mangle]` here makes the linker resolve it to
// the kernel-side wrapper that:
//   1. packs the asm-shuffled regs into `SyscallArgs`,
//   2. calls `syscall::dispatch(nr, &args) -> i64`,
//   3. returns the result as `u64` (rax) per `15§1.3` so a libc-style
//      `rv > -4096UL` failure check works userspace-side.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use syscall::{dispatch, SyscallArgs};

/// SysV-ABI hook invoked by `oxide_syscall_entry`. Stack-switched +
/// arg-shuffled by the asm stub before this is called.
///
/// # SAFETY: caller is the syscall asm stub; runs single-CPU with
/// IF=0 (FMASK cleared). Returns a u64 placed in rax for sysretq.
/// # C: O(1) + dispatch fn cost
#[no_mangle]
pub unsafe extern "C" fn oxide_syscall_dispatch(
    nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
) -> u64 {
    let args = SyscallArgs { a0, a1, a2, a3, a4, a5: 0 };
    let rv = dispatch(nr as u32, &args);
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    rv as u64
}
