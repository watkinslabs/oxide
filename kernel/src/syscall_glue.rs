// Glue between the per-arch syscall asm stub and the architecture-
// neutral `syscall::dispatch` table per `15§4`.
//
// Both arches' asm stubs reference `oxide_syscall_dispatch` by symbol;
// `extern "C"` + `#[no_mangle]` here makes the linker resolve it to
// the kernel-side wrapper that:
//   1. packs the asm-shuffled regs into `SyscallArgs`,
//   2. calls `syscall::dispatch(nr, &args) -> i64`,
//   3. returns the result as `u64` placed in rax (x86) / x0 (arm)
//      per `15§1.3` so a libc-style `rv > -4096UL` failure check
//      works userspace-side.
//
// arch-specific interceptions (e.g., x86 `sys_arch_prctl`) live
// here behind cfg gates because they need to call into `hal-<arch>`.

#![cfg(target_os = "oxide-kernel")]

use syscall::{dispatch, SyscallArgs};
use syscall::errno::Errno;
use hal::{TimerOps, USER_VA_END};

#[cfg(target_arch = "x86_64")]
const SYSCALL_NR_ARCH_PRCTL: u64 = 158;
#[cfg(target_arch = "x86_64")]
const ARCH_SET_FS: u64 = 0x1002;
#[cfg(target_arch = "x86_64")]
const ARCH_GET_FS: u64 = 0x1003;

const SYSCALL_NR_CLOCK_GETTIME: u64 = 228;
const SYSCALL_NR_UNAME: u64          = 63;
const SYSCALL_NR_MMAP: u64           = 9;
const SYSCALL_NR_MUNMAP: u64         = 11;

const NS_PER_SEC: u64 = 1_000_000_000;

/// `struct utsname` field width per Linux. Six fixed-length C
/// strings, NUL-terminated, total 6 × 65 = 390 bytes.
const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

/// Per-arch machine identifier returned by `uname.machine`.
#[cfg(target_arch = "x86_64")]
const UNAME_MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const UNAME_MACHINE: &[u8] = b"aarch64";

/// Write the 6 utsname fields at consecutive 65-byte slots starting
/// at `tp`. Each field is the source bytes followed by NUL padding
/// out to 65 B. Caller validates `tp` range.
unsafe fn write_utsname_field(tp: u64, off: usize, src: &[u8]) {
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    for i in 0..n {
        // SAFETY: caller validated [tp, tp + UTSNAME_TOTAL_LEN) lies entirely below USER_VA_END and is mapped writable; CPL=0 ignores the leaf U bit so direct writes land in the user page.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, src[i]); }
    }
    for i in n..UTSNAME_FIELD_LEN {
        // SAFETY: same range as above; pads out the field with NUL.
        unsafe { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, 0u8); }
    }
}

/// `sys_mmap(addr, len, prot, flags, fd, off)` — slot 9. Routes to
/// the real `vmm::AddressSpace::mmap` per `11§3`/`11§6` via the
/// `crate::user_as` integration. v1 supports only
/// `MAP_ANONYMOUS | MAP_PRIVATE` with `addr=NULL` / `fd=-1`; pages
/// are demand-faulted in by `user_as::user_fault_handler` per
/// `11§5`. No upfront frame allocation — first user access faults.
fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd = args.a4 as i64;
    match crate::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}

/// `sys_munmap(addr, len)` — slot 11. Routes to
/// `vmm::AddressSpace::munmap` + per-page PT unmap + frame free per
/// `11§6` via the `crate::user_as` integration. Replaces the no-op
/// stub in `crates/syscall::dispatch::sys_munmap` (the in-table
/// stub still exists as a fallback when glue isn't routing — but
/// glue now intercepts nr=11 first so it's dead-path).
fn kernel_munmap(args: &SyscallArgs) -> i64 {
    crate::user_as::glue_munmap(args.a0, args.a1)
}

fn kernel_uname(args: &SyscallArgs) -> i64 {
    let tp = args.a0;
    if let Err(rv) = validate_user_buf(tp, UTSNAME_TOTAL_LEN as u64, 1) { return rv; }
    // SAFETY: range validated above; user-half VA is mapped writable
    // by the userspace-smoke setup. Each field write iterates byte-
    // by-byte so no alignment requirement.
    unsafe {
        write_utsname_field(tp, 0 * UTSNAME_FIELD_LEN, b"oxide");
        write_utsname_field(tp, 1 * UTSNAME_FIELD_LEN, b"oxide");                  // nodename
        write_utsname_field(tp, 2 * UTSNAME_FIELD_LEN, b"0.1.0-pre");              // release
        write_utsname_field(tp, 3 * UTSNAME_FIELD_LEN, b"oxide #1 SMP PREEMPT");  // version
        write_utsname_field(tp, 4 * UTSNAME_FIELD_LEN, UNAME_MACHINE);             // machine
        write_utsname_field(tp, 5 * UTSNAME_FIELD_LEN, b"(none)");                 // domainname
    }
    0
}

/// Validate that a user buffer `[ptr, ptr + len)` lies entirely
/// below `USER_VA_END` and is `align`-byte aligned at `ptr`.
/// Returns Ok(()) or Err(-EFAULT-as-i64) ready to return from a
/// glue handler.
fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    if ptr == 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if align > 1 && (ptr & (align - 1)) != 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    Ok(())
}

/// Read the per-arch monotonic clock and write `{tv_sec, tv_nsec}`
/// to the user `timespec*`. Both arches' `TimerOps::monotonic_ns`
/// returns 0 until calibrated, so a CLOCK_MONOTONIC reading at
/// boot-time may legitimately be 0.
///
/// v1: ignore clk_id; CLOCK_REALTIME and CLOCK_MONOTONIC alike use
/// the kernel monotonic counter (no wall-time RTC source yet).
fn kernel_clock_gettime(args: &SyscallArgs) -> i64 {
    let _clk_id = args.a0;
    let tp = args.a1;
    if let Err(rv) = validate_user_buf(tp, 16, 8) { return rv; }

    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;

    let tv_sec  = ns / NS_PER_SEC;
    let tv_nsec = ns % NS_PER_SEC;
    // SAFETY: `tp` validated 16-byte range below USER_VA_END + 8-byte
    // aligned. CPL=0 ignores the leaf U bit so the kernel can write
    // the user mapping directly.
    unsafe {
        core::ptr::write_volatile(tp as *mut u64,         tv_sec);
        core::ptr::write_volatile((tp + 8) as *mut u64,   tv_nsec);
    }
    0
}

/// x86-specific syscall handled in the kernel-side glue (since
/// `crates/syscall` is arch-neutral and can't call `hal-x86_64`).
/// Only `ARCH_SET_FS` and `ARCH_GET_FS` are implemented; other
/// codes return -EINVAL. v1 single-thread → ARCH_GET_FS reads
/// IA32_FS_BASE via rdmsr (added if needed); v1 just returns 0.
#[cfg(target_arch = "x86_64")]
fn kernel_arch_prctl(args: &SyscallArgs) -> i64 {
    let code = args.a0;
    let val  = args.a1;
    match code {
        ARCH_SET_FS => {
            // Reject non-canonical / kernel-VA addresses.
            if val >= USER_VA_END {
                return -(Errno::Efault.as_i32() as i64);
            }
            // SAFETY: val is a user-canonical address per the check
            // above; wrmsr IA32_FS_BASE = val updates the per-CPU
            // segment base used by user-mode `fs:` accesses.
            unsafe { hal_x86_64::set_user_fs_base(val); }
            0
        }
        ARCH_GET_FS => {
            // v1: report 0; once we read FS_BASE back, return that.
            0
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

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
    // Arch-specific + per-arch-time syscalls handled here (kernel can
    // call hal); others fall through to the arch-neutral dispatch.
    let rv = match nr {
        #[cfg(target_arch = "x86_64")]
        SYSCALL_NR_ARCH_PRCTL    => kernel_arch_prctl(&args),
        SYSCALL_NR_CLOCK_GETTIME => kernel_clock_gettime(&args),
        SYSCALL_NR_UNAME         => kernel_uname(&args),
        SYSCALL_NR_MMAP          => kernel_mmap(&args),
        SYSCALL_NR_MUNMAP        => kernel_munmap(&args),
        _                        => dispatch(nr as u32, &args),
    };
    debug_sched! {
        klog::write_raw(b"[INFO]  syscall: nr=");
        klog::write_hex_u64(nr);
        klog::write_raw(b" rv=");
        klog::write_hex_u64(rv as u64);
        klog::write_raw(b"\n");
    }
    rv as u64
}
