// Standalone syscalls for the rtld (docs/59§5). The dynamic linker runs
// before libc is relocated, so it cannot call libc — it issues syscalls
// directly. Only the calls the loader needs; grows with the ladder
// (G12b adds openat/mmap/close/read). Per-arch numbers inline.
#![cfg(feature = "freestanding")]
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
pub const NR_WRITE: usize = 1;
#[cfg(target_arch = "x86_64")]
pub const NR_EXIT_GROUP: usize = 231;

#[cfg(target_arch = "aarch64")]
pub const NR_WRITE: usize = 64;
#[cfg(target_arch = "aarch64")]
pub const NR_EXIT_GROUP: usize = 94;

#[cfg(target_arch = "x86_64")]
pub unsafe fn sys1(n: usize, a1: usize) -> isize {
    let r;
    // SAFETY: a raw 1-arg syscall; rax=nr, rdi=a1; clobbers rcx/r11 per the
    // x86_64 syscall ABI. Caller guarantees the call's arg contract.
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") n => r, in("rdi") a1,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn sys3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let r;
    // SAFETY: a raw 3-arg syscall; rax=nr, rdi/rsi/rdx=args; clobbers
    // rcx/r11. Caller guarantees the buffers/fds named by the args are valid.
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") n => r, in("rdi") a1,
            in("rsi") a2, in("rdx") a3, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn sys1(n: usize, a1: usize) -> isize {
    let r;
    // SAFETY: a raw 1-arg syscall; x8=nr, x0=a1/ret per the aarch64 ABI.
    unsafe {
        core::arch::asm!("svc 0", in("x8") n, inlateout("x0") a1 => r, options(nostack));
    }
    r
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn sys3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let r;
    // SAFETY: a raw 3-arg syscall; x8=nr, x0..x2=args, x0=ret per the
    // aarch64 ABI. Caller guarantees the args' validity.
    unsafe {
        core::arch::asm!("svc 0", in("x8") n, inlateout("x0") a1 => r,
            in("x1") a2, in("x2") a3, options(nostack));
    }
    r
}

/// Write a byte slice to a fd (debug/diagnostic path before libc exists).
///
/// # C: ssize_t write(fd, buf, len)
pub unsafe fn write(fd: i32, buf: &[u8]) -> isize {
    // SAFETY: buf is a live slice; we pass its ptr/len to write(2).
    unsafe { sys3(NR_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) }
}
