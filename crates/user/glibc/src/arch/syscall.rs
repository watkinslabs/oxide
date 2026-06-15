// Raw syscall shim (docs/59§4). The ONLY place that emits the syscall
// instruction; everything in libc calls sys0..sys6 with a `nr::*`
// constant. Linux ABI: return in the [-4095,-1] band = -errno
// (split by `internal::errno::ret`).

// x86_64: nr→rax, args rdi/rsi/rdx/r10/r8/r9, `syscall`, clobbers rcx/r11.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let r;
    // SAFETY: raw x86_64 syscall; caller (a libc wrapper) guarantees nr +
    // arg pointers are valid for that syscall's kernel contract per docs/15.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => r,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    r
}

// aarch64: nr→x8, args x0..x5, `svc #0`, result x0.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn syscall6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let r;
    // SAFETY: raw aarch64 syscall; caller (a libc wrapper) guarantees nr +
    // arg pointers are valid for that syscall's kernel contract per docs/15.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inlateout("x0") a1 => r,
            in("x1") a2, in("x2") a3, in("x3") a4, in("x4") a5, in("x5") a6,
            options(nostack, preserves_flags),
        );
    }
    r
}

// Non-target host (dev box may build the rlib for type-check); no real
// syscall — return -ENOSYS so the symbols resolve. Hosted tests hit the
// host glibc directly, never this.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub unsafe fn syscall6(_nr: usize, _a1: usize, _a2: usize, _a3: usize, _a4: usize, _a5: usize, _a6: usize) -> isize {
    -38
}

// sys0..sys6 over syscall6 with trailing zero args.
#[inline]
pub unsafe fn sys0(nr: usize) -> isize { unsafe { syscall6(nr, 0, 0, 0, 0, 0, 0) } }
#[inline]
pub unsafe fn sys1(nr: usize, a1: usize) -> isize { unsafe { syscall6(nr, a1, 0, 0, 0, 0, 0) } }
#[inline]
pub unsafe fn sys2(nr: usize, a1: usize, a2: usize) -> isize { unsafe { syscall6(nr, a1, a2, 0, 0, 0, 0) } }
#[inline]
pub unsafe fn sys3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize { unsafe { syscall6(nr, a1, a2, a3, 0, 0, 0) } }
#[inline]
pub unsafe fn sys4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize { unsafe { syscall6(nr, a1, a2, a3, a4, 0, 0) } }
#[inline]
pub unsafe fn sys5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize { unsafe { syscall6(nr, a1, a2, a3, a4, a5, 0) } }
#[inline]
pub unsafe fn sys6(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize { unsafe { syscall6(nr, a1, a2, a3, a4, a5, a6) } }
