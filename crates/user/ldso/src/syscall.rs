// Standalone syscalls for the rtld (docs/59§5). The dynamic linker runs
// before libc is relocated, so it cannot call libc — it issues syscalls
// directly. Per-arch numbers inline; grows with the ladder.
#![cfg(feature = "freestanding")]
#![allow(dead_code)]

pub const AT_FDCWD: isize = -100;
pub const F_OK: usize = 0;
pub const O_RDONLY: usize = 0;
pub const PROT_READ: usize = 1;
pub const PROT_WRITE: usize = 2;
pub const PROT_EXEC: usize = 4;
pub const MAP_PRIVATE: usize = 0x02;
pub const MAP_FIXED: usize = 0x10;
pub const MAP_ANONYMOUS: usize = 0x20;

#[cfg(target_arch = "x86_64")]
mod nr {
    pub const READ: usize = 0;
    pub const CLOSE: usize = 3;
    pub const FSTAT: usize = 5;
    pub const MMAP: usize = 9;
    pub const MPROTECT: usize = 10;
    pub const MUNMAP: usize = 11;
    pub const PREAD64: usize = 17;
    pub const WRITE: usize = 1;
    pub const EXIT_GROUP: usize = 231;
    pub const OPENAT: usize = 257;
    pub const NEWFSTATAT: usize = 262;
    pub const FACCESSAT: usize = 269;
    pub const ARCH_PRCTL: usize = 158;
    pub const ARCH_SET_FS: usize = 0x1002;
}
#[cfg(target_arch = "aarch64")]
mod nr {
    pub const READ: usize = 63;
    pub const CLOSE: usize = 57;
    pub const FSTAT: usize = 80;
    pub const MMAP: usize = 222;
    pub const MPROTECT: usize = 226;
    pub const MUNMAP: usize = 215;
    pub const PREAD64: usize = 67;
    pub const WRITE: usize = 64;
    pub const EXIT_GROUP: usize = 94;
    pub const OPENAT: usize = 56;
    pub const NEWFSTATAT: usize = 79;
    pub const FACCESSAT: usize = 48;
}

pub const NR_EXIT_GROUP: usize = nr::EXIT_GROUP;
pub const NR_WRITE: usize = nr::WRITE;

#[cfg(target_arch = "x86_64")]
unsafe fn syscall(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let r;
    // SAFETY: generic x86_64 syscall — rax=nr, rdi/rsi/rdx/r10/r8/r9 = args,
    // clobbers rcx/r11. Caller guarantees each arg matches the call's contract.
    unsafe {
        core::arch::asm!("syscall", inlateout("rax") n => r, in("rdi") a1, in("rsi") a2,
            in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[cfg(target_arch = "aarch64")]
unsafe fn syscall(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let r;
    // SAFETY: generic aarch64 syscall — x8=nr, x0..x5 = args, x0 = ret.
    // Caller guarantees each arg matches the call's contract.
    unsafe {
        core::arch::asm!("svc 0", in("x8") n, inlateout("x0") a1 => r, in("x1") a2,
            in("x2") a3, in("x3") a4, in("x4") a5, in("x5") a6, options(nostack));
    }
    r
}

/// Set the thread pointer to `tp` (x86_64: arch_prctl ARCH_SET_FS;
/// aarch64: write tpidr_el0). Installs the static TLS block.
/// # C: arch_prctl(ARCH_SET_FS, tp) / msr tpidr_el0, tp
pub unsafe fn set_thread_pointer(tp: usize) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: arch_prctl(ARCH_SET_FS, tp) sets this thread's FS base; the
    // kernel reads no user memory.
    unsafe { syscall(nr::ARCH_PRCTL, nr::ARCH_SET_FS, tp, 0, 0, 0, 0); }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: a single move to the user TLS register; no memory access.
    unsafe { core::arch::asm!("msr tpidr_el0, {}", in(reg) tp); }
}

/// # C: ssize_t write(fd, buf, len)
pub unsafe fn write(fd: i32, buf: &[u8]) -> isize {
    // SAFETY: buf is a live slice passed by ptr/len to write(2).
    unsafe { syscall(nr::WRITE, fd as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0) }
}
/// # C: _Noreturn void exit_group(code)
pub unsafe fn exit_group(code: i32) -> ! {
    // SAFETY: exit_group(2) ends the process and never returns.
    unsafe {
        syscall(nr::EXIT_GROUP, code as usize, 0, 0, 0, 0, 0);
        core::hint::unreachable_unchecked()
    }
}
/// # C: int openat(AT_FDCWD, path, flags, 0)
pub unsafe fn open(path: *const u8, flags: usize) -> isize {
    // SAFETY: path is a NUL-terminated C string valid for openat(2).
    unsafe { syscall(nr::OPENAT, AT_FDCWD as usize, path as usize, flags, 0, 0, 0) }
}
/// # C: int close(fd)
pub unsafe fn close(fd: i32) -> isize {
    // SAFETY: fd is an open descriptor or close returns EBADF harmlessly.
    unsafe { syscall(nr::CLOSE, fd as usize, 0, 0, 0, 0, 0) }
}
/// # C: ssize_t read(fd, buf, len)
pub unsafe fn read(fd: i32, buf: *mut u8, len: usize) -> isize {
    // SAFETY: buf is writable for len bytes; fd is open for reading.
    unsafe { syscall(nr::READ, fd as usize, buf as usize, len, 0, 0, 0) }
}
/// # C: ssize_t pread64(fd, buf, len, off)
pub unsafe fn pread(fd: i32, buf: *mut u8, len: usize, off: u64) -> isize {
    // SAFETY: buf is writable for len bytes; fd is open for reading.
    unsafe { syscall(nr::PREAD64, fd as usize, buf as usize, len, off as usize, 0, 0) }
}
/// # C: int faccessat(AT_FDCWD, path, mode, 0) — 0 if accessible
pub unsafe fn access(path: *const u8, mode: usize) -> isize {
    // SAFETY: path is a NUL-terminated C string valid for faccessat(2).
    unsafe { syscall(nr::FACCESSAT, AT_FDCWD as usize, path as usize, mode, 0, 0, 0) }
}
/// # C: void *mmap(addr, len, prot, flags, fd, off)
pub unsafe fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: i32, off: u64) -> isize {
    // SAFETY: a raw mmap(2); caller owns the resulting mapping and the fd/off
    // describe a valid file window (or MAP_ANONYMOUS with fd=-1).
    unsafe { syscall(nr::MMAP, addr, len, prot, flags, fd as usize, off as usize) }
}
/// # C: int mprotect(addr, len, prot)
pub unsafe fn mprotect(addr: usize, len: usize, prot: usize) -> isize {
    // SAFETY: [addr, addr+len) is a mapping owned by the rtld.
    unsafe { syscall(nr::MPROTECT, addr, len, prot, 0, 0, 0) }
}
/// # C: int munmap(addr, len)
pub unsafe fn munmap(addr: usize, len: usize) -> isize {
    // SAFETY: [addr, addr+len) is a mapping owned by the rtld.
    unsafe { syscall(nr::MUNMAP, addr, len, 0, 0, 0, 0) }
}
