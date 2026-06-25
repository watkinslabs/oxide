// Memory syscalls (docs/59§6 G3). Raw wrappers; the malloc arena that
// uses them lands at G5. mmap returns MAP_FAILED (-1) + errno on failure;
// the others use the -1/errno convention.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys1, sys2, sys3, sys6};
use crate::internal::errno::{ret, ret_isize, set};
use crate::internal::nr;

const ENOMEM: i32 = 12;

// mmap prot/flags (same numeric values on x86_64 and aarch64).
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;
pub const MAP_PRIVATE: i32 = 0x2;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_FAILED: *mut u8 = usize::MAX as *mut u8;

// # C: void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
#[no_mangle]
pub unsafe extern "C" fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8 {
    // SAFETY: mmap(2); the kernel validates addr/len/fd and never writes
    // through `addr` itself — it only maps. Returns -errno on failure.
    let r = unsafe { sys6(nr::MMAP, addr as usize, len, prot as usize, flags as usize, fd as usize, off as usize) };
    match ret(r) {
        Ok(v) => v as *mut u8,
        Err(e) => { set(e); usize::MAX as *mut u8 } // MAP_FAILED
    }
}
// # C: void *__mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
#[no_mangle]
pub unsafe extern "C" fn __mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8 {
    // SAFETY: __mmap has the same ABI and scalar mapping contract as mmap.
    unsafe { mmap(addr, len, prot, flags, fd, off) }
}

// # C: void *mmap64(...) — LFS alias (off64_t == off_t on LP64)
#[no_mangle]
pub unsafe extern "C" fn mmap64(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8 {
    // SAFETY: identical to mmap on LP64; forwards unchanged.
    unsafe { mmap(addr, len, prot, flags, fd, off) }
}

// # C: int munmap(void *addr, size_t len)
#[no_mangle]
pub unsafe extern "C" fn munmap(addr: *mut u8, len: usize) -> i32 {
    // SAFETY: munmap(2) takes scalar addr/len; no libc-side deref.
    ret_isize(unsafe { sys2(nr::MUNMAP, addr as usize, len) }) as i32
}
// # C: int __munmap(void *addr, size_t len)
#[no_mangle]
pub unsafe extern "C" fn __munmap(addr: *mut u8, len: usize) -> i32 {
    // SAFETY: __munmap has the same scalar addr/len contract as munmap.
    unsafe { munmap(addr, len) }
}

// # C: int mprotect(void *addr, size_t len, int prot)
#[no_mangle]
pub unsafe extern "C" fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32 {
    // SAFETY: mprotect(2) takes scalar addr/len/prot; no libc-side deref.
    ret_isize(unsafe { sys3(nr::MPROTECT, addr as usize, len, prot as usize) }) as i32
}

// # C: int brk(void *addr) — glibc convention: 0 on success, -1/errno.
#[no_mangle]
pub unsafe extern "C" fn brk(addr: *mut u8) -> i32 {
    // SAFETY: brk(2) returns the resulting program break (a scalar); no
    // memory is dereferenced by libc here.
    let new = unsafe { sys1(nr::BRK, addr as usize) } as usize;
    if new >= addr as usize { 0 } else { set(ENOMEM); -1 }
}
