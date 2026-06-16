// statfs/fstatfs + statvfs/fstatvfs (docs/59§6 — G19 audit; `df`, coreutils).
// On LP64 the kernel `struct statfs` (120 B, 8-byte words) IS glibc's public
// `struct statfs`, so statfs/fstatfs pass the buffer straight through. statvfs
// is a DIFFERENT struct (112 B) glibc derives from a statfs(2) call — we
// replicate glibc's field mapping (favail=ffree, namemax=namelen, frsize
// fallback, f_flag from the kernel ST_VALID flags word).
#![cfg(feature = "freestanding")]
use core::ffi::c_char;
use crate::arch::syscall::{sys2};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// Kernel struct statfs (asm-generic, LP64): 15 × 8-byte words = 120 bytes.
#[repr(C)]
struct KStatfs {
    f_type: u64, f_bsize: u64, f_blocks: u64, f_bfree: u64, f_bavail: u64,
    f_files: u64, f_ffree: u64, f_fsid: u64, f_namelen: u64, f_frsize: u64,
    f_flags: u64, f_spare: [u64; 4],
}
// glibc struct statvfs (LP64): 112 bytes.
#[repr(C)]
struct Statvfs {
    f_bsize: u64, f_frsize: u64, f_blocks: u64, f_bfree: u64, f_bavail: u64,
    f_files: u64, f_ffree: u64, f_favail: u64, f_fsid: u64, f_flag: u64,
    f_namemax: u64, f_spare: [i32; 6],
}
const ST_VALID: u64 = 0x0020; // kernel sets this in f_flags when the mount flags are valid

// # C: int statfs(const char *path, struct statfs *buf)
#[no_mangle]
pub unsafe extern "C" fn statfs(path: *const c_char, buf: *mut core::ffi::c_void) -> i32 {
    // SAFETY: path NUL-terminated; buf a 120-byte struct statfs the kernel fills.
    ret_isize(unsafe { sys2(nr::STATFS, path as usize, buf as usize) }) as i32
}
// # C: int fstatfs(int fd, struct statfs *buf)
#[no_mangle]
pub unsafe extern "C" fn fstatfs(fd: i32, buf: *mut core::ffi::c_void) -> i32 {
    // SAFETY: buf is a 120-byte struct statfs the kernel fills for fd.
    ret_isize(unsafe { sys2(nr::FSTATFS, fd as usize, buf as usize) }) as i32
}
// LFS aliases — identical on LP64.
// SAFETY: statfs64 == statfs on LP64; same path+buffer contract.
#[no_mangle] pub unsafe extern "C" fn statfs64(p: *const c_char, b: *mut core::ffi::c_void) -> i32 { unsafe { statfs(p, b) } }
// SAFETY: fstatfs64 == fstatfs on LP64; same fd+buffer contract.
#[no_mangle] pub unsafe extern "C" fn fstatfs64(fd: i32, b: *mut core::ffi::c_void) -> i32 { unsafe { fstatfs(fd, b) } }

// Map a filled kernel statfs into glibc's struct statvfs (glibc internal_statvfs).
unsafe fn fill_statvfs(ks: &KStatfs, out: *mut Statvfs) {
    // SAFETY: out is a writable 112-byte struct statvfs on the caller's frame;
    // we copy the statfs fields glibc surfaces and zero the spare words.
    unsafe {
        (*out).f_bsize = ks.f_bsize;
        (*out).f_frsize = if ks.f_frsize != 0 { ks.f_frsize } else { ks.f_bsize };
        (*out).f_blocks = ks.f_blocks;
        (*out).f_bfree = ks.f_bfree;
        (*out).f_bavail = ks.f_bavail;
        (*out).f_files = ks.f_files;
        (*out).f_ffree = ks.f_ffree;
        (*out).f_favail = ks.f_ffree; // glibc: favail = ffree
        (*out).f_fsid = ks.f_fsid;
        (*out).f_namemax = ks.f_namelen;
        // Modern kernels set ST_VALID; glibc then uses the flags word directly.
        (*out).f_flag = if ks.f_flags & ST_VALID != 0 { ks.f_flags & !ST_VALID } else { 0 };
        (*out).f_spare = [0; 6];
    }
}

// # C: int statvfs(const char *path, struct statvfs *buf)
#[no_mangle]
pub unsafe extern "C" fn statvfs(path: *const c_char, buf: *mut core::ffi::c_void) -> i32 {
    // SAFETY: path NUL; we statfs into a local KStatfs then translate into buf.
    unsafe {
        let mut ks: KStatfs = core::mem::zeroed();
        let r = sys2(nr::STATFS, path as usize, &mut ks as *mut _ as usize);
        if r < 0 { return ret_isize(r) as i32; }
        fill_statvfs(&ks, buf as *mut Statvfs);
        0
    }
}
// # C: int fstatvfs(int fd, struct statvfs *buf)
#[no_mangle]
pub unsafe extern "C" fn fstatvfs(fd: i32, buf: *mut core::ffi::c_void) -> i32 {
    // SAFETY: fstatfs into a local KStatfs then translate into buf.
    unsafe {
        let mut ks: KStatfs = core::mem::zeroed();
        let r = sys2(nr::FSTATFS, fd as usize, &mut ks as *mut _ as usize);
        if r < 0 { return ret_isize(r) as i32; }
        fill_statvfs(&ks, buf as *mut Statvfs);
        0
    }
}
// SAFETY: statvfs64 == statvfs on LP64; same path+buffer contract.
#[no_mangle] pub unsafe extern "C" fn statvfs64(p: *const c_char, b: *mut core::ffi::c_void) -> i32 { unsafe { statvfs(p, b) } }
// SAFETY: fstatvfs64 == fstatvfs on LP64; same fd+buffer contract.
#[no_mangle] pub unsafe extern "C" fn fstatvfs64(fd: i32, b: *mut core::ffi::c_void) -> i32 { unsafe { fstatvfs(fd, b) } }
