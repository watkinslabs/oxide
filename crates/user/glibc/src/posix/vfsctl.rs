// Mount/sync/swap control (docs/59§6 G8). Thin syscall wrappers; all require
// CAP_SYS_ADMIN so they fail EPERM as non-root (still ABI-correct). sync(2)
// returns void; the others use the -1/errno convention. Both arches share the
// slots (asm-generic + x86_64).
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys0, sys1, sys2, sys5};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// umount2(2) flags.
pub const MNT_FORCE: i32 = 1;
pub const MNT_DETACH: i32 = 2;
pub const MNT_EXPIRE: i32 = 4;
pub const UMOUNT_NOFOLLOW: i32 = 8;

// # C: int mount(const char *src, const char *tgt, const char *fstype,
//                unsigned long flags, const void *data)
#[no_mangle]
pub unsafe extern "C" fn mount(src: *const u8, tgt: *const u8, fstype: *const u8, flags: u64, data: *const u8) -> i32 {
    // SAFETY: mount(2); src/tgt/fstype are NUL-terminated strings and data is a
    // fs-specific buffer; the kernel reads them from the caller address space.
    ret_isize(unsafe { sys5(nr::MOUNT, src as usize, tgt as usize, fstype as usize, flags as usize, data as usize) }) as i32
}
// # C: int umount(const char *target) — legacy 1-arg form via umount2(tgt, 0).
#[no_mangle]
pub unsafe extern "C" fn umount(target: *const u8) -> i32 {
    // SAFETY: target NUL-terminated; composes umount2 with flags 0 (asm-generic
    // has no plain umount, so this is the canonical path on both arches).
    ret_isize(unsafe { sys2(nr::UMOUNT2, target as usize, 0) }) as i32
}
// # C: int umount2(const char *target, int flags)
#[no_mangle]
pub unsafe extern "C" fn umount2(target: *const u8, flags: i32) -> i32 {
    // SAFETY: target NUL-terminated; umount2(2) reads it from caller memory.
    ret_isize(unsafe { sys2(nr::UMOUNT2, target as usize, flags as usize) }) as i32
}
// # C: void sync(void)
#[no_mangle]
pub unsafe extern "C" fn sync() {
    // SAFETY: sync(2) takes no args and cannot fail; no memory dereferenced.
    unsafe { sys0(nr::SYNC); }
}
// # C: int syncfs(int fd)
#[no_mangle]
pub unsafe extern "C" fn syncfs(fd: i32) -> i32 {
    // SAFETY: syncfs(2) takes a scalar fd; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::SYNCFS, fd as usize) }) as i32
}
// # C: int swapon(const char *path, int swapflags)
#[no_mangle]
pub unsafe extern "C" fn swapon(path: *const u8, swapflags: i32) -> i32 {
    // SAFETY: path NUL-terminated; swapon(2) reads it from caller memory.
    ret_isize(unsafe { sys2(nr::SWAPON, path as usize, swapflags as usize) }) as i32
}
// # C: int swapoff(const char *path)
#[no_mangle]
pub unsafe extern "C" fn swapoff(path: *const u8) -> i32 {
    // SAFETY: path NUL-terminated; swapoff(2) reads it from caller memory.
    ret_isize(unsafe { sys1(nr::SWAPOFF, path as usize) }) as i32
}
