// stat family (docs/59§6 G8, §2). `struct stat` is byte-exact glibc
// layout — and it DIFFERS by arch (x86_64 sizeof 144, aarch64 sizeof 128,
// different field order/sizes), so two #[repr(C)] defs gated per arch with
// compile-time size/offset assertions (checked at each target's build)
// plus a hosted oracle vs libc::stat. All four calls route through
// newfstatat (present on both arches): fstat = newfstatat(fd,"",AT_EMPTY_PATH).
// b"\0" (empty path) is *const u8 directly — avoids the arch-varying c_char cast.
#![allow(clippy::manual_c_str_literals)]

#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    __reserved: [i64; 3],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    __reserved: [i32; 2],
}

// host-target fallback so the rlib type-checks off x86_64/aarch64.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
pub struct stat { pub st_mode: u32, pub st_size: i64 }

// Compile-time ABI goldens (checked at each target's build). abi/<arch>.toml.
#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(core::mem::size_of::<stat>() == 144);
    assert!(core::mem::offset_of!(stat, st_mode) == 24);
    assert!(core::mem::offset_of!(stat, st_size) == 48);
    assert!(core::mem::offset_of!(stat, st_mtime) == 88);
};
#[cfg(target_arch = "aarch64")]
const _: () = {
    assert!(core::mem::size_of::<stat>() == 128);
    assert!(core::mem::offset_of!(stat, st_mode) == 16);
    assert!(core::mem::offset_of!(stat, st_size) == 48);
    assert!(core::mem::offset_of!(stat, st_mtime) == 88);
};

#[cfg(feature = "freestanding")]
pub(crate) use exports::stat_raw;

#[cfg(feature = "freestanding")]
mod exports {
    use super::stat;
    use crate::arch::syscall::sys4;
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;
    use crate::posix::io::AT_FDCWD;

    const AT_SYMLINK_NOFOLLOW: usize = 0x100;
    const AT_EMPTY_PATH: usize = 0x1000;

    // crate-internal stat for glob's GLOB_MARK (buf is a raw byte buffer).
    pub(crate) unsafe fn stat_raw(path: *const u8, buf: *mut u8) -> i32 {
        // SAFETY: path NUL-terminated; buf is ≥ sizeof(struct stat) bytes.
        unsafe { statat(AT_FDCWD, path, buf as *mut stat, 0) }
    }

    unsafe fn statat(dirfd: i32, path: *const u8, buf: *mut stat, flags: usize) -> i32 {
        // SAFETY: path NUL-terminated (or "" with AT_EMPTY_PATH); buf is a
        // valid `struct stat` the kernel fills via newfstatat.
        ret_isize(unsafe { sys4(nr::NEWFSTATAT, dirfd as usize, path as usize, buf as usize, flags) }) as i32
    }

    // # C: int stat(const char *path, struct stat *buf)
    #[no_mangle]
    pub unsafe extern "C" fn stat(path: *const u8, buf: *mut stat) -> i32 {
        // SAFETY: composes newfstatat(AT_FDCWD, path, buf, 0).
        unsafe { statat(AT_FDCWD, path, buf, 0) }
    }
    // # C: int lstat(const char *path, struct stat *buf)
    #[no_mangle]
    pub unsafe extern "C" fn lstat(path: *const u8, buf: *mut stat) -> i32 {
        // SAFETY: composes newfstatat(AT_FDCWD, path, buf, NOFOLLOW).
        unsafe { statat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW) }
    }
    // # C: int fstat(int fd, struct stat *buf)
    #[no_mangle]
    pub unsafe extern "C" fn fstat(fd: i32, buf: *mut stat) -> i32 {
        // SAFETY: composes newfstatat(fd, "", buf, AT_EMPTY_PATH).
        unsafe { statat(fd, b"\0".as_ptr(), buf, AT_EMPTY_PATH) }
    }
    // # C: int fstatat(int dirfd, const char *path, struct stat *buf, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn fstatat(dirfd: i32, path: *const u8, buf: *mut stat, flags: i32) -> i32 {
        // SAFETY: path NUL-terminated; direct newfstatat with caller flags.
        unsafe { statat(dirfd, path, buf, flags as usize) }
    }
    // LFS aliases: on LP64 struct stat64 == struct stat (off64_t == off_t), so
    // these are exact aliases of the base calls (what glibc does).
    // # C: int stat64(const char *, struct stat64 *)
    // SAFETY: LFS alias of stat; identical struct layout on LP64. Forwards.
    #[no_mangle] pub unsafe extern "C" fn stat64(path: *const u8, buf: *mut stat) -> i32 { unsafe { stat(path, buf) } }
    // # C: int lstat64(const char *, struct stat64 *)
    // SAFETY: LFS alias of lstat; identical struct layout on LP64. Forwards.
    #[no_mangle] pub unsafe extern "C" fn lstat64(path: *const u8, buf: *mut stat) -> i32 { unsafe { lstat(path, buf) } }
    // # C: int fstat64(int, struct stat64 *)
    // SAFETY: LFS alias of fstat; identical struct layout on LP64. Forwards.
    #[no_mangle] pub unsafe extern "C" fn fstat64(fd: i32, buf: *mut stat) -> i32 { unsafe { fstat(fd, buf) } }
    // # C: int fstatat64(int, const char *, struct stat64 *, int)
    // SAFETY: LFS alias of fstatat; identical struct layout on LP64. Forwards.
    #[no_mangle] pub unsafe extern "C" fn fstatat64(d: i32, p: *const u8, buf: *mut stat, f: i32) -> i32 { unsafe { fstatat(d, p, buf, f) } }
    // # C: int __xstat(int ver, const char *, struct stat *) — old glibc inline-stat ABI
    // SAFETY: versioned-stat ABI alias; ver ignored, struct is our single stat. Forwards.
    #[no_mangle] pub unsafe extern "C" fn __xstat(_ver: i32, path: *const u8, buf: *mut stat) -> i32 { unsafe { stat(path, buf) } }
    // # C: int __lxstat(int ver, const char *, struct stat *)
    // SAFETY: versioned-lstat ABI alias; ver ignored. Forwards to lstat.
    #[no_mangle] pub unsafe extern "C" fn __lxstat(_ver: i32, path: *const u8, buf: *mut stat) -> i32 { unsafe { lstat(path, buf) } }
    // # C: int __fxstat(int ver, int fd, struct stat *)
    // SAFETY: versioned-fstat ABI alias; ver ignored. Forwards to fstat.
    #[no_mangle] pub unsafe extern "C" fn __fxstat(_ver: i32, fd: i32, buf: *mut stat) -> i32 { unsafe { fstat(fd, buf) } }
    // # C: int __xstat64(int ver, const char *, struct stat64 *)
    // SAFETY: versioned-stat64 ABI alias; ver ignored, LP64 struct. Forwards to stat.
    #[no_mangle] pub unsafe extern "C" fn __xstat64(_ver: i32, path: *const u8, buf: *mut stat) -> i32 { unsafe { stat(path, buf) } }
    // # C: int __lxstat64(int ver, const char *, struct stat64 *)
    // SAFETY: versioned-lstat64 ABI alias; ver ignored, LP64 struct. Forwards to lstat.
    #[no_mangle] pub unsafe extern "C" fn __lxstat64(_ver: i32, path: *const u8, buf: *mut stat) -> i32 { unsafe { lstat(path, buf) } }
    // # C: int __fxstat64(int ver, int fd, struct stat64 *)
    // SAFETY: versioned-fstat64 ABI alias; ver ignored, LP64 struct. Forwards to fstat.
    #[no_mangle] pub unsafe extern "C" fn __fxstat64(_ver: i32, fd: i32, buf: *mut stat) -> i32 { unsafe { fstat(fd, buf) } }
}

#[cfg(test)]
mod tests {
    use super::stat;
    #[test]
    fn stat_abi_matches_host() {
        // differential vs the host libc::stat (x86_64 test host).
        assert_eq!(core::mem::size_of::<stat>(), core::mem::size_of::<libc::stat>());
        assert_eq!(core::mem::offset_of!(stat, st_size), core::mem::offset_of!(libc::stat, st_size));
        assert_eq!(core::mem::offset_of!(stat, st_mode), core::mem::offset_of!(libc::stat, st_mode));
        assert_eq!(core::mem::offset_of!(stat, st_ino), core::mem::offset_of!(libc::stat, st_ino));
    }
}
