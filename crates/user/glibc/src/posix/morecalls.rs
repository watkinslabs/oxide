// Misc file/process syscall wrappers needed by real userspace (docs/59§6 —
// G19): statfs/fstatfs (df), flock, sendfile/splice/copy_file_range (cp),
// posix_fadvise, memfd_create, mincore, prctl/setns/unshare (systemd ns),
// getresuid/getresgid (id), vhangup, preadv2/pwritev2, usleep. Thin wrappers;
// kernel structs (statfs, iovec) pass through as pointers. From the systematic
// export-vs-vendor symbol audit.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys1, sys2, sys3, sys4, sys5, sys6};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// statfs/fstatfs + statvfs/fstatvfs now live in posix/statfs.rs.

// # C: int acct(const char *filename) — enable/disable process accounting.
#[no_mangle]
pub unsafe extern "C" fn acct(filename: *const c_char) -> i32 {
    // SAFETY: filename is null (disable) or a NUL-terminated path the kernel reads.
    ret_isize(unsafe { sys1(nr::ACCT, filename as usize) }) as i32
}

// # C: int flock(int fd, int op)
#[no_mangle]
pub unsafe extern "C" fn flock(fd: i32, op: i32) -> i32 {
    // SAFETY: flock(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys2(nr::FLOCK, fd as usize, op as usize) }) as i32
}

// # C: ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
#[no_mangle]
pub unsafe extern "C" fn sendfile(out_fd: i32, in_fd: i32, offset: *mut i64, count: usize) -> isize {
    // SAFETY: offset is null or a writable off_t the kernel reads+updates.
    unsafe { ret_isize(sys4(nr::SENDFILE, out_fd as usize, in_fd as usize, offset as usize, count)) }
}
// SAFETY: LFS alias of sendfile (off64_t == off_t on LP64); same fd+buffer contract.
#[no_mangle] pub unsafe extern "C" fn sendfile64(o: i32, i: i32, off: *mut i64, c: usize) -> isize { unsafe { sendfile(o, i, off, c) } }

// # C: ssize_t splice(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn splice(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> isize {
    // SAFETY: off_in/off_out null or writable off64_t; fds are pipe/file fds.
    unsafe { ret_isize(sys6(nr::SPLICE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize)) }
}

// # C: ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> isize {
    // SAFETY: tee(2) duplicates pipe data between two pipe fds; scalar args.
    unsafe { ret_isize(sys4(nr::TEE, fd_in as usize, fd_out as usize, len, flags as usize)) }
}

// # C: ssize_t vmsplice(int fd, const struct iovec *iov, size_t nr_segs, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn vmsplice(fd: i32, iov: *const c_void, nr_segs: usize, flags: u32) -> isize {
    // SAFETY: iov points at nr_segs struct iovec the kernel reads; fd is a pipe.
    unsafe { ret_isize(sys4(nr::VMSPLICE, fd as usize, iov as usize, nr_segs, flags as usize)) }
}

// # C: int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn sync_file_range(fd: i32, offset: i64, nbytes: i64, flags: u32) -> i32 {
    // SAFETY: sync_file_range(2) — scalar args, no user buffers.
    unsafe { ret_isize(sys4(nr::SYNC_FILE_RANGE, fd as usize, offset as usize, nbytes as usize, flags as usize)) as i32 }
}

// # C: ssize_t copy_file_range(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out, size_t len, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn copy_file_range(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> isize {
    // SAFETY: off_in/off_out null or writable off64_t; fds are file fds.
    unsafe { ret_isize(sys6(nr::COPY_FILE_RANGE, fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize)) }
}

// # C: int posix_fadvise(int fd, off_t offset, off_t len, int advice)
#[no_mangle]
pub unsafe extern "C" fn posix_fadvise(fd: i32, offset: i64, len: i64, advice: i32) -> i32 {
    // SAFETY: fadvise64(2) — scalar args, no user buffers. Returns errno (not -errno).
    let r = unsafe { sys4(nr::FADVISE64, fd as usize, offset as usize, len as usize, advice as usize) };
    if r < 0 { (-r) as i32 } else { 0 }
}
// SAFETY: LFS alias of posix_fadvise; identical scalar args, no user buffers.
#[no_mangle] pub unsafe extern "C" fn posix_fadvise64(fd: i32, o: i64, l: i64, a: i32) -> i32 { unsafe { posix_fadvise(fd, o, l, a) } }

// # C: int memfd_create(const char *name, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn memfd_create(name: *const c_char, flags: u32) -> i32 {
    // SAFETY: name a NUL-terminated user string the kernel reads.
    ret_isize(unsafe { sys2(nr::MEMFD_CREATE, name as usize, flags as usize) }) as i32
}

// # C: int mincore(void *addr, size_t length, unsigned char *vec)
#[no_mangle]
pub unsafe extern "C" fn mincore(addr: *mut c_void, length: usize, vec: *mut u8) -> i32 {
    // SAFETY: vec is a writable byte array of ceil(length/page) bytes.
    ret_isize(unsafe { sys3(nr::MINCORE, addr as usize, length, vec as usize) }) as i32
}

// # C: int prctl(int option, unsigned long a2, a3, a4, a5)
#[no_mangle]
pub unsafe extern "C" fn prctl(option: i32, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    // SAFETY: prctl(2) — args are option-specific scalars/pointers passed through.
    ret_isize(unsafe { sys5(nr::PRCTL, option as usize, a2, a3, a4, a5) }) as i32
}

// # C: int setns(int fd, int nstype)
#[no_mangle]
pub unsafe extern "C" fn setns(fd: i32, nstype: i32) -> i32 {
    // SAFETY: setns(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys2(nr::SETNS, fd as usize, nstype as usize) }) as i32
}

// # C: int unshare(int flags)
#[no_mangle]
pub unsafe extern "C" fn unshare(flags: i32) -> i32 {
    // SAFETY: unshare(2) — scalar arg, no user buffers.
    ret_isize(unsafe { sys1(nr::UNSHARE, flags as usize) }) as i32
}

// # C: int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
#[no_mangle]
pub unsafe extern "C" fn getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> i32 {
    // SAFETY: three writable uid_t the kernel fills.
    ret_isize(unsafe { sys3(nr::GETRESUID, ruid as usize, euid as usize, suid as usize) }) as i32
}
// # C: int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
#[no_mangle]
pub unsafe extern "C" fn getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> i32 {
    // SAFETY: three writable gid_t the kernel fills.
    ret_isize(unsafe { sys3(nr::GETRESGID, rgid as usize, egid as usize, sgid as usize) }) as i32
}

// # C: int vhangup(void)
#[no_mangle]
pub unsafe extern "C" fn vhangup() -> i32 {
    // SAFETY: vhangup(2) takes no args; the extra 0 is ignored by the kernel.
    ret_isize(unsafe { sys1(nr::VHANGUP, 0) }) as i32
}

// # C: ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t off, int flags)
#[no_mangle]
pub unsafe extern "C" fn preadv2(fd: i32, iov: *const c_void, iovcnt: i32, off: i64, flags: i32) -> isize {
    // SAFETY: iov is an array of `iovcnt` iovec the kernel reads; off split lo/hi
    // (hi=0 for the common case); flags is RWF_*.
    unsafe { ret_isize(sys6(nr::PREADV2, fd as usize, iov as usize, iovcnt as usize, off as usize, 0, flags as usize)) }
}
// # C: ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t off, int flags)
#[no_mangle]
pub unsafe extern "C" fn pwritev2(fd: i32, iov: *const c_void, iovcnt: i32, off: i64, flags: i32) -> isize {
    // SAFETY: iov is an array of `iovcnt` iovec the kernel reads.
    unsafe { ret_isize(sys6(nr::PWRITEV2, fd as usize, iov as usize, iovcnt as usize, off as usize, 0, flags as usize)) }
}
// LFS aliases — off64_t == off_t on LP64.
// SAFETY: preadv64v2 == preadv2 on LP64; same fd + iovec + flags contract.
#[no_mangle] pub unsafe extern "C" fn preadv64v2(fd: i32, iov: *const c_void, c: i32, off: i64, fl: i32) -> isize { unsafe { preadv2(fd, iov, c, off, fl) } }
// SAFETY: pwritev64v2 == pwritev2 on LP64; same fd + iovec + flags contract.
#[no_mangle] pub unsafe extern "C" fn pwritev64v2(fd: i32, iov: *const c_void, c: i32, off: i64, fl: i32) -> isize { unsafe { pwritev2(fd, iov, c, off, fl) } }

// # C: int __sched_cpucount(size_t setsize, const cpu_set_t *setp)
// Backs the CPU_COUNT macro: popcount of the first `setsize` bytes of the mask.
#[no_mangle]
pub unsafe extern "C" fn __sched_cpucount(setsize: usize, setp: *const c_void) -> i32 {
    let mut n = 0u32;
    // SAFETY: setp points to at least `setsize` readable bytes (the cpu_set_t).
    unsafe { let p = setp as *const u8; for i in 0..setsize { n += (*p.add(i)).count_ones(); } }
    n as i32
}

// # C: int usleep(useconds_t usec) — composed from nanosleep.
#[no_mangle]
pub unsafe extern "C" fn usleep(usec: u32) -> i32 {
    // SAFETY: ts lives on this frame for the nanosleep(2) call's duration.
    unsafe {
        let ts = crate::time::clock::timespec { tv_sec: (usec / 1_000_000) as i64, tv_nsec: ((usec % 1_000_000) as i64) * 1000 };
        ret_isize(sys2(nr::NANOSLEEP, &ts as *const _ as usize, 0)) as i32
    }
}
