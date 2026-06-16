// lockf(3) (docs/59§6) — POSIX advisory record locking over fcntl. The region
// is [current offset, +len) (negative len locks the bytes before the offset),
// expressed as a struct flock with l_whence=SEEK_CUR. F_LOCK→F_SETLKW/F_WRLCK,
// F_TLOCK→F_SETLK/F_WRLCK, F_ULOCK→F_SETLK/F_UNLCK, F_TEST→F_GETLK probe. C ABI.
#![cfg(feature = "freestanding")]
use crate::internal::errno::set as set_errno;

// 64-bit Linux struct flock (identical on x86_64 + aarch64): 32 bytes.
#[repr(C)]
struct Flock { l_type: i16, l_whence: i16, l_start: i64, l_len: i64, l_pid: i32 }
const _: () = assert!(core::mem::size_of::<Flock>() == 32);

const F_GETLK: i32 = 5;
const F_SETLK: i32 = 6;
const F_SETLKW: i32 = 7;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const SEEK_CUR: i16 = 1;

const F_ULOCK: i32 = 0;
const F_LOCK: i32 = 1;
const F_TLOCK: i32 = 2;
const F_TEST: i32 = 3;
const EINVAL: i32 = 22;
const EACCES: i32 = 13;

extern "C" {
    fn fcntl(fd: i32, cmd: i32, arg: usize) -> i32;
    fn getpid() -> i32;
}

// # C: int lockf(int fd, int cmd, off_t len)
#[no_mangle]
pub unsafe extern "C" fn lockf(fd: i32, cmd: i32, len: i64) -> i32 {
    // SAFETY: fd is an open file; builds a stack flock for the [offset,+len)
    // region and forwards to fcntl. F_TEST probes via F_GETLK.
    unsafe {
        let mut fl = Flock { l_type: F_RDLCK, l_whence: SEEK_CUR, l_start: 0, l_len: 0, l_pid: 0 };
        if len > 0 { fl.l_start = 0; fl.l_len = len; }
        else if len < 0 { fl.l_start = len; fl.l_len = -len; }
        let p = &mut fl as *mut Flock as usize;
        match cmd {
            F_TEST => {
                fl.l_type = F_RDLCK;
                if fcntl(fd, F_GETLK, p) < 0 { return -1; }
                if fl.l_type == F_UNLCK || fl.l_pid == getpid() { 0 } else { set_errno(EACCES); -1 }
            }
            F_ULOCK => { fl.l_type = F_UNLCK; fcntl(fd, F_SETLK, p) }
            F_LOCK => { fl.l_type = F_WRLCK; fcntl(fd, F_SETLKW, p) }
            F_TLOCK => { fl.l_type = F_WRLCK; fcntl(fd, F_SETLK, p) }
            _ => { set_errno(EINVAL); -1 }
        }
    }
}

// # C: int lockf64(int fd, int cmd, off64_t len) — off_t == off64_t on LP64
#[no_mangle]
pub unsafe extern "C" fn lockf64(fd: i32, cmd: i32, len: i64) -> i32 {
    // SAFETY: off64_t == off_t on LP64; forwards to lockf.
    unsafe { lockf(fd, cmd, len) }
}
