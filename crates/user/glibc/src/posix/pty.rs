// <pty.h> + pseudoterminal helpers from <stdlib.h>/<unistd.h> (docs/59§6).
// getpt/grantpt/unlockpt/ptsname[_r] open /dev/ptmx and drive the
// TIOCGPTN/TIOCSPTLCK ioctls; openpty/forkpty/login_tty compose those
// with fork+setsid+TIOCSCTTY. Raw syscalls for ioctl; the file-level
// helpers reuse our exported open/close/read C wrappers (arch dispatch
// lives there). C ABI only.
#![cfg(feature = "freestanding")]
#![allow(clippy::manual_c_str_literals)]
use crate::arch::syscall::sys3;
use crate::internal::errno::{ret_isize, set};
use crate::internal::nr;

// Terminal ioctl request numbers — arch-independent on Linux (asm-generic,
// shared x86_64/aarch64). Verified against host <asm/ioctls.h>.
const TIOCGPTN: usize = 0x8004_5430; // get pty number (int out)
const TIOCSPTLCK: usize = 0x4004_5431; // lock/unlock pty (int in)
const TIOCSCTTY: usize = 0x0000_540e; // make controlling tty

// errno values used directly (07§5 — typed at the one call site each).
const EINVAL: i32 = 22;
const ERANGE: i32 = 34;

// open flags (octal, arch-independent for these).
const O_RDWR: i32 = 0o2;
const O_NOCTTY: i32 = 0o400;

extern "C" {
    fn open(path: *const u8, flags: i32, mode: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn fork() -> i32;
    fn setsid() -> i32;
    fn strlen(s: *const u8) -> usize;
    fn snprintf(s: *mut u8, n: usize, fmt: *const u8, ...) -> i32;
}

const PTMX: &[u8] = b"/dev/ptmx\0";

// Raw ioctl(fd, req, arg) → libc convention (-1 + errno on error).
fn ioctl(fd: i32, req: usize, arg: usize) -> i32 {
    // SAFETY: pty ioctls take an fd plus a pointer/scalar arg; each call site
    // passes the arg shape (int* for TIOCGPTN/TIOCSPTLCK) the request expects.
    ret_isize(unsafe { sys3(nr::IOCTL, fd as usize, req, arg) }) as i32
}

// # C: int getpt(void)
#[no_mangle]
pub extern "C" fn getpt() -> i32 {
    // SAFETY: PTMX is a 'static NUL-terminated path; open takes no caller buf.
    unsafe { open(PTMX.as_ptr(), O_RDWR | O_NOCTTY, 0) }
}

// # C: int posix_openpt(int flags)
#[no_mangle]
pub extern "C" fn posix_openpt(flags: i32) -> i32 {
    // SAFETY: PTMX is a 'static NUL-terminated path; flags is a scalar arg.
    unsafe { open(PTMX.as_ptr(), flags, 0) }
}

// # C: int grantpt(int fd)
#[no_mangle]
pub extern "C" fn grantpt(_fd: i32) -> i32 {
    // devpts mounted with the modern ptmxmode/gid handling grants slave perms
    // at open(); glibc's grantpt is a no-op success on such systems. Match that.
    0
}

// # C: int unlockpt(int fd)
#[no_mangle]
pub extern "C" fn unlockpt(fd: i32) -> i32 {
    let unlock: i32 = 0;
    // SAFETY: TIOCSPTLCK reads one int through the pointer; &unlock is a live
    // local int valid for the duration of this ioctl call.
    ioctl(fd, TIOCSPTLCK, &unlock as *const i32 as usize)
}

// Fetch the pty number for master `fd`; returns Ok(n) or Err(()) (errno set).
fn ptyno(fd: i32) -> Result<i32, ()> {
    let mut n: i32 = 0;
    // SAFETY: TIOCGPTN writes one int through the pointer; &mut n is a live
    // local int valid for the duration of this ioctl call.
    if ioctl(fd, TIOCGPTN, &mut n as *mut i32 as usize) < 0 { return Err(()); }
    Ok(n)
}

// Process-global ptsname() buffer (glibc's is also static/non-reentrant).
const PTS_BUF: usize = 32;
struct PtsCell(core::cell::UnsafeCell<[u8; PTS_BUF]>);
// SAFETY: ptsname's return buffer mirrors glibc's single static buffer; the
// non-reentrancy contract is identical, so no cross-thread aliasing guarantee.
unsafe impl Sync for PtsCell {}
static PTS: PtsCell = PtsCell(core::cell::UnsafeCell::new([0u8; PTS_BUF]));

// # C: char *ptsname(int fd)
#[no_mangle]
pub extern "C" fn ptsname(fd: i32) -> *mut u8 {
    let buf = PTS.0.get();
    // SAFETY: buf is the 'static process-global PTS buffer (PTS_BUF bytes);
    // ptsname_r writes a NUL-terminated "/dev/pts/N" no longer than PTS_BUF.
    if unsafe { ptsname_r(fd, buf as *mut u8, PTS_BUF) } != 0 { return core::ptr::null_mut(); }
    buf as *mut u8
}

// # C: int ptsname_r(int fd, char *buf, size_t buflen)
#[no_mangle]
pub unsafe extern "C" fn ptsname_r(fd: i32, buf: *mut u8, buflen: usize) -> i32 {
    if buf.is_null() { set(EINVAL); return EINVAL; }
    let n = match ptyno(fd) { Ok(n) => n, Err(()) => return EINVAL };
    // Format "/dev/pts/<n>" into the caller buffer; snprintf NUL-terminates and
    // returns the would-be length, so a too-small buffer maps to ERANGE.
    // SAFETY: buf is caller storage of `buflen` bytes; snprintf bounds its write
    // to buflen and the "%d" fmt + n match the C varargs ABI here.
    let want = unsafe { snprintf(buf, buflen, b"/dev/pts/%d\0".as_ptr(), n) };
    if want < 0 || want as usize >= buflen { set(ERANGE); return ERANGE; }
    0
}

// Open the slave for a freshly-unlocked master `mfd`; returns slave fd or -1.
fn open_slave(mfd: i32) -> i32 {
    let mut name = [0u8; PTS_BUF];
    // SAFETY: name is a 32-byte local; ptsname_r writes a NUL-terminated path
    // bounded by PTS_BUF, leaving a valid C string for open below.
    if unsafe { ptsname_r(mfd, name.as_mut_ptr(), PTS_BUF) } != 0 { return -1; }
    // SAFETY: name now holds a NUL-terminated "/dev/pts/N" path; open reads it.
    unsafe { open(name.as_ptr(), O_RDWR | O_NOCTTY, 0) }
}

#[inline]
fn close_fd(fd: i32) {
    // SAFETY: fd is a libc fd owned by this module on an error/cleanup path;
    // closing it once is sound and matches the open() that produced it.
    unsafe { close(fd); }
}

// # C: int openpty(int *amaster, int *aslave, char *name, const struct termios *termp, const struct winsize *winp)
#[no_mangle]
pub unsafe extern "C" fn openpty(amaster: *mut i32, aslave: *mut i32, name: *mut u8,
                                 _termp: *const u8, _winp: *const u8) -> i32 {
    if amaster.is_null() || aslave.is_null() { set(EINVAL); return -1; }
    let m = getpt();
    if m < 0 { return -1; }
    if unlockpt(m) < 0 { close_fd(m); return -1; }
    let s = open_slave(m);
    if s < 0 { close_fd(m); return -1; }
    // SAFETY: amaster/aslave are the caller-checked non-null int* out params.
    unsafe { *amaster = m; *aslave = s; }
    if !name.is_null() {
        let mut tmp = [0u8; PTS_BUF];
        // SAFETY: tmp is a 32-byte local; ptsname_r NUL-terminates within it.
        if unsafe { ptsname_r(m, tmp.as_mut_ptr(), PTS_BUF) } == 0 {
            // SAFETY: copy the NUL-terminated path (incl. terminator) into the
            // caller's `name` buffer, which glibc requires hold the path length.
            unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), name, strlen(tmp.as_ptr()) + 1); }
        }
    }
    0
}

// # C: int login_tty(int fd)
#[no_mangle]
pub unsafe extern "C" fn login_tty(fd: i32) -> i32 {
    // SAFETY: new session, then make `fd` the controlling tty and dup it onto
    // stdin/out/err; fd is a caller-owned slave-tty fd. setsid detaches first.
    unsafe {
        setsid();
        if ioctl(fd, TIOCSCTTY, 0) < 0 { return -1; }
        dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
        if fd > 2 { close(fd); }
    }
    0
}

// # C: pid_t forkpty(int *amaster, char *name, const struct termios *termp, const struct winsize *winp)
#[no_mangle]
pub unsafe extern "C" fn forkpty(amaster: *mut i32, name: *mut u8,
                                 termp: *const u8, winp: *const u8) -> i32 {
    let mut s: i32 = -1;
    // SAFETY: openpty fills `amaster` (caller out) and our local slave fd `s`.
    if unsafe { openpty(amaster, &mut s as *mut i32, name, termp, winp) } < 0 { return -1; }
    // SAFETY: fork(2) returns 0 in the child, pid in the parent, -1 on error.
    let pid = unsafe { fork() };
    if pid < 0 {
        // SAFETY: amaster, if non-null, holds the master fd to close on failure.
        if !amaster.is_null() { close_fd(unsafe { *amaster }); }
        close_fd(s);
        return -1;
    }
    if pid == 0 {
        // child: drop the master, attach the slave as controlling tty.
        // SAFETY: amaster (if non-null) holds the master fd, unused by the child.
        if !amaster.is_null() { close_fd(unsafe { *amaster }); }
        // SAFETY: s is the child's slave fd; login_tty consumes it as stdio.
        unsafe { login_tty(s); }
        return 0;
    }
    // parent: slave fd belongs to the child.
    close_fd(s);
    pid
}
