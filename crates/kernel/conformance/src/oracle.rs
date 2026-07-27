//! Host oracle — every function here runs the REAL syscall on THIS machine's
//! real Linux kernel via raw `libc` (never hand-recalled expected values,
//! `F721` requirement). Callers compare the returned [`crate::outcome::Outcome`]
//! against the equivalent oxide work-fn call.
//!
//! Every `unsafe` block here is the same shape: a plain libc FFI call with
//! arguments this function itself just built and owns for the call's
//! duration (a `CString`/local buffer/valid fd) — each is annotated at its
//! own site rather than repeating that sentence per call.

use std::ffi::CString;
use std::path::Path;

use crate::outcome::Outcome;

fn cpath(p: &Path) -> CString { CString::new(p.to_str().expect("utf8 test path")).expect("no NUL in test path") }

/// A fresh, auto-cleaned host directory for one case's fixtures. Every
/// family builds both its host tree and its oxide synthetic tree from the
/// same relative layout under here / under the oxide fixture root.
pub struct TempDir(std::path::PathBuf);
impl TempDir {
    pub fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("oxide-conformance-{tag}-{pid}-{n}"));
        std::fs::create_dir_all(&p).expect("create host fixture tempdir");
        TempDir(p)
    }
    pub fn path(&self) -> &Path { &self.0 }
    pub fn join(&self, name: &str) -> std::path::PathBuf { self.0.join(name) }
}
static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
impl Drop for TempDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

/// Close a host fd, ignoring the result — fixture teardown only.
pub fn close_raw(fd: i32) {
    // SAFETY: fd is a live fd this module opened; close(2) is safe on any int.
    unsafe { libc::close(fd); }
}

/// `open(2)` / `openat(AT_FDCWD, ...)`. Closes the fd on success (`ret` still
/// reports the success class; callers that need the fd for further host-side
/// probing should call [`open_keep`] instead).
pub fn open(p: &Path, flags: i32, mode: u32) -> Outcome {
    let c = cpath(p);
    // SAFETY: c is a NUL-terminated CString kept alive for this call.
    let rv = unsafe { libc::open(c.as_ptr(), flags, mode as libc::mode_t) };
    if rv >= 0 { close_raw(rv); }
    Outcome::from_host(rv as i64)
}

/// Like [`open`] but keeps and returns the live fd (panics on failure) — for
/// cases that need to probe further host-side operations (`fcntl`, `read`,
/// `ftruncate`, …) against the SAME open file description. Caller closes it
/// with [`close_raw`].
pub fn open_keep(p: &Path, flags: i32, mode: u32) -> i32 {
    let c = cpath(p);
    // SAFETY: c is a NUL-terminated CString kept alive for this call.
    let rv = unsafe { libc::open(c.as_ptr(), flags, mode as libc::mode_t) };
    assert!(rv >= 0, "host fixture open({p:?}) failed: {}", std::io::Error::last_os_error());
    rv
}

/// `pipe(2)` — both ends kept open (unlike [`pipe2`]), for cases that need
/// live host fds (`dup`/`dup2`/`dup3`/`lseek`/`fcntl` targets).
pub fn pipe_keep() -> (i32, i32) {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a 2-element stack array, exactly what pipe(2) writes.
    let rv = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rv, 0, "host fixture pipe() failed: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

pub fn mkdir(p: &Path, mode: u32) -> Outcome {
    let c = cpath(p);
    // SAFETY: c is a NUL-terminated CString kept alive for this call.
    Outcome::from_host(unsafe { libc::mkdir(c.as_ptr(), mode as libc::mode_t) } as i64)
}

pub fn rmdir(p: &Path) -> Outcome {
    let c = cpath(p);
    // SAFETY: c is a NUL-terminated CString kept alive for this call.
    Outcome::from_host(unsafe { libc::rmdir(c.as_ptr()) } as i64)
}

pub fn unlink(p: &Path) -> Outcome {
    let c = cpath(p);
    // SAFETY: c is a NUL-terminated CString kept alive for this call.
    Outcome::from_host(unsafe { libc::unlink(c.as_ptr()) } as i64)
}

pub fn rename(from: &Path, to: &Path) -> Outcome {
    let a = cpath(from); let b = cpath(to);
    // SAFETY: a and b are NUL-terminated CStrings kept alive for this call.
    Outcome::from_host(unsafe { libc::rename(a.as_ptr(), b.as_ptr()) } as i64)
}

pub fn symlink(target: &str, linkpath: &Path) -> Outcome {
    let t = CString::new(target).unwrap(); let l = cpath(linkpath);
    // SAFETY: t and l are NUL-terminated CStrings kept alive for this call.
    Outcome::from_host(unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) } as i64)
}

pub fn link(src: &Path, dst: &Path) -> Outcome {
    let a = cpath(src); let b = cpath(dst);
    // SAFETY: a and b are NUL-terminated CStrings kept alive for this call.
    Outcome::from_host(unsafe { libc::link(a.as_ptr(), b.as_ptr()) } as i64)
}

/// Returns `(Outcome, Some(target))` on success. `Outcome.ret` on success
/// carries the target byte length (matches `readlink(2)`'s own contract), so
/// generic ret-comparison is meaningful when both sides succeed.
pub fn readlink(p: &Path) -> (Outcome, Option<String>) {
    let c = cpath(p);
    let mut buf = vec![0u8; 4096];
    // SAFETY: buf is a Vec of the given length; c is a live CString.
    let rv = unsafe { libc::readlink(c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rv < 0 { return (Outcome::from_host(rv as i64), None); }
    buf.truncate(rv as usize);
    (Outcome::ok(rv as i64), Some(String::from_utf8_lossy(&buf).into_owned()))
}

/// `mode_t` bits actually relevant here; `st_mode & S_IFMT` for a directory
/// check, `errno` on failure. Kept minimal — full stat-struct differential
/// is out of this lane's scope (see README "not covered").
pub fn is_dir(p: &Path) -> bool { p.is_dir() }
pub fn exists(p: &Path) -> bool { p.exists() }

/// # Safety-comment note
/// The `dup*`/fd-numeric family below takes only plain integers (no raw
/// pointers, no buffers) — each one-line `unsafe` wraps a libc call whose
/// only precondition is "fd is an int", which is always true.
pub fn dup(fd: i32) -> Outcome {
    // SAFETY: dup(2) accepts any int fd and errors cleanly on an invalid one.
    Outcome::from_host(unsafe { libc::dup(fd) } as i64)
}
pub fn dup2(oldfd: i32, newfd: i32) -> Outcome {
    // SAFETY: dup2(2) accepts any int fds and errors cleanly on invalid ones.
    Outcome::from_host(unsafe { libc::dup2(oldfd, newfd) } as i64)
}
pub fn dup3(oldfd: i32, newfd: i32, flags: i32) -> Outcome {
    // SAFETY: dup3(2) accepts any int fds and errors cleanly on invalid ones.
    Outcome::from_host(unsafe { libc::dup3(oldfd, newfd, flags) } as i64)
}
pub fn close(fd: i32) -> Outcome {
    // SAFETY: close(2) accepts any int fd and errors cleanly on an invalid one.
    Outcome::from_host(unsafe { libc::close(fd) } as i64)
}

pub fn fcntl_dupfd_cloexec(fd: i32, min: i32) -> Outcome {
    // SAFETY: fcntl(2) F_DUPFD_CLOEXEC takes only int args, errors cleanly.
    Outcome::from_host(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) } as i64)
}
pub fn fcntl_getfl(fd: i32) -> Outcome {
    // SAFETY: fcntl(2) F_GETFL takes only an int fd, errors cleanly.
    Outcome::from_host(unsafe { libc::fcntl(fd, libc::F_GETFL) } as i64)
}

/// `ret` on success carries the new offset (`lseek(2)` contract) — directly
/// ret-comparable across host/oxide.
pub fn lseek(fd: i32, off: i64, whence: i32) -> Outcome {
    // SAFETY: lseek(2) takes only int/offset args, errors cleanly.
    Outcome::from_host(unsafe { libc::lseek(fd, off, whence) })
}

pub fn ftruncate(fd: i32, len: i64) -> Outcome {
    // SAFETY: ftruncate(2) takes only an int fd + offset, errors cleanly.
    Outcome::from_host(unsafe { libc::ftruncate(fd, len) } as i64)
}

pub fn read(fd: i32, buf: &mut [u8]) -> Outcome {
    // SAFETY: buf is a live Rust slice of exactly buf.len() writable bytes.
    Outcome::from_host(unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } as i64)
}
pub fn write(fd: i32, buf: &[u8]) -> Outcome {
    // SAFETY: buf is a live Rust slice of exactly buf.len() readable bytes.
    Outcome::from_host(unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) } as i64)
}

/// `pipe2(2)`. Closes both ends on success — callers only need the errno
/// class + flag-validation ordering, not live host fds.
pub fn pipe2(flags: i32) -> Outcome {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a 2-element stack array, exactly what pipe2(2) writes.
    let rv = unsafe { libc::pipe2(fds.as_mut_ptr(), flags) };
    if rv == 0 { close_raw(fds[0]); close_raw(fds[1]); }
    Outcome::from_host(rv as i64)
}

/// Raw `SYS_getrandom` syscall — NOT `libc::getrandom()`. Modern glibc
/// (2.36+) serves `getrandom()` from a per-thread vDSO fast path
/// (`vgetrandom`) that does NOT reproduce the kernel's flag validation
/// (observed: glibc's wrapper returned success for the invalid
/// `GRND_RANDOM|GRND_INSECURE` combo while the real syscall returns
/// `EINVAL`), which would make the oracle lie about kernel truth. Going
/// through `libc::syscall` forces the actual syscall path every time.
pub fn getrandom(buf: &mut [u8], flags: u32) -> Outcome {
    // SAFETY: buf is a live Rust slice of exactly buf.len() writable bytes.
    Outcome::from_host(unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), flags) } as i64)
}

/// `clock_gettime(2)` — `ret` is 0 on success (Linux contract); the only
/// interesting signal for the cases in this lane is the errno on an invalid
/// clockid, so the filled `timespec` is discarded.
pub fn clock_gettime(clockid: libc::clockid_t) -> Outcome {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: ts is a live, stack-owned timespec the call writes into.
    Outcome::from_host(unsafe { libc::clock_gettime(clockid, &mut ts) } as i64)
}

/// `fstatat(AT_FDCWD, path, &buf, flags)`. Only the errno class matters for
/// the cases in this lane (AT_EMPTY_PATH / AT_SYMLINK_NOFOLLOW ordering),
/// so the filled `stat` is discarded.
pub fn fstatat(p: &Path, flags: i32) -> Outcome {
    let c = cpath(p);
    // SAFETY: a zeroed stat is a valid initial value; fstatat overwrites it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: c is a live CString; st is a stack-owned buffer the call fills.
    Outcome::from_host(unsafe { libc::fstatat(libc::AT_FDCWD, c.as_ptr(), &mut st, flags) } as i64)
}

/// `fstatat(fd, "", &buf, AT_EMPTY_PATH | extra)` — the empty-relative-path
/// form `fstat(fd)` desugars to.
pub fn fstatat_empty(fd: i32, extra: i32) -> Outcome {
    let empty = CString::new("").unwrap();
    // SAFETY: a zeroed stat is a valid initial value; fstatat overwrites it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: empty is a live CString; st is a stack-owned buffer the call fills.
    Outcome::from_host(unsafe { libc::fstatat(fd, empty.as_ptr(), &mut st, libc::AT_EMPTY_PATH | extra) } as i64)
}

/// `ret` on success is `1` for `S_ISLNK` else `2` — directly ret-comparable
/// against the oxide side's own symlink-vs-target classification.
pub fn stat_or_lstat_type_tag(p: &Path, follow: bool) -> Outcome {
    let c = cpath(p);
    // SAFETY: a zeroed stat is a valid initial value; stat/lstat overwrites it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rv = if follow {
        // SAFETY: c is a live CString; st is a stack-owned buffer the call fills.
        unsafe { libc::stat(c.as_ptr(), &mut st) }
    } else {
        // SAFETY: c is a live CString; st is a stack-owned buffer the call fills.
        unsafe { libc::lstat(c.as_ptr(), &mut st) }
    };
    if rv != 0 { return Outcome::from_host(rv as i64); }
    let tag = if (st.st_mode & libc::S_IFMT) == libc::S_IFLNK { 1 } else { 2 };
    Outcome::ok(tag)
}

pub fn nanosleep_zero() -> Outcome {
    let req = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: req is a live, stack-owned timespec; rem ptr is null (not read back).
    Outcome::from_host(unsafe { libc::nanosleep(&req, std::ptr::null_mut()) } as i64)
}
