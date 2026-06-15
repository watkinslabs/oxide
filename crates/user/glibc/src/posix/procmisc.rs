// Miscellaneous process/identity/dir/temp + legacy syscalls (docs/59§6).
//   identity:  getlogin, getlogin_r
//   cwd:       getwd, get_current_dir_name, canonicalize_file_name
//   temp:      tmpnam, tmpnam_r, tempnam, remove
//   legacy:    syscall (generic indirect), sysctl/_sysctl, vlimit, vtimes,
//              gtty, stty (obsolete — ENOSYS, matching modern glibc).
// C ABI only — freestanding. getdomainname lives in net/netdb_host.rs;
// setgroups in posix/ids.rs; on_exit/wait3 in stdlib/exit.rs/posix/process.rs.
#![cfg(feature = "freestanding")]
// b"..\0" literals are already *const u8 (no arch-varying c_char cast), matching
// the rest of posix/.
#![allow(clippy::manual_c_str_literals)]
extern crate alloc;
use crate::arch::syscall::syscall6;
use crate::internal::errno;
use crate::string::len::strlen_impl;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

const PATH_MAX: usize = 4096;
const ENOSYS: i32 = 38;
const ERANGE: i32 = 34;
const ENAMETOOLONG: i32 = 36;

extern "C" {
    fn getcwd(buf: *mut u8, size: usize) -> *mut u8;
    fn getenv(name: *const u8) -> *mut u8;
    fn getuid() -> u32;
    fn getpid() -> i32;
    fn malloc(n: usize) -> *mut c_void;
    fn realpath(path: *const u8, resolved: *mut u8) -> *mut u8;
    fn unlink(path: *const u8) -> i32;
    fn rmdir(path: *const u8) -> i32;
    fn getpwuid(uid: u32) -> *mut crate::nss::passwd;
}

// ---- identity ----

// # C: char *getlogin(void)
#[no_mangle]
pub unsafe extern "C" fn getlogin() -> *mut u8 {
    // SAFETY: prefer $LOGNAME, else the passwd name for getuid(); returns a
    // pointer into a process-global buffer (glibc getlogin is not thread-safe).
    unsafe {
        static BUF: LoginBuf = LoginBuf(core::cell::UnsafeCell::new([0u8; 256]));
        let dst = BUF.0.get() as *mut u8;
        let env = getenv(b"LOGNAME\0".as_ptr());
        let src = if !env.is_null() && *env != 0 { env } else {
            let pw = getpwuid(getuid());
            if pw.is_null() || (*pw).pw_name.is_null() { return core::ptr::null_mut(); }
            (*pw).pw_name
        };
        let n = strlen_impl(src).min(255);
        core::ptr::copy_nonoverlapping(src, dst, n);
        *dst.add(n) = 0;
        dst
    }
}
struct LoginBuf(core::cell::UnsafeCell<[u8; 256]>);
// SAFETY: process-global getlogin scratch; single-threaded libc contract like
// glibc's non-reentrant getlogin (threads use getlogin_r).
unsafe impl Sync for LoginBuf {}

// # C: int getlogin_r(char *name, size_t len)
#[no_mangle]
pub unsafe extern "C" fn getlogin_r(name: *mut u8, len: usize) -> i32 {
    // SAFETY: name writable for `len`; copy the login name (LOGNAME or passwd)
    // into it, ERANGE if too small, ENOENT (2) if no login is known.
    unsafe {
        if name.is_null() || len == 0 { return ERANGE; }
        let l = getlogin();
        if l.is_null() { return 2; }
        let n = strlen_impl(l);
        if n + 1 > len { return ERANGE; }
        core::ptr::copy_nonoverlapping(l, name, n);
        *name.add(n) = 0;
        0
    }
}

// ---- cwd ----

// # C: char *getwd(char *buf) — legacy getcwd into a PATH_MAX caller buffer.
#[no_mangle]
pub unsafe extern "C" fn getwd(buf: *mut u8) -> *mut u8 {
    // SAFETY: buf is a caller PATH_MAX buffer per the (obsolete) getwd contract;
    // getcwd fills it. Returns buf on success, null on error (errno set).
    unsafe { if buf.is_null() { errno::set(22); return core::ptr::null_mut(); } getcwd(buf, PATH_MAX) }
}

// # C: char *get_current_dir_name(void)
#[no_mangle]
pub unsafe extern "C" fn get_current_dir_name() -> *mut u8 {
    // SAFETY: honours $PWD when it names the current directory (glibc), else
    // getcwd into a freshly malloc'd buffer the caller frees.
    unsafe {
        let pwd = getenv(b"PWD\0".as_ptr());
        if !pwd.is_null() && *pwd == b'/' {
            // trust $PWD only when it matches the actual cwd lexically; verify by
            // getcwd compare (cheap, avoids a stat dance).
            let mut cur = [0u8; PATH_MAX];
            if !getcwd(cur.as_mut_ptr(), PATH_MAX).is_null() {
                let pn = strlen_impl(pwd);
                if pn == strlen_impl(cur.as_ptr())
                    && core::slice::from_raw_parts(pwd, pn) == &cur[..pn] {
                    let d = malloc(pn + 1) as *mut u8;
                    if d.is_null() { return core::ptr::null_mut(); }
                    core::ptr::copy_nonoverlapping(pwd, d, pn); *d.add(pn) = 0;
                    return d;
                }
            }
        }
        let mut cur = [0u8; PATH_MAX];
        if getcwd(cur.as_mut_ptr(), PATH_MAX).is_null() { return core::ptr::null_mut(); }
        let n = strlen_impl(cur.as_ptr());
        let d = malloc(n + 1) as *mut u8;
        if d.is_null() { return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(cur.as_ptr(), d, n); *d.add(n) = 0;
        d
    }
}

// # C: char *canonicalize_file_name(const char *path)
#[no_mangle]
pub unsafe extern "C" fn canonicalize_file_name(path: *const u8) -> *mut u8 {
    // SAFETY: path is NUL-terminated. realpath gives the lexical+existence
    // canonical form; we then iteratively resolve a terminal symlink via
    // readlink (the lexical realpath does not follow links) so the result
    // matches glibc for symlinked paths. Up to 40 hops (ELOOP guard).
    unsafe {
        let mut cur = [0u8; PATH_MAX];
        let r = realpath(path, cur.as_mut_ptr());
        if r.is_null() { return core::ptr::null_mut(); }
        let mut hops = 0;
        loop {
            // readlink the current absolute path; ok→it's a symlink to follow.
            let mut tgt = [0u8; PATH_MAX];
            let n = readlink_abs(cur.as_ptr(), tgt.as_mut_ptr(), PATH_MAX - 1);
            if n <= 0 || hops >= 40 { break; }
            tgt[n as usize] = 0;
            // Build the next path: absolute target as-is, else joined to cur's dir.
            let mut next = [0u8; PATH_MAX];
            let mut w = 0usize;
            if tgt[0] == b'/' {
                while w < n as usize { next[w] = tgt[w]; w += 1; }
            } else {
                // dirname(cur) + '/' + tgt
                let clen = strlen_impl(cur.as_ptr());
                let mut d = clen;
                while d > 1 && cur[d - 1] != b'/' { d -= 1; }
                if d > 1 { d -= 1; } // drop trailing '/'
                while w < d { next[w] = cur[w]; w += 1; }
                next[w] = b'/'; w += 1;
                let mut i = 0; while i < n as usize && w < PATH_MAX - 1 { next[w] = tgt[i]; w += 1; i += 1; }
            }
            next[w] = 0;
            let r2 = realpath(next.as_ptr(), cur.as_mut_ptr());
            if r2.is_null() { return core::ptr::null_mut(); }
            hops += 1;
        }
        let clen = strlen_impl(cur.as_ptr());
        let out = malloc(clen + 1) as *mut u8;
        if out.is_null() { return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(cur.as_ptr(), out, clen);
        *out.add(clen) = 0;
        out
    }
}

// readlinkat(AT_FDCWD, path, buf, n) → byte count, or -1 if not a symlink.
unsafe fn readlink_abs(path: *const u8, buf: *mut u8, n: usize) -> isize {
    // SAFETY: path NUL-terminated; buf writable for n bytes. Raw readlinkat over
    // AT_FDCWD; a negative kernel return (EINVAL when not a link) yields -1.
    unsafe {
        const AT_FDCWD: usize = (-100i64) as usize;
        let r = syscall6(crate::internal::nr::READLINKAT, AT_FDCWD, path as usize, buf as usize, n, 0, 0);
        if r < 0 { -1 } else { r }
    }
}

// ---- temp names ----

const P_TMPDIR: &[u8] = b"/tmp\0"; // NUL-terminated so strlen_impl is safe
static TMP_SEQ: AtomicU32 = AtomicU32::new(0);

// Choose the temp directory. tmpnam ignores $TMPDIR (always P_tmpdir, glibc);
// tempnam honours `dir` then $TMPDIR then P_tmpdir. `honor_env` selects which.
// Writes a NUL-terminated prefix (no trailing slash) into `out`, returns len.
unsafe fn tmp_dir(out: &mut [u8], dir: *const u8, honor_env: bool) -> usize {
    // SAFETY: out is writable; dir/the env value are null or NUL-terminated.
    // Pick the dir per precedence and copy it (bounded by out.len()-1).
    unsafe {
        let pick: *const u8 = if !dir.is_null() && *dir != 0 { dir } else if honor_env {
            let e = getenv(b"TMPDIR\0".as_ptr());
            if !e.is_null() && *e == b'/' { e } else { P_TMPDIR.as_ptr() }
        } else { P_TMPDIR.as_ptr() };
        let mut n = strlen_impl(pick);
        if n > out.len() - 1 { n = out.len() - 1; }
        core::ptr::copy_nonoverlapping(pick, out.as_mut_ptr(), n);
        // strip a trailing slash so the join is uniform
        if n > 1 && out[n - 1] == b'/' { n -= 1; }
        out[n] = 0;
        n
    }
}

// Build "<dir>/<prefix>NNNNNN" into `out`; returns total length (no NUL count).
unsafe fn build_name(out: &mut [u8], dir: &[u8], prefix: &[u8]) -> usize {
    // SAFETY: out is large enough for dir + '/' + prefix + a 12-digit suffix +
    // NUL; we bound every copy. The suffix mixes pid + a process-local counter.
    unsafe {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let mix = (getpid() as u32).wrapping_mul(0x9E3779B1).wrapping_add(seq);
        let mut w = 0usize;
        for &c in dir { if w < out.len() { out[w] = c; w += 1; } }
        if w < out.len() { out[w] = b'/'; w += 1; }
        for &c in prefix { if w < out.len() { out[w] = c; w += 1; } }
        // 6 hex digits of the mix for a stable-length suffix.
        let hex = b"0123456789abcdef";
        let mut i = 24i32;
        while i >= 0 { if w < out.len() { out[w] = hex[((mix >> i) & 0xf) as usize]; w += 1; } i -= 4; }
        if w < out.len() { out[w] = 0; }
        w
    }
}

// # C: char *tmpnam(char *s)
#[no_mangle]
pub unsafe extern "C" fn tmpnam(s: *mut u8) -> *mut u8 {
    // SAFETY: s is null or an L_tmpnam (>=20) buffer. Build a unique path under
    // P_tmpdir; into s when given, else a process-global buffer (glibc style).
    unsafe {
        static BUF: TmpBuf = TmpBuf(core::cell::UnsafeCell::new([0u8; PATH_MAX]));
        let mut tmp = [0u8; PATH_MAX];
        let dlen = tmp_dir(&mut tmp, core::ptr::null(), false);
        let mut name = [0u8; PATH_MAX];
        let nlen = build_name(&mut name, &tmp[..dlen], b"file");
        let dst = if s.is_null() { BUF.0.get() as *mut u8 } else { s };
        core::ptr::copy_nonoverlapping(name.as_ptr(), dst, nlen);
        *dst.add(nlen) = 0;
        dst
    }
}
struct TmpBuf(core::cell::UnsafeCell<[u8; PATH_MAX]>);
// SAFETY: process-global tmpnam scratch; single-threaded libc contract (the
// reentrant tmpnam_r takes a caller buffer).
unsafe impl Sync for TmpBuf {}

// # C: char *tmpnam_r(char *s)
#[no_mangle]
pub unsafe extern "C" fn tmpnam_r(s: *mut u8) -> *mut u8 {
    // SAFETY: s is null (→ NULL, no global buffer) or a caller L_tmpnam buffer.
    unsafe { if s.is_null() { core::ptr::null_mut() } else { tmpnam(s) } }
}

// # C: char *tempnam(const char *dir, const char *pfx)
#[no_mangle]
pub unsafe extern "C" fn tempnam(dir: *const u8, pfx: *const u8) -> *mut u8 {
    // SAFETY: dir/pfx are null or NUL-terminated. Build a unique path under the
    // chosen dir with the given prefix into a malloc'd buffer the caller frees.
    unsafe {
        let mut tmp = [0u8; PATH_MAX];
        let dlen = tmp_dir(&mut tmp, dir, true);
        let mut prefix = [0u8; 8];
        let mut pl = 0;
        if !pfx.is_null() { while pl < 5 { let c = *pfx.add(pl); if c == 0 { break; } prefix[pl] = c; pl += 1; } }
        let mut name = [0u8; PATH_MAX];
        let nlen = build_name(&mut name, &tmp[..dlen], &prefix[..pl]);
        let d = malloc(nlen + 1) as *mut u8;
        if d.is_null() { return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(name.as_ptr(), d, nlen);
        *d.add(nlen) = 0;
        d
    }
}

// # C: int remove(const char *path) — unlink a file, rmdir a directory.
#[no_mangle]
pub unsafe extern "C" fn remove(path: *const u8) -> i32 {
    // SAFETY: path is NUL-terminated. Try unlink; on EISDIR fall back to rmdir
    // (glibc remove dispatches on the kernel's directory error).
    unsafe {
        const EISDIR: i32 = 21;
        let r = unlink(path);
        if r == 0 { return 0; }
        if *errno::__errno_location() == EISDIR { return rmdir(path); }
        r
    }
}

// ---- generic indirect syscall ----

// # C: long syscall(long number, ...)
#[no_mangle]
pub unsafe extern "C" fn syscall(number: core::ffi::c_long, mut ap: ...) -> core::ffi::c_long {
    // SAFETY: variadic up to 6 register args forwarded verbatim to syscall6;
    // the caller guarantees `number` + the supplied args form a valid kernel
    // call. Result follows the raw -errno convention split by errno::ret_isize.
    unsafe {
        let a1 = ap.next_arg::<usize>();
        let a2 = ap.next_arg::<usize>();
        let a3 = ap.next_arg::<usize>();
        let a4 = ap.next_arg::<usize>();
        let a5 = ap.next_arg::<usize>();
        let a6 = ap.next_arg::<usize>();
        errno::ret_isize(syscall6(number as usize, a1, a2, a3, a4, a5, a6)) as core::ffi::c_long
    }
}

// ---- obsolete / deprecated (ENOSYS, matching modern glibc) ----

// _sysctl was removed from Linux; glibc's stub sets ENOSYS and returns -1
// without issuing a syscall. These obsolete entry points dereference nothing.

// # C: int sysctl(int *name, int nlen, void *old, size_t *oldlen, void *new, size_t newlen)
#[no_mangle]
pub extern "C" fn sysctl(_name: *mut i32, _nlen: i32, _old: *mut c_void, _oldlen: *mut usize, _new: *mut c_void, _newlen: usize) -> i32 {
    errno::set(ENOSYS); -1
}
// # C: int _sysctl(...) — alias glibc keeps for the removed syscall.
#[no_mangle]
pub extern "C" fn _sysctl(_name: *mut i32, _nlen: i32, _old: *mut c_void, _oldlen: *mut usize, _new: *mut c_void, _newlen: usize) -> i32 {
    errno::set(ENOSYS); -1
}
// # C: int vlimit(int resource, int value) — obsolete BSD; ENOSYS.
#[no_mangle]
pub extern "C" fn vlimit(_resource: i32, _value: i32) -> i32 {
    errno::set(ENOSYS); -1
}
// # C: int vtimes(struct vtimes *par, struct vtimes *chi) — obsolete BSD; ENOSYS.
#[no_mangle]
pub extern "C" fn vtimes(_par: *mut c_void, _chi: *mut c_void) -> i32 {
    errno::set(ENOSYS); -1
}
// # C: int gtty(int fd, struct sgttyb *params) — obsolete; ENOSYS.
#[no_mangle]
pub extern "C" fn gtty(_fd: i32, _params: *mut c_void) -> i32 {
    errno::set(ENOSYS); -1
}
// # C: int stty(int fd, const struct sgttyb *params) — obsolete; ENOSYS.
#[no_mangle]
pub extern "C" fn stty(_fd: i32, _params: *const c_void) -> i32 {
    errno::set(ENOSYS); -1
}
