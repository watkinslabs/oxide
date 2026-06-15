// <err.h> — BSD-style error reporting (err/warn family). glibc provides
// these as a compatibility layer. Output goes to stderr in the form:
//   "progname: <user message>: <strerror(errno)>\n"   (warn/err)
//   "progname: <user message>\n"                       (warnx/errx)
// The err*/errx* variants then exit(eval). progname is
// program_invocation_short_name (misc::progname).

#![cfg(feature = "freestanding")]
use super::progname;
use super::sink::{vformat_into, FdSink};
use crate::string::strerror::msg as strerror_msg;
use core::ffi::VaList;

const STDERR_FD: i32 = 2;

// Emit "progname: [<fmt-expanded>][: strerror]\n" to stderr. `with_errno`
// captures errno BEFORE formatting (glibc reads it up front so the user
// format cannot clobber it), then appends ": <strerror>".
unsafe fn emit(fmt: *const u8, ap: &mut VaList, with_errno: bool) {
    // SAFETY: errno slot is this thread's; read it before formatting.
    let e = unsafe { *crate::internal::errno::__errno_location() };
    let mut s = FdSink::new(STDERR_FD);
    s.put_cstr(progname::short());
    s.put(b':');
    s.put(b' ');
    if !fmt.is_null() {
        // SAFETY: fmt is NUL-terminated; ap supplies the named varargs.
        unsafe { vformat_into(&mut s, fmt, ap); }
    }
    if with_errno {
        s.put(b':');
        s.put(b' ');
        // strerror_msg is NUL-terminated; drop the NUL before the newline.
        let m = strerror_msg(e);
        for &b in &m[..m.len().saturating_sub(1)] { s.put(b); }
    }
    s.put(b'\n');
    s.flush();
}

// # C: void vwarn(const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vwarn(fmt: *const u8, mut ap: VaList) {
    // SAFETY: fmt NUL-terminated or null; ap holds the matching varargs.
    unsafe { emit(fmt, &mut ap, true); }
}
// # C: void vwarnx(const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vwarnx(fmt: *const u8, mut ap: VaList) {
    // SAFETY: fmt NUL-terminated or null; ap holds the matching varargs.
    unsafe { emit(fmt, &mut ap, false); }
}
// # C: void verr(int eval, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn verr(eval: i32, fmt: *const u8, mut ap: VaList) -> ! {
    // SAFETY: fmt NUL-terminated or null; ap holds the matching varargs.
    unsafe { emit(fmt, &mut ap, true); }
    crate::stdlib::exit::exit(eval)
}
// # C: void verrx(int eval, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn verrx(eval: i32, fmt: *const u8, mut ap: VaList) -> ! {
    // SAFETY: fmt NUL-terminated or null; ap holds the matching varargs.
    unsafe { emit(fmt, &mut ap, false); }
    crate::stdlib::exit::exit(eval)
}
// # C: void warn(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn warn(fmt: *const u8, mut ap: ...) {
    // SAFETY: ap supplies the varargs named by fmt; appends strerror(errno).
    unsafe { emit(fmt, &mut ap, true); }
}
// # C: void warnx(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn warnx(fmt: *const u8, mut ap: ...) {
    // SAFETY: ap supplies the varargs named by fmt; no strerror suffix.
    unsafe { emit(fmt, &mut ap, false); }
}
// # C: void err(int eval, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn err(eval: i32, fmt: *const u8, mut ap: ...) -> ! {
    // SAFETY: ap supplies the varargs named by fmt; appends strerror, exits.
    unsafe { emit(fmt, &mut ap, true); }
    crate::stdlib::exit::exit(eval)
}
// # C: void errx(int eval, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn errx(eval: i32, fmt: *const u8, mut ap: ...) -> ! {
    // SAFETY: ap supplies the varargs named by fmt; no strerror, exits.
    unsafe { emit(fmt, &mut ap, false); }
    crate::stdlib::exit::exit(eval)
}
