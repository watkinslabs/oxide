// fopencookie(3) (docs/59§6 G6, GNU): a custom stream whose I/O is driven by
// four caller callbacks (read/write/seek/close) over an opaque cookie. Reuses
// the FILE backing abstraction — _fileno=-1 + IS_COOKIE bit + a CookieStream*
// in _codecvt — so all of stdio routes through it via the stream_* helpers.
// C ABI only. (funopen is BSD-only and absent from glibc, so not provided.)
#![cfg(feature = "freestanding")]
use super::file::{alloc_file, cookie, set_cookie_backing, FILE};
use crate::malloc::heap;
use core::ffi::c_void;

type ReadFn = extern "C" fn(*mut c_void, *mut u8, usize) -> isize;
type WriteFn = extern "C" fn(*mut c_void, *const u8, usize) -> isize;
type SeekFn = extern "C" fn(*mut c_void, *mut i64, i32) -> i32;
type CloseFn = extern "C" fn(*mut c_void) -> i32;

#[repr(C)]
pub struct CookieIoFns { read: Option<ReadFn>, write: Option<WriteFn>, seek: Option<SeekFn>, close: Option<CloseFn> }

struct CookieStream { cookie: *mut c_void, io: CookieIoFns }

unsafe fn cs(f: *mut FILE) -> *mut CookieStream {
    // SAFETY: f is a fopencookie stream; its cookie pointer is in _codecvt.
    unsafe { cookie(f) as *mut CookieStream }
}

pub(crate) unsafe fn cookie_read(f: *mut FILE, dst: *mut u8, n: usize) -> isize {
    // SAFETY: f is a cookie stream; invoke the caller's read callback (EOF=0 if
    // it provided none).
    unsafe { let c = cs(f); match (*c).io.read { Some(r) => r((*c).cookie, dst, n), None => 0 } }
}
pub(crate) unsafe fn cookie_write(f: *mut FILE, src: *const u8, n: usize) -> isize {
    // SAFETY: f is a cookie stream; invoke the caller's write callback (0 if none).
    unsafe { let c = cs(f); match (*c).io.write { Some(wr) => wr((*c).cookie, src, n), None => 0 } }
}
pub(crate) unsafe fn cookie_seek(f: *mut FILE, off: i64, whence: i32) -> i64 {
    // SAFETY: f is a cookie stream; the seek callback takes an in/out offset and
    // returns 0 on success (then *pos is the new absolute position), -1 on error.
    unsafe {
        let c = cs(f);
        match (*c).io.seek {
            Some(sk) => { let mut pos = off; if sk((*c).cookie, &mut pos, whence) < 0 { -1 } else { pos } }
            None => -1,
        }
    }
}
pub(crate) unsafe fn cookie_close(f: *mut FILE) {
    // SAFETY: f is a cookie stream; call the close callback (if any), then free
    // the CookieStream wrapper.
    unsafe { let c = cs(f); if let Some(cl) = (*c).io.close { cl((*c).cookie); } heap::free(c as *mut u8); }
}

// # C: FILE *fopencookie(void *cookie, const char *mode, cookie_io_functions_t io)
#[no_mangle]
pub unsafe extern "C" fn fopencookie(cookie: *mut c_void, _mode: *const u8, io: CookieIoFns) -> *mut FILE {
    // SAFETY: cookie is the caller's opaque handle; io holds the (nullable)
    // callbacks. Wrap them in a heap CookieStream and a fd-less FILE.
    unsafe {
        let c = heap::malloc(core::mem::size_of::<CookieStream>()) as *mut CookieStream;
        if c.is_null() { return core::ptr::null_mut(); }
        c.write(CookieStream { cookie, io });
        let f = alloc_file(-1, 0);
        if f.is_null() { heap::free(c as *mut u8); return core::ptr::null_mut(); }
        set_cookie_backing(f, c as *mut u8);
        f
    }
}
