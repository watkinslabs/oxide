// scanf C ABI (docs/59§6 G6b). sscanf/vsscanf over a string Source.
// scanf/fscanf/vfscanf (FILE source) land with the read-side file ops
// (G6c), reusing this same engine.
#![cfg(feature = "freestanding")]
use super::file::{set_unget, stdin_ptr, FILE};
use super::read::getc_raw;
use super::scan::{self, ScanArgs, Source, StrSource};
use core::ffi::{c_void, VaList};

// A scanf Source backed by a FILE. Peeks by reading one byte ahead; any
// peeked-but-unconsumed byte is pushed back to the FILE on finish() so the
// stream position matches C scanf semantics.
struct FileSource { f: *mut FILE, ahead: i32, n: usize }
impl FileSource {
    fn new(f: *mut FILE) -> Self { FileSource { f, ahead: -2, n: 0 } }
    fn finish(&mut self) {
        if self.ahead >= 0 {
            // SAFETY: f is a valid stream; return the lookahead byte.
            unsafe { set_unget(self.f, self.ahead as u8); }
            self.ahead = -2;
        }
    }
}
impl Source for FileSource {
    fn peek(&mut self) -> i32 {
        if self.ahead == -2 {
            // SAFETY: f is a valid stream; read one byte of lookahead.
            self.ahead = unsafe { getc_raw(self.f) };
        }
        self.ahead
    }
    fn bump(&mut self) -> i32 { let c = self.peek(); if c >= 0 { self.ahead = -2; self.n += 1; } c }
    fn consumed(&self) -> usize { self.n }
}

struct Va<'a, 'b>(&'a mut VaList<'b>);
impl ScanArgs for Va<'_, '_> {
    unsafe fn next_ptr(&mut self) -> *mut u8 {
        // SAFETY: each scanf vararg is a pointer destination per the format.
        unsafe { self.0.next_arg::<*mut c_void>() as *mut u8 }
    }
}

unsafe fn scan_str_va(s: *const u8, fmt: *const u8, ap: &mut VaList) -> i32 {
    // SAFETY: s/fmt are NUL-terminated; ap holds matching pointer args.
    unsafe {
        let mut src = StrSource::new(s);
        let mut a = Va(ap);
        scan::vscan(&mut src, fmt, &mut a)
    }
}

unsafe fn scan_file_va(f: *mut FILE, fmt: *const u8, ap: &mut VaList) -> i32 {
    // SAFETY: f is a readable stream; fmt NUL-terminated; ap pointer args.
    unsafe {
        let mut src = FileSource::new(f);
        let mut a = Va(ap);
        let r = scan::vscan(&mut src, fmt, &mut a);
        src.finish();
        r
    }
}

// # C: int vsscanf(const char *s, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vsscanf(s: *const u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: s/fmt are NUL-terminated; ap holds matching pointer args.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}
// # C: int __vsscanf(const char *s, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __vsscanf(s: *const u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: internal alias has the same ABI contract and va_list layout as vsscanf.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}

// # C: int sscanf(const char *s, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn sscanf(s: *const u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: s/fmt are NUL-terminated; ap supplies the pointer args.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}

// glibc 2.38+ headers redirect sscanf to __isoc23_sscanf (and older ones to
// __isoc99_sscanf). Same contract as sscanf; provide both aliases.
// # C: int __isoc23_sscanf(const char *s, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_sscanf(s: *const u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: s/fmt NUL-terminated; ap supplies the pointer args.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}
// # C: int __isoc99_sscanf(const char *s, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __isoc99_sscanf(s: *const u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: s/fmt NUL-terminated; ap supplies the pointer args.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}

// # C: int __isoc23_vsscanf(const char *s, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_vsscanf(s: *const u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: same ABI contract and va_list layout as vsscanf.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}

// # C: int __isoc99_vsscanf(const char *s, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __isoc99_vsscanf(s: *const u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: same ABI contract and va_list layout as vsscanf.
    unsafe { scan_str_va(s, fmt, &mut ap) }
}

// # C: int vfscanf(FILE *f, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vfscanf(f: *mut FILE, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: f is a readable stream; fmt NUL-terminated; ap pointer args.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}
// # C: int __vfscanf(FILE *f, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __vfscanf(f: *mut FILE, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: internal alias has the same ABI contract and va_list layout as vfscanf.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}
// # C: int fscanf(FILE *f, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn fscanf(f: *mut FILE, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: f is a readable stream; ap supplies the pointer args.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}

// # C: int __isoc23_vfscanf(FILE *f, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_vfscanf(f: *mut FILE, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: same ABI contract and va_list layout as vfscanf.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}

// # C: int __isoc99_vfscanf(FILE *f, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __isoc99_vfscanf(f: *mut FILE, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: same ABI contract and va_list layout as vfscanf.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}

// # C: int __isoc23_fscanf(FILE *f, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_fscanf(f: *mut FILE, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: same ABI contract and varargs layout as fscanf.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}

// # C: int __isoc99_fscanf(FILE *f, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __isoc99_fscanf(f: *mut FILE, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: same ABI contract and varargs layout as fscanf.
    unsafe { scan_file_va(f, fmt, &mut ap) }
}

// # C: int vscanf(const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vscanf(fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: reads from stdin; fmt NUL-terminated; ap pointer args.
    unsafe { scan_file_va(stdin_ptr(), fmt, &mut ap) }
}
// # C: int scanf(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn scanf(fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: reads from stdin; ap supplies the pointer args.
    unsafe { scan_file_va(stdin_ptr(), fmt, &mut ap) }
}

// # C: int __isoc23_vscanf(const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_vscanf(fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: same ABI contract and va_list layout as vscanf.
    unsafe { scan_file_va(stdin_ptr(), fmt, &mut ap) }
}

// # C: int __isoc99_vscanf(const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __isoc99_vscanf(fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: same ABI contract and va_list layout as vscanf.
    unsafe { scan_file_va(stdin_ptr(), fmt, &mut ap) }
}

// # C: int __isoc23_scanf(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __isoc23_scanf(fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: same ABI contract and varargs layout as scanf.
    unsafe { scan_file_va(stdin_ptr(), fmt, &mut ap) }
}

// # C: int __isoc99_scanf(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __isoc99_scanf(fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: same ABI contract and varargs layout as scanf.
    unsafe { scan_file_va(stdin_ptr(), fmt, &mut ap) }
}
