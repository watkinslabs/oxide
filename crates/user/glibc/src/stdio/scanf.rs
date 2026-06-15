// scanf C ABI (docs/59§6 G6b). sscanf/vsscanf over a string Source.
// scanf/fscanf/vfscanf (FILE source) land with the read-side file ops
// (G6c), reusing this same engine.
#![cfg(feature = "freestanding")]
use super::scan::{self, ScanArgs, StrSource};
use core::ffi::{c_void, VaList};

struct Va<'a, 'b>(&'a mut VaList<'b>);
impl ScanArgs for Va<'_, '_> {
    unsafe fn next_ptr(&mut self) -> *mut u8 {
        // SAFETY: each scanf vararg is a pointer destination per the format.
        unsafe { self.0.next_arg::<*mut c_void>() as *mut u8 }
    }
}

// # C: int vsscanf(const char *s, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vsscanf(s: *const u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: s/fmt are NUL-terminated; ap holds matching pointer args.
    unsafe {
        let mut src = StrSource::new(s);
        let mut a = Va(&mut ap);
        scan::vscan(&mut src, fmt, &mut a)
    }
}

// # C: int sscanf(const char *s, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn sscanf(s: *const u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: s/fmt are NUL-terminated; ap supplies the pointer args.
    unsafe {
        let mut src = StrSource::new(s);
        let mut a = Va(&mut ap);
        scan::vscan(&mut src, fmt, &mut a)
    }
}
