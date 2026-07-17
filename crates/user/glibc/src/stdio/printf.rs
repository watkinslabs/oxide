// printf family (docs/59§6 G6). c_variadic C exports over the format
// engine (super::fmt). G6a writes unbuffered via posix::io::write; stdio
// buffering is a G6 follow-up. v* variants take a va_list (VaList); the
// rest take C varargs (...).
#![cfg(feature = "freestanding")]
use super::fmt::{self, Args, Sink};
use super::file::{self, FILE};
use super::memstream::stream_write;
use crate::posix::io;
use core::ffi::{c_void, VaList};
use core::sync::atomic::{AtomicI32, Ordering};

static NEXT_PRINTF_TYPE: AtomicI32 = AtomicI32::new(8);

// # C: int register_printf_type(printf_va_arg_function fct)
#[no_mangle]
pub extern "C" fn register_printf_type(_fct: *mut c_void) -> i32 {
    NEXT_PRINTF_TYPE.fetch_add(1, Ordering::Relaxed)
}

// snprintf sink: write ≤ cap-1 bytes + NUL; count everything (return value).
struct SliceSink { buf: *mut u8, cap: usize, pos: usize, total: usize }
impl SliceSink {
    fn new(buf: *mut u8, cap: usize) -> Self { SliceSink { buf, cap, pos: 0, total: 0 } }
    fn terminate(&self) {
        if self.cap > 0 {
            // SAFETY: pos < cap by construction, so buf[pos] is in bounds.
            unsafe { *self.buf.add(self.pos) = 0; }
        }
    }
}
impl Sink for SliceSink {
    fn push(&mut self, b: u8) {
        if self.cap > 0 && self.pos < self.cap - 1 {
            // SAFETY: pos < cap-1, so buf[pos] is within the caller's buffer.
            unsafe { *self.buf.add(self.pos) = b; }
            self.pos += 1;
        }
        self.total += 1;
    }
    fn count(&self) -> usize { self.total }
}

// dprintf sink: buffer then write(2) to an explicitly supplied fd.
struct FdSink { fd: i32, buf: [u8; 256], len: usize, total: usize }
impl FdSink {
    fn new(fd: i32) -> Self { FdSink { fd, buf: [0; 256], len: 0, total: 0 } }
    fn flush(&mut self) {
        if self.len > 0 {
            // SAFETY: buf[..len] is initialised; write reads exactly len bytes.
            unsafe { io::write(self.fd, self.buf.as_ptr(), self.len); }
            self.len = 0;
        }
    }
}
impl Sink for FdSink {
    fn push(&mut self, b: u8) {
        self.buf[self.len] = b;
        self.len += 1;
        self.total += 1;
        if self.len == self.buf.len() { self.flush(); }
    }
    fn count(&self) -> usize { self.total }
}

// FILE sink: buffer then route through stream_write so stdio and memory
// streams share the canonical FILE ownership path.
struct FileSink { f: *mut FILE, buf: [u8; 256], len: usize, total: usize }
impl FileSink {
    fn new(f: *mut FILE) -> Self { FileSink { f, buf: [0; 256], len: 0, total: 0 } }
    fn flush(&mut self) {
        if self.len > 0 {
            // SAFETY: buf[..len] is initialised; stream_write reads len bytes.
            unsafe { stream_write(self.f, self.buf.as_ptr(), self.len); }
            self.len = 0;
        }
    }
}
impl Sink for FileSink {
    fn push(&mut self, b: u8) {
        self.buf[self.len] = b;
        self.len += 1;
        self.total += 1;
        if self.len == self.buf.len() { self.flush(); }
    }
    fn count(&self) -> usize { self.total }
}
unsafe fn into_file(f: *mut FILE, fmt: *const u8, ap: &mut VaList) -> i32 {
    let mut sink = FileSink::new(f);
    let mut a = Va(ap);
    // SAFETY: fmt is NUL-terminated; ap holds the matching varargs.
    let total = unsafe { fmt::vformat(&mut sink, fmt, &mut a) };
    sink.flush();
    total as i32
}

struct Va<'a, 'b>(&'a mut VaList<'b>);
impl Args for Va<'_, '_> {
    unsafe fn next_i32(&mut self) -> i32 { unsafe { self.0.next_arg() } }
    unsafe fn next_i64(&mut self) -> i64 { unsafe { self.0.next_arg() } }
    unsafe fn next_u32(&mut self) -> u32 { unsafe { self.0.next_arg() } }
    unsafe fn next_u64(&mut self) -> u64 { unsafe { self.0.next_arg() } }
    unsafe fn next_ptr(&mut self) -> *const u8 { unsafe { self.0.next_arg::<*mut c_void>() as *const u8 } }
    unsafe fn next_f64(&mut self) -> f64 { unsafe { self.0.next_arg() } }
}

unsafe fn into_slice(s: *mut u8, n: usize, fmt: *const u8, ap: &mut VaList) -> i32 {
    let mut sink = SliceSink::new(s, n);
    let mut a = Va(ap);
    // SAFETY: fmt is NUL-terminated; ap holds the matching varargs.
    let total = unsafe { fmt::vformat(&mut sink, fmt, &mut a) };
    sink.terminate();
    total as i32
}
unsafe fn into_fd(fd: i32, fmt: *const u8, ap: &mut VaList) -> i32 {
    let mut sink = FdSink::new(fd);
    let mut a = Va(ap);
    // SAFETY: fmt is NUL-terminated; ap holds the matching varargs.
    let total = unsafe { fmt::vformat(&mut sink, fmt, &mut a) };
    sink.flush();
    total as i32
}

// # C: int vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vsnprintf(s: *mut u8, n: usize, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: forwards to the slice formatter under the C contract.
    unsafe { into_slice(s, n, fmt, &mut ap) }
}
// # C: int __vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn __vsnprintf(s: *mut u8, n: usize, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: internal alias has the same buffer/format/va_list contract as vsnprintf.
    unsafe { into_slice(s, n, fmt, &mut ap) }
}
// # C: int snprintf(char *s, size_t n, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn snprintf(s: *mut u8, n: usize, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: ap supplies the varargs named by fmt; buffer is n bytes.
    unsafe { into_slice(s, n, fmt, &mut ap) }
}
// # C: int vsprintf(char *s, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vsprintf(s: *mut u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: unbounded buffer per C sprintf; caller guarantees capacity.
    unsafe { into_slice(s, usize::MAX, fmt, &mut ap) }
}
// # C: int sprintf(char *s, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn sprintf(s: *mut u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: unbounded buffer per C sprintf; caller guarantees capacity.
    unsafe { into_slice(s, usize::MAX, fmt, &mut ap) }
}
// asprintf: format into a grown buffer, then malloc(len+1)+copy so the result
// is free()-able by the caller. Format once (no va_copy needed).
struct VecSink { v: alloc::vec::Vec<u8> }
impl Sink for VecSink {
    fn push(&mut self, b: u8) { self.v.push(b); }
    fn count(&self) -> usize { self.v.len() }
}
unsafe fn into_alloc(strp: *mut *mut u8, fmt: *const u8, ap: &mut VaList) -> i32 {
    extern "C" { fn malloc(n: usize) -> *mut c_void; }
    let mut sink = VecSink { v: alloc::vec::Vec::new() };
    let mut a = Va(ap);
    // SAFETY: fmt NUL-terminated; ap holds the matching varargs.
    let n = unsafe { fmt::vformat(&mut sink, fmt, &mut a) };
    // SAFETY: malloc n+1; copy the formatted bytes + NUL; publish via *strp.
    unsafe {
        let buf = malloc(n + 1) as *mut u8;
        if buf.is_null() { *strp = core::ptr::null_mut(); return -1; }
        core::ptr::copy_nonoverlapping(sink.v.as_ptr(), buf, n);
        *buf.add(n) = 0;
        *strp = buf;
    }
    n as i32
}
// # C: int vasprintf(char **strp, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vasprintf(strp: *mut *mut u8, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: strp writable; fmt/ap per the C contract.
    unsafe { into_alloc(strp, fmt, &mut ap) }
}
// # C: int asprintf(char **strp, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn asprintf(strp: *mut *mut u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: strp writable; ap supplies the varargs named by fmt.
    unsafe { into_alloc(strp, fmt, &mut ap) }
}
// # C: int __asprintf(char **strp, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn __asprintf(strp: *mut *mut u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: __asprintf has the same writable strp and varargs contract as asprintf.
    unsafe { into_alloc(strp, fmt, &mut ap) }
}

// # C: int vfprintf(FILE *f, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vfprintf(f: *mut file::FILE, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: f is a valid stream (fd-backed or memory); route via stream_write.
    unsafe { into_file(f, fmt, &mut ap) }
}
// # C: int fprintf(FILE *f, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn fprintf(f: *mut file::FILE, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: f is a valid stream; ap supplies the named varargs.
    unsafe { into_file(f, fmt, &mut ap) }
}
// # C: int vprintf(const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vprintf(fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: stdout is the process-owned FILE stream; ap holds matching varargs.
    unsafe { into_file(file::stdout_ptr(), fmt, &mut ap) }
}
// # C: int printf(const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn printf(fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: stdout is the process-owned FILE stream; ap supplies matching varargs.
    unsafe { into_file(file::stdout_ptr(), fmt, &mut ap) }
}
// # C: int dprintf(int fd, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn dprintf(fd: i32, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: fd is an open descriptor; ap supplies the named varargs.
    unsafe { into_fd(fd, fmt, &mut ap) }
}
// # C: int vdprintf(int fd, const char *fmt, va_list ap)
#[no_mangle]
pub unsafe extern "C" fn vdprintf(fd: i32, fmt: *const u8, mut ap: VaList) -> i32 {
    // SAFETY: fd is an open descriptor; ap holds the matching varargs.
    unsafe { into_fd(fd, fmt, &mut ap) }
}
