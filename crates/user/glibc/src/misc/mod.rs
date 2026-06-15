// misc — small glibc surfaces that don't fit a larger area (docs/59§6).
// <syslog.h> (system logging), <err.h> (BSD err/warn), <error.h> (GNU
// error/error_at_line). All format via the shared printf engine
// (crate::stdio::fmt) and write to a fd (stderr / /dev/log / console).
//
// program_invocation_name / program_invocation_short_name are the glibc
// data symbols err()/error() prefix their messages with; they are seeded
// from argv[0] by __libc_start_main (progname::seed). Defined here so the
// misc consumers and the startup seeder share one definition.

pub mod progname;
pub mod syslog;
pub mod err;
pub mod error;
#[cfg(feature = "freestanding")]
pub mod backtrace;

// Shared fd-backed formatting sink: drives crate::stdio::fmt::vformat with
// a VaList, accumulating into a small stack buffer flushed via write(2).
// Used by err/warn/error (no stdio buffering dependency, no_std).
#[cfg(feature = "freestanding")]
pub(crate) mod sink {
    use crate::stdio::fmt::{Args, Sink};
    use core::ffi::{c_void, VaList};

    pub(crate) struct FdSink { fd: i32, buf: [u8; 256], len: usize }
    impl FdSink {
        /// # C: new fd-backed sink targeting descriptor `fd`.
        pub(crate) fn new(fd: i32) -> Self { FdSink { fd, buf: [0; 256], len: 0 } }
        /// # C: flush the pending buffer with write(2).
        pub(crate) fn flush(&mut self) {
            if self.len > 0 {
                // SAFETY: buf[..len] is initialised; write(2) reads exactly
                // len bytes and the kernel validates the range.
                unsafe { crate::posix::io::write(self.fd, self.buf.as_ptr(), self.len); }
                self.len = 0;
            }
        }
        /// # C: append one byte to the sink.
        pub(crate) fn put(&mut self, b: u8) { self.push(b); }
        /// # C: append a NUL-terminated C string (excluding the NUL).
        pub(crate) fn put_cstr(&mut self, mut s: *const u8) {
            if s.is_null() { return; }
            // SAFETY: s is a NUL-terminated C string; loop stops at the NUL.
            unsafe { while *s != 0 { self.push(*s); s = s.add(1); } }
        }
    }
    impl Sink for FdSink {
        fn push(&mut self, b: u8) {
            self.buf[self.len] = b;
            self.len += 1;
            if self.len == self.buf.len() { self.flush(); }
        }
        fn count(&self) -> usize { 0 }
    }

    pub(crate) struct Va<'a, 'b>(pub(crate) &'a mut VaList<'b>);
    impl Args for Va<'_, '_> {
        unsafe fn next_i32(&mut self) -> i32 { unsafe { self.0.next_arg() } }
        unsafe fn next_i64(&mut self) -> i64 { unsafe { self.0.next_arg() } }
        unsafe fn next_u32(&mut self) -> u32 { unsafe { self.0.next_arg() } }
        unsafe fn next_u64(&mut self) -> u64 { unsafe { self.0.next_arg() } }
        unsafe fn next_ptr(&mut self) -> *const u8 { unsafe { self.0.next_arg::<*mut c_void>() as *const u8 } }
        unsafe fn next_f64(&mut self) -> f64 { unsafe { self.0.next_arg() } }
    }

    // # C: format `fmt` with `ap` into the sink via the printf engine.
    pub(crate) unsafe fn vformat_into(sink: &mut FdSink, fmt: *const u8, ap: &mut VaList) {
        let mut a = Va(ap);
        // SAFETY: fmt is NUL-terminated; ap holds the matching varargs.
        unsafe { crate::stdio::fmt::vformat(sink, fmt, &mut a); }
    }
}
