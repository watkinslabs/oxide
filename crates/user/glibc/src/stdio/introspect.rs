// GNU/Solaris stdio_ext introspection (docs/59§6 G6). These read FILE-struct
// state our stdio maintains: buffer span (set_buf), buffering mode + access
// mode + last-op direction (the _flags bits). Booleans match glibc semantics;
// raw sizes are our-FILE specific.
#![cfg(feature = "freestanding")]
use super::file::{buf_size, last_was_read, FILE, IO_LINE_BUF, IO_NO_READS, IO_NO_WRITES};

// __fsetlocking states (stdio_ext.h): 0=query, 1=internal, 2=bycaller.
const FSETLOCKING_BYCALLER: i32 = 2;

unsafe fn flags(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; read its _flags word.
    unsafe { (*f)._flags }
}

// # C: size_t __fbufsize(FILE *f) — size of the stream's buffer.
#[no_mangle]
pub unsafe extern "C" fn __fbufsize(f: *mut FILE) -> usize {
    // SAFETY: f is a valid stream; report the recorded buffer span.
    unsafe { buf_size(f) }
}
// # C: size_t __fpending(FILE *f) — bytes in the put buffer pending flush.
#[no_mangle]
pub unsafe extern "C" fn __fpending(f: *mut FILE) -> usize {
    // SAFETY: f is a valid stream; our I/O is unbuffered, so nothing pends.
    let _ = f; 0
}
// # C: int __freadable(FILE *f) — nonzero if the stream allows reads.
#[no_mangle]
pub unsafe extern "C" fn __freadable(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; readable unless the NO_READS bit is set.
    unsafe { (flags(f) & IO_NO_READS == 0) as i32 }
}
// # C: int __fwritable(FILE *f) — nonzero if the stream allows writes.
#[no_mangle]
pub unsafe extern "C" fn __fwritable(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; writable unless the NO_WRITES bit is set.
    unsafe { (flags(f) & IO_NO_WRITES == 0) as i32 }
}
// # C: int __freading(FILE *f) — nonzero if the last op was a read (or RO).
#[no_mangle]
pub unsafe extern "C" fn __freading(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; read-only streams always read, otherwise
    // report the last-op direction.
    unsafe { (flags(f) & IO_NO_WRITES != 0 || last_was_read(f)) as i32 }
}
// # C: int __fwriting(FILE *f) — nonzero if the last op was a write (or WO).
#[no_mangle]
pub unsafe extern "C" fn __fwriting(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; write-only streams always write, otherwise
    // report the inverse of the last-op direction.
    unsafe { (flags(f) & IO_NO_READS != 0 || !last_was_read(f)) as i32 }
}
// # C: int __flbf(FILE *f) — nonzero if the stream is line-buffered.
#[no_mangle]
pub unsafe extern "C" fn __flbf(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; report the line-buffer flag.
    unsafe { (flags(f) & IO_LINE_BUF != 0) as i32 }
}
// # C: void __fpurge(FILE *f) — discard buffered (unread/unwritten) data.
#[no_mangle]
pub unsafe extern "C" fn __fpurge(f: *mut FILE) {
    // SAFETY: f is a valid stream; drop any one-char pushback. Unbuffered I/O
    // holds no other buffered data to discard.
    unsafe { let _ = super::file::take_unget(f); }
}
// # C: void _flushlbf(void) — flush all line-buffered streams.
#[no_mangle]
pub unsafe extern "C" fn _flushlbf() {
    // SAFETY: our fd streams are unbuffered, so nothing is held back; the call
    // is a no-op satisfying the contract that line-buffered data is flushed.
}
// # C: int __fsetlocking(FILE *f, int type) — set/query stream lock mode.
#[no_mangle]
pub unsafe extern "C" fn __fsetlocking(f: *mut FILE, ty: i32) -> i32 {
    // SAFETY: f is a valid stream. We run single-threaded (no per-stream lock),
    // so report BYCALLER and accept INTERNAL/BYCALLER requests as no-ops.
    let _ = (f, ty);
    FSETLOCKING_BYCALLER
}
