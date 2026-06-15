// <error.h> — GNU error()/error_at_line(). Output to stderr:
//   "progname: <fmt>[: strerror(errnum)]\n"            (error)
//   "progname:fname:line: <fmt>[: strerror(errnum)]\n" (error_at_line)
// errnum == 0 omits the strerror suffix. status != 0 → exit(status).
// Public data hooks (glibc-compatible):
//   error_message_count  — incremented per call.
//   error_print_progname — if non-NULL, called instead of printing progname.
//   error_one_per_line   — error_at_line skips a repeat of the same
//                          file+line when set.

#![cfg(feature = "freestanding")]
use super::progname;
use super::sink::{vformat_into, FdSink};
use crate::string::strerror::msg as strerror_msg;
use core::cell::UnsafeCell;
use core::ffi::VaList;
use core::sync::atomic::{AtomicI32, Ordering};

const STDERR_FD: i32 = 2;

// Writable C data symbols. Wrapped in UnsafeCell (no `static mut`, per
// docs/07§5) and Sync-asserted: glibc itself accesses these unsynchronised,
// and oxide's startup is single-threaded before any error() call.
#[repr(transparent)]
struct U32Cell(UnsafeCell<u32>);
// SAFETY: the C error() data symbols are read/written without locking by
// glibc too; oxide error() runs single-threaded relative to these counters.
unsafe impl Sync for U32Cell {}
#[repr(transparent)]
struct I32Cell(UnsafeCell<i32>);
// SAFETY: same contract as U32Cell — plain integer data symbol, no aliasing.
unsafe impl Sync for I32Cell {}

// # C: unsigned int error_message_count;
#[no_mangle]
static error_message_count: U32Cell = U32Cell(UnsafeCell::new(0));

// # C: int error_one_per_line;
#[no_mangle]
static error_one_per_line: I32Cell = I32Cell(UnsafeCell::new(0));

type PrintProgFn = extern "C" fn();
#[repr(transparent)]
struct PrintProg(UnsafeCell<Option<PrintProgFn>>);
// SAFETY: a plain function-pointer cell the program sets at most once; libc
// only reads it. No interior pointer aliasing beyond the C data-symbol API.
unsafe impl Sync for PrintProg {}
// # C: void (*error_print_progname)(void);
#[no_mangle]
static error_print_progname: PrintProg = PrintProg(UnsafeCell::new(None));

// last file+line reported, for error_one_per_line dedup in error_at_line.
static LAST_LINE: AtomicI32 = AtomicI32::new(-1);
static LAST_FILE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe fn emit_progname(s: &mut FdSink) {
    // SAFETY: reads the program-set hook; if non-NULL it prints progname.
    let hook = unsafe { *error_print_progname.0.get() };
    match hook {
        Some(f) => { s.flush(); f(); }
        None => s.put_cstr(progname::full()),
    }
}

unsafe fn core_emit(errnum: i32, file: *const u8, line: u32, has_loc: bool, fmt: *const u8, ap: &mut VaList) {
    let mut s = FdSink::new(STDERR_FD);
    // SAFETY: emit_progname reads the progname hook / data symbol.
    unsafe { emit_progname(&mut s); }
    if has_loc {
        s.put(b':');
        s.put_cstr(file);
        s.put(b':');
        // decimal line number
        let mut tmp = [0u8; 10];
        let mut n = line;
        let mut i = tmp.len();
        loop { i -= 1; tmp[i] = b'0' + (n % 10) as u8; n /= 10; if n == 0 { break; } }
        for &b in &tmp[i..] { s.put(b); }
    }
    s.put(b':');
    s.put(b' ');
    if !fmt.is_null() {
        // SAFETY: fmt NUL-terminated; ap supplies the named varargs.
        unsafe { vformat_into(&mut s, fmt, ap); }
    }
    if errnum != 0 {
        s.put(b':');
        s.put(b' ');
        // strerror_msg is NUL-terminated; drop the NUL before the newline.
        let m = strerror_msg(errnum);
        for &b in &m[..m.len().saturating_sub(1)] { s.put(b); }
    }
    s.put(b'\n');
    s.flush();
    // SAFETY: single increment of the public counter; startup single-thread
    // assumption matches glibc (unsynchronised in glibc too).
    unsafe { let c = error_message_count.0.get(); *c = (*c).wrapping_add(1); }
}

// # C: void error(int status, int errnum, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn error(status: i32, errnum: i32, fmt: *const u8, mut ap: ...) {
    // SAFETY: ap supplies the varargs named by fmt; emits one diagnostic.
    unsafe { core_emit(errnum, core::ptr::null(), 0, false, fmt, &mut ap); }
    if status != 0 { crate::stdlib::exit::exit(status); }
}

// # C: void error_at_line(int status, int errnum, const char *file, unsigned int line, const char *fmt, ...)
#[no_mangle]
pub unsafe extern "C" fn error_at_line(status: i32, errnum: i32, file: *const u8, line: u32, fmt: *const u8, mut ap: ...) {
    // error_one_per_line: suppress a repeat of the same file+line.
    // SAFETY: reads the public flag; compares against the last location.
    let once = unsafe { *error_one_per_line.0.get() } != 0;
    if once {
        let lf = file as usize;
        if LAST_LINE.load(Ordering::Relaxed) == line as i32 && LAST_FILE.load(Ordering::Relaxed) == lf {
            return;
        }
        LAST_LINE.store(line as i32, Ordering::Relaxed);
        LAST_FILE.store(lf, Ordering::Relaxed);
    }
    // SAFETY: ap supplies the varargs named by fmt; emits with file:line.
    unsafe { core_emit(errnum, file, line, true, fmt, &mut ap); }
    if status != 0 { crate::stdlib::exit::exit(status); }
}
