// <fmtmsg.h> (docs/59§6) — fmtmsg formats a structured diagnostic
// (label: severity: text \n TO FIX: action tag) to stderr (MM_PRINT) and/or
// the system console (MM_CONSOLE, routed to stderr here). addseverity registers
// up to 8 application severity strings keyed by integer level. C ABI only.
#![cfg(feature = "freestanding")]
use crate::posix::io;
use crate::string::len::strlen_impl;
use core::cell::UnsafeCell;

// Classification bits (host fmtmsg.h enum).
pub const MM_HARD: i64 = 0x001;
pub const MM_SOFT: i64 = 0x002;
pub const MM_FIRM: i64 = 0x004;
pub const MM_APPL: i64 = 0x008;
pub const MM_UTIL: i64 = 0x010;
pub const MM_OPSYS: i64 = 0x020;
pub const MM_RECOVER: i64 = 0x040;
pub const MM_NRECOV: i64 = 0x080;
pub const MM_PRINT: i64 = 0x100;
pub const MM_CONSOLE: i64 = 0x200;
// Severity levels.
pub const MM_NOSEV: i32 = 0;
pub const MM_HALT: i32 = 1;
pub const MM_ERROR: i32 = 2;
pub const MM_WARNING: i32 = 3;
pub const MM_INFO: i32 = 4;
// Return values.
pub const MM_OK: i32 = 0;
pub const MM_NOTOK: i32 = -1;
pub const MM_NOMSG: i32 = 1;
pub const MM_NOCON: i32 = 4;

const MM_NULLSEV: i32 = 0;

// Built-in severity strings (NUL-terminated, paralleling glibc's table).
fn builtin_sev(s: i32) -> Option<&'static [u8]> {
    match s {
        MM_HALT => Some(b"HALT\0"),
        MM_ERROR => Some(b"ERROR\0"),
        MM_WARNING => Some(b"WARNING\0"),
        MM_INFO => Some(b"INFO\0"),
        _ => None,
    }
}

// addseverity registry: up to 8 (level, string-ptr) entries. A null/empty
// string removes the level; level<5 (built-in/NOSEV) can't be redefined.
#[derive(Clone, Copy)]
struct Sev { level: i32, str: *const u8 }
struct Tab(UnsafeCell<[Sev; 8]>);
// SAFETY: process-global addseverity table; single-threaded until TLS lands.
unsafe impl Sync for Tab {}
static TAB: Tab = Tab(UnsafeCell::new([Sev { level: 0, str: core::ptr::null() }; 8]));

unsafe fn lookup_custom(level: i32) -> *const u8 {
    // SAFETY: read-only scan of the process-global severity table.
    unsafe {
        let t = &*TAB.0.get();
        for e in t.iter() { if e.level == level && !e.str.is_null() { return e.str; } }
        core::ptr::null()
    }
}

// # C: int addseverity(int severity, const char *s)
#[no_mangle]
pub unsafe extern "C" fn addseverity(severity: i32, s: *const u8) -> i32 {
    // SAFETY: s is null or a NUL-terminated C string; mutate the process-global
    // severity table. Built-in levels (<=MM_INFO) and MM_NOSEV are immutable.
    unsafe {
        if (MM_NOSEV..=MM_INFO).contains(&severity) { return MM_NOTOK; }
        let t = &mut *TAB.0.get();
        let removing = s.is_null() || *s == 0;
        // Replace an existing entry for this level.
        for e in t.iter_mut() {
            if e.level == severity && !e.str.is_null() {
                if removing { e.str = core::ptr::null(); e.level = 0; } else { e.str = s; }
                return MM_OK;
            }
        }
        if removing { return MM_NOTOK; } // nothing to remove
        for e in t.iter_mut() {
            if e.str.is_null() { e.level = severity; e.str = s; return MM_OK; }
        }
        MM_NOTOK // table full
    }
}

unsafe fn emit(fd: i32, s: *const u8) {
    // SAFETY: s is a NUL-terminated C string; write its body (sans NUL) to fd.
    unsafe { if !s.is_null() { io::write(fd, s, strlen_impl(s)); } }
}
unsafe fn emit_lit(fd: i32, b: &[u8]) {
    // SAFETY: b is a 'static byte slice; write it verbatim to fd.
    unsafe { io::write(fd, b.as_ptr(), b.len()); }
}

unsafe fn write_msg(fd: i32, label: *const u8, sev: i32, text: *const u8, action: *const u8, tag: *const u8) {
    // SAFETY: all pointers are null or NUL-terminated; compose the glibc line
    // "label: sevstr: text\nTO FIX: action tag\n" skipping null components.
    unsafe {
        let mut first = true;
        if !label.is_null() { emit(fd, label); first = false; }
        let sevstr = builtin_sev(sev).map(|b| b.as_ptr()).unwrap_or_else(|| lookup_custom(sev));
        if sev != MM_NOSEV && !sevstr.is_null() {
            if !first { emit_lit(fd, b": "); } emit(fd, sevstr); first = false;
        }
        if !text.is_null() { if !first { emit_lit(fd, b": "); } emit(fd, text); first = false; }
        if !first { emit_lit(fd, b"\n"); }
        if !action.is_null() {
            emit_lit(fd, b"TO FIX: "); emit(fd, action);
            if !tag.is_null() { emit_lit(fd, b" "); emit(fd, tag); }
            emit_lit(fd, b"\n");
        }
    }
}

// # C: int fmtmsg(long classification, const char *label, int severity, const char *text, const char *action, const char *tag)
#[no_mangle]
pub unsafe extern "C" fn fmtmsg(classification: i64, label: *const u8, severity: i32, text: *const u8, action: *const u8, tag: *const u8) -> i32 {
    // SAFETY: label/text/action/tag are null or NUL-terminated C strings. Route
    // the formatted message to stderr (MM_PRINT) and/or console (MM_CONSOLE,
    // also fd 2 here), returning MM_OK/MM_NOMSG/MM_NOCON per which sinks fired.
    unsafe {
        let _ = MM_NULLSEV;
        let want_print = classification & MM_PRINT != 0;
        let want_con = classification & MM_CONSOLE != 0;
        // Both sinks resolve to fd 2 (no syslog/console device yet); the
        // unbuffered io::write path can't fail recoverably, so each requested
        // sink succeeds → MM_OK. (MM_NOMSG/MM_NOCON would signal a sink failure.)
        if want_print { write_msg(2, label, severity, text, action, tag); }
        if want_con { write_msg(2, label, severity, text, action, tag); }
        MM_OK
    }
}
