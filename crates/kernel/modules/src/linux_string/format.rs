extern crate alloc;

use alloc::vec::Vec;
use core::ffi::{c_void, VaList};
use core::ptr::copy_nonoverlapping;

use super::cstr::c_strlen;

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("snprintf",  snprintf  as *const () as usize),
        ("scnprintf", scnprintf as *const () as usize),
        ("sprintf",   sprintf   as *const () as usize),
        ("_printk",   printk    as *const () as usize),
        ("printk",    printk    as *const () as usize),
        ("__warn_printk", printk as *const () as usize),
        ("__dynamic_pr_debug", dynamic_pr_debug as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) unsafe extern "C" fn snprintf(buf: *mut u8, size: usize, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: snprintf's contract gives a NUL-terminated fmt with matching varargs and a buf writable for size bytes, which is format_to_buf's precondition.
    unsafe { format_to_buf(buf, size, fmt, &mut ap) as i32 }
}

pub(crate) unsafe extern "C" fn scnprintf(buf: *mut u8, size: usize, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: scnprintf's contract matches vscnprintf's: NUL-terminated fmt, one vararg per conversion, buf writable for size bytes.
    unsafe { vscnprintf(buf, size, fmt, &mut ap) }
}

pub(crate) unsafe extern "C" fn sprintf(buf: *mut u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: sprintf's contract obliges the caller to size buf for the whole result plus its terminator, which is what the usize::MAX bound expresses here.
    unsafe { format_to_buf(buf, usize::MAX, fmt, &mut ap) as i32 }
}

pub(crate) unsafe extern "C" fn printk(fmt: *const u8, mut ap: ...) -> i32 {
    let mut out = Vec::new();
    // SAFETY: printk's contract gives a NUL-terminated format plus one vararg per conversion, which format_c consumes in order; it null-checks fmt.
    unsafe { format_c(&mut out, fmt, &mut ap); }
    out.len() as i32
}

unsafe extern "C" fn dynamic_pr_debug(_desc: *mut c_void, fmt: *const u8, mut ap: ...) {
    let mut out = Vec::new();
    // SAFETY: dynamic debug callers pass a descriptor followed by printf-compatible varargs.
    unsafe { format_c(&mut out, fmt, &mut ap); }
}

// Precondition: `fmt` is null or a NUL-terminated format string whose conversions match
// the arguments in `ap`, and `buf` is null or writable for `size` bytes — sprintf passes
// `usize::MAX` for the unbounded case, where the caller instead owes room for the result.
unsafe fn format_to_buf(buf: *mut u8, size: usize, fmt: *const u8, ap: &mut VaList) -> usize {
    let mut out = Vec::new();
    // SAFETY: the snprintf/sprintf caller's contract makes fmt NUL-terminated and ap match its conversions; format_c null-checks fmt.
    unsafe { format_c(&mut out, fmt, ap); }
    if !buf.is_null() && size != 0 {
        let n = core::cmp::min(out.len(), size - 1);
        if n != 0 {
            // SAFETY: n is min(out.len(), size-1), so the copy reads inside the local Vec and writes inside buf's size bytes.
            unsafe { copy_nonoverlapping(out.as_ptr(), buf, n); }
        }
        // SAFETY: n <= size-1, so index n is the terminator slot inside buf's size writable bytes.
        unsafe { *buf.add(n) = 0; }
    }
    out.len()
}

pub(crate) unsafe fn vscnprintf(buf: *mut u8, size: usize, fmt: *const u8, ap: &mut VaList) -> i32 {
    // SAFETY: vscnprintf's callers pass format_to_buf's precondition through unchanged: NUL-terminated fmt, matching ap, buf writable for size bytes.
    let n = unsafe { format_to_buf(buf, size, fmt, ap) };
    core::cmp::min(n, size.saturating_sub(1)) as i32
}

// Precondition: `fmt` is null or a NUL-terminated format string, and `ap` carries one
// argument per conversion in `fmt` of the width that conversion's length modifier selects.
// Every index below either sits on a byte already proven non-NUL or is the terminator.
unsafe fn format_c(out: &mut Vec<u8>, fmt: *const u8, ap: &mut VaList) {
    if fmt.is_null() { return; }
    let mut i = 0usize;
    loop {
        // SAFETY: fmt was null-checked and i only advances past bytes proven non-NUL, so fmt+i is at worst the terminator.
        let b = unsafe { *fmt.add(i) };
        if b == 0 { break; }
        if b != b'%' { out.push(b); i += 1; continue; }
        i += 1;
        // SAFETY: fmt[i-1] was '%' so it was not the terminator, leaving fmt+i at worst the NUL.
        let mut c = unsafe { *fmt.add(i) };
        if c == b'%' { out.push(b'%'); i += 1; continue; }
        while matches!(c, b'0' | b'-' | b'+' | b' ' | b'#') {
            // SAFETY: c was a flag byte, so fmt[i] was not the terminator and fmt+i+1 is at worst the NUL.
            i += 1; c = unsafe { *fmt.add(i) };
        }
        while c.is_ascii_digit() {
            // SAFETY: c was a width digit, so fmt[i] was not the terminator and fmt+i+1 is at worst the NUL.
            i += 1; c = unsafe { *fmt.add(i) };
        }
        if c == b'.' {
            // SAFETY: c was '.', so fmt[i] was not the terminator and fmt+i+1 is at worst the NUL.
            i += 1; c = unsafe { *fmt.add(i) };
            while c.is_ascii_digit() {
                // SAFETY: c was a precision digit, so fmt[i] was not the terminator and fmt+i+1 is at worst the NUL.
                i += 1; c = unsafe { *fmt.add(i) };
            }
        }
        let mut long = false;
        if matches!(c, b'l' | b'z' | b't') {
            // SAFETY: c was an 'l'/'z'/'t' length modifier, so fmt[i] was not the terminator and fmt+i+1 is at worst the NUL.
            long = true; i += 1; c = unsafe { *fmt.add(i) };
            // SAFETY: c was the second 'l' of "ll", so fmt[i] was not the terminator and fmt+i+1 is at worst the NUL.
            if c == b'l' { i += 1; c = unsafe { *fmt.add(i) }; }
        }
        match c {
            b's' => {
                // SAFETY: "%s" obliges the caller to have pushed a pointer argument for this conversion.
                let p = unsafe { ap.next_arg::<*mut c_void>() as *const u8 };
                // SAFETY: "%s"'s argument is null or a NUL-terminated C string, which is push_cstr's precondition.
                unsafe { push_cstr(out, p); }
            }
            // SAFETY: "%c" obliges the caller to have pushed an int argument, the width next_arg reads here.
            b'c' => out.push(unsafe { ap.next_arg::<i32>() as u8 }),
            b'd' | b'i' => {
                // SAFETY: "%ld"/"%zd" oblige the caller to push a long and plain "%d"/"%i" an int; `long` records which modifier the format carried.
                let v = if long { unsafe { ap.next_arg::<i64>() } } else { unsafe { ap.next_arg::<i32>() as i64 } };
                push_i64(out, v);
            }
            b'u' | b'x' | b'X' => {
                // SAFETY: the 'l'/'z'/'t' modifier obliges the caller to push an unsigned long, its absence an unsigned int; `long` records which the format carried.
                let v = if long { unsafe { ap.next_arg::<u64>() } } else { unsafe { ap.next_arg::<u32>() as u64 } };
                push_u64(out, v, if c == b'u' { 10 } else { 16 }, c == b'X');
            }
            b'p' => {
                // SAFETY: "%p" obliges the caller to have pushed a pointer argument, which is only formatted as a number here and never dereferenced.
                let p = unsafe { ap.next_arg::<*mut c_void>() as usize };
                out.extend_from_slice(b"0x");
                push_u64(out, p as u64, 16, false);
            }
            _ => { out.push(b'%'); out.push(c); }
        }
        i += 1;
    }
}

// Precondition: `p` is null or a NUL-terminated C string.
unsafe fn push_cstr(out: &mut Vec<u8>, p: *const u8) {
    if p.is_null() { out.extend_from_slice(b"(null)"); return; }
    // SAFETY: p was null-checked and the caller's precondition makes it NUL-terminated, which is c_strlen's requirement.
    let len = unsafe { c_strlen(p) };
    for i in 0..len {
        // SAFETY: len is strlen(p), so every i < len names a byte before the terminator.
        out.push(unsafe { *p.add(i) });
    }
}

fn push_i64(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); push_u64(out, v.unsigned_abs(), 10, false); }
    else { push_u64(out, v as u64, 10, false); }
}

fn push_u64(out: &mut Vec<u8>, mut v: u64, base: u64, upper: bool) {
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    loop {
        i -= 1;
        let d = (v % base) as u8;
        buf[i] = if d < 10 { b'0' + d } else if upper { b'A' + d - 10 } else { b'a' + d - 10 };
        v /= base;
        if v == 0 { break; }
    }
    out.extend_from_slice(&buf[i..]);
}
