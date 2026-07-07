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
    ] { export(name, addr, false); }
}

pub(crate) unsafe extern "C" fn snprintf(buf: *mut u8, size: usize, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: caller supplies a printf format and matching varargs.
    unsafe { format_to_buf(buf, size, fmt, &mut ap) as i32 }
}

pub(crate) unsafe extern "C" fn scnprintf(buf: *mut u8, size: usize, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: caller supplies a printf format and matching varargs.
    unsafe { vscnprintf(buf, size, fmt, &mut ap) }
}

pub(crate) unsafe extern "C" fn sprintf(buf: *mut u8, fmt: *const u8, mut ap: ...) -> i32 {
    // SAFETY: caller supplies an unbounded writable buffer and matching varargs.
    unsafe { format_to_buf(buf, usize::MAX, fmt, &mut ap) as i32 }
}

pub(crate) unsafe extern "C" fn printk(fmt: *const u8, mut ap: ...) -> i32 {
    let mut out = Vec::new();
    unsafe { format_c(&mut out, fmt, &mut ap); }
    out.len() as i32
}

unsafe fn format_to_buf(buf: *mut u8, size: usize, fmt: *const u8, ap: &mut VaList) -> usize {
    let mut out = Vec::new();
    unsafe { format_c(&mut out, fmt, ap); }
    if !buf.is_null() && size != 0 {
        let n = core::cmp::min(out.len(), size - 1);
        if n != 0 {
            // SAFETY: buf has size writable bytes and out has n readable bytes.
            unsafe { copy_nonoverlapping(out.as_ptr(), buf, n); }
        }
        // SAFETY: size is non-zero and buf is writable for size bytes.
        unsafe { *buf.add(n) = 0; }
    }
    out.len()
}

pub(crate) unsafe fn vscnprintf(buf: *mut u8, size: usize, fmt: *const u8, ap: &mut VaList) -> i32 {
    // SAFETY: caller supplies a printf format and matching varargs.
    let n = unsafe { format_to_buf(buf, size, fmt, ap) };
    core::cmp::min(n, size.saturating_sub(1)) as i32
}

unsafe fn format_c(out: &mut Vec<u8>, fmt: *const u8, ap: &mut VaList) {
    if fmt.is_null() { return; }
    let mut i = 0usize;
    loop {
        // SAFETY: fmt is a NUL-terminated format string.
        let b = unsafe { *fmt.add(i) };
        if b == 0 { break; }
        if b != b'%' { out.push(b); i += 1; continue; }
        i += 1;
        let mut c = unsafe { *fmt.add(i) };
        if c == b'%' { out.push(b'%'); i += 1; continue; }
        while matches!(c, b'0' | b'-' | b'+' | b' ' | b'#') {
            i += 1; c = unsafe { *fmt.add(i) };
        }
        while c.is_ascii_digit() {
            i += 1; c = unsafe { *fmt.add(i) };
        }
        if c == b'.' {
            i += 1; c = unsafe { *fmt.add(i) };
            while c.is_ascii_digit() {
                i += 1; c = unsafe { *fmt.add(i) };
            }
        }
        let mut long = false;
        if matches!(c, b'l' | b'z' | b't') {
            long = true; i += 1; c = unsafe { *fmt.add(i) };
            if c == b'l' { i += 1; c = unsafe { *fmt.add(i) }; }
        }
        match c {
            b's' => {
                let p = unsafe { ap.next_arg::<*mut c_void>() as *const u8 };
                push_cstr(out, p);
            }
            b'c' => out.push(unsafe { ap.next_arg::<i32>() as u8 }),
            b'd' | b'i' => {
                let v = if long { unsafe { ap.next_arg::<i64>() } } else { unsafe { ap.next_arg::<i32>() as i64 } };
                push_i64(out, v);
            }
            b'u' | b'x' | b'X' => {
                let v = if long { unsafe { ap.next_arg::<u64>() } } else { unsafe { ap.next_arg::<u32>() as u64 } };
                push_u64(out, v, if c == b'u' { 10 } else { 16 }, c == b'X');
            }
            b'p' => {
                let p = unsafe { ap.next_arg::<*mut c_void>() as usize };
                out.extend_from_slice(b"0x");
                push_u64(out, p as u64, 16, false);
            }
            _ => { out.push(b'%'); out.push(c); }
        }
        i += 1;
    }
}

fn push_cstr(out: &mut Vec<u8>, p: *const u8) {
    if p.is_null() { out.extend_from_slice(b"(null)"); return; }
    let len = unsafe { c_strlen(p) };
    for i in 0..len {
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
