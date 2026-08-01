use super::types::DEVICE_NAME_LEN;
use core::ffi::{c_char, c_void, VaList};
use core::ptr::copy_nonoverlapping;

const DECIMAL_BASE: u64 = 10;
const HEX_BASE: u64 = 16;

pub(super) unsafe fn copy_cstr(dst: *mut c_char, cap: usize, src: *const c_char) {
    if cap == 0 { return; }
    let mut i = 0usize;
    // SAFETY: src is a caller-owned C string and dst covers cap bytes.
    unsafe {
        while i + 1 < cap && *src.add(i) != 0 {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
        *dst.add(i) = 0;
    }
}

pub(super) unsafe fn format_into(dst: *mut c_char, cap: usize, fmt: *const c_char, ap: &mut VaList) {
    if cap == 0 { return; }
    let mut out = [0u8; DEVICE_NAME_LEN];
    let mut n = 0usize;
    // SAFETY: fmt is a NUL-terminated C format string and ap matches it.
    unsafe { format_bytes(&mut out, &mut n, fmt, ap); }
    let len = n.min(cap - 1);
    // SAFETY: dst covers cap bytes and out has at least len bytes.
    unsafe {
        copy_nonoverlapping(out.as_ptr() as *const c_char, dst, len);
        *dst.add(len) = 0;
    }
}

unsafe fn format_bytes(out: &mut [u8], n: &mut usize, fmt: *const c_char, ap: &mut VaList) {
    if fmt.is_null() { return; }
    let mut i = 0usize;
    loop {
        // SAFETY: fmt is a NUL-terminated C string.
        let b = unsafe { *fmt.add(i) as u8 };
        if b == 0 { break; }
        if b != b'%' { push_byte(out, n, b); i += 1; continue; }
        i += 1;
        // SAFETY: conversion byte is within the C string or NUL.
        let mut c = unsafe { *fmt.add(i) as u8 };
        if c == b'%' { push_byte(out, n, b'%'); i += 1; continue; }
        let mut long = false;
        while matches!(c, b'l' | b'z') {
            long = true;
            i += 1;
            // SAFETY: length modifier consumed; read next byte from the same C string.
            c = unsafe { *fmt.add(i) as u8 };
        }
        match c {
            b's' => {
                // SAFETY: the C varargs contract makes the argument matching a %s conversion a pointer, so reading it as pointer-sized is the promoted type the caller pushed.
                let p = unsafe { ap.next_arg::<*mut c_void>() as *const c_char };
                push_cstr(out, n, p);
            }
            b'd' | b'i' => {
                let v = if long {
                    // SAFETY: vararg type follows signed long conversion.
                    unsafe { ap.next_arg::<i64>() }
                } else {
                    // SAFETY: vararg type follows signed int conversion.
                    unsafe { ap.next_arg::<i32>() as i64 }
                };
                push_i64(out, n, v);
            }
            b'u' => {
                let v = if long {
                    // SAFETY: vararg type follows unsigned long conversion.
                    unsafe { ap.next_arg::<u64>() }
                } else {
                    // SAFETY: vararg type follows unsigned int conversion.
                    unsafe { ap.next_arg::<u32>() as u64 }
                };
                push_u64(out, n, v, DECIMAL_BASE);
            }
            b'x' | b'X' => {
                let v = if long {
                    // SAFETY: vararg type follows unsigned long conversion.
                    unsafe { ap.next_arg::<u64>() }
                } else {
                    // SAFETY: vararg type follows unsigned int conversion.
                    unsafe { ap.next_arg::<u32>() as u64 }
                };
                push_u64(out, n, v, HEX_BASE);
            }
            _ => push_byte(out, n, c),
        }
        if c == 0 { break; }
        i += 1;
    }
}

fn push_byte(out: &mut [u8], n: &mut usize, b: u8) {
    if *n < out.len() { out[*n] = b; }
    *n += 1;
}

fn push_cstr(out: &mut [u8], n: &mut usize, s: *const c_char) {
    if s.is_null() { return; }
    let mut i = 0usize;
    // SAFETY: s is a NUL-terminated C string.
    unsafe {
        while *s.add(i) != 0 {
            push_byte(out, n, *s.add(i) as u8);
            i += 1;
        }
    }
}

fn push_i64(out: &mut [u8], n: &mut usize, v: i64) {
    if v < 0 {
        push_byte(out, n, b'-');
        push_u64(out, n, v.unsigned_abs(), DECIMAL_BASE);
    } else { push_u64(out, n, v as u64, DECIMAL_BASE); }
}

fn push_u64(out: &mut [u8], n: &mut usize, mut v: u64, base: u64) {
    let mut tmp = [0u8; u64::BITS as usize];
    let mut len = 0usize;
    loop {
        let digit = (v % base) as u8;
        tmp[len] = if digit < DECIMAL_BASE as u8 { b'0' + digit } else { b'a' + digit - DECIMAL_BASE as u8 };
        len += 1;
        v /= base;
        if v == 0 { break; }
    }
    while len != 0 {
        len -= 1;
        push_byte(out, n, tmp[len]);
    }
}
