use core::ffi::c_void;
use core::ptr::{copy_nonoverlapping, write_bytes};

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("memcpy",         memcpy         as *const () as usize),
        ("memset",         memset         as *const () as usize),
        ("memcmp",         memcmp         as *const () as usize),
        ("memcpy_and_pad", memcpy_and_pad as *const () as usize),
    ] { export(name, addr, false); }
}

pub(crate) unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n != 0 && !dst.is_null() && !src.is_null() {
        // SAFETY: Linux memcpy callers provide non-overlapping valid byte ranges.
        unsafe { copy_nonoverlapping(src as *const u8, dst as *mut u8, n); }
    }
    dst
}

pub(crate) unsafe extern "C" fn memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    if n != 0 && !dst.is_null() {
        // SAFETY: Linux memset callers provide a valid writable byte range.
        unsafe { write_bytes(dst as *mut u8, c as u8, n); }
    }
    dst
}

pub(crate) unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: Linux memcmp callers provide valid readable byte ranges.
        let av = unsafe { *(a as *const u8).add(i) };
        // SAFETY: Linux memcmp callers provide valid readable byte ranges.
        let bv = unsafe { *(b as *const u8).add(i) };
        if av != bv { return av as i32 - bv as i32; }
    }
    0
}

pub(crate) unsafe extern "C" fn memcpy_and_pad(
    dst: *mut c_void,
    dst_len: usize,
    src: *const c_void,
    count: usize,
    pad: i32,
) -> *mut c_void {
    if dst.is_null() { return dst; }
    let n = core::cmp::min(dst_len, count);
    if n != 0 && !src.is_null() {
        // SAFETY: caller supplies dst_len writable bytes and count readable source bytes.
        unsafe { copy_nonoverlapping(src as *const u8, dst as *mut u8, n); }
    }
    if dst_len > n {
        // SAFETY: tail is inside the caller-provided destination byte range.
        unsafe { write_bytes((dst as *mut u8).add(n), pad as u8, dst_len - n); }
    }
    dst
}
