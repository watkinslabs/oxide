// <envz.h> (docs/59§6 G8). An envz is an argz (NUL-separated run of strings)
// whose entries are "NAME" or "NAME=VALUE". These helpers index by NAME up to
// the '=' separator. error_t return = 0 / ENOMEM. C ABI only.
#![cfg(feature = "freestanding")]
use crate::malloc::heap;
use crate::posix::argz::{argz_add, argz_append, argz_delete, argz_next};
use crate::string::len::strlen_impl;

const ENOMEM: i32 = 12;

// Length of the NAME part of an entry (up to '=' or NUL).
unsafe fn name_len(e: *const u8) -> usize {
    // SAFETY: e is a NUL-terminated entry; scan to '=' or terminator.
    unsafe {
        let mut i = 0;
        while *e.add(i) != 0 && *e.add(i) != b'=' { i += 1; }
        i
    }
}

// True if entry e has NAME == name[..nlen] exactly.
unsafe fn name_eq(e: *const u8, name: *const u8, nlen: usize) -> bool {
    // SAFETY: e/name readable; compares the NAME segment length + bytes.
    unsafe {
        if name_len(e) != nlen { return false; }
        (0..nlen).all(|k| *e.add(k) == *name.add(k))
    }
}

// # C: char *envz_entry(const char *envz, size_t len, const char *name)
#[no_mangle]
pub unsafe extern "C" fn envz_entry(envz: *const u8, len: usize, name: *const u8) -> *mut u8 {
    // SAFETY: envz is `len` bytes of argz; name NUL-terminated. Returns the
    // first entry whose NAME matches, or null.
    unsafe {
        let nlen = strlen_impl(name);
        let mut e = argz_next(envz, len, core::ptr::null());
        while !e.is_null() {
            if name_eq(e, name, nlen) { return e; }
            e = argz_next(envz, len, e);
        }
        core::ptr::null_mut()
    }
}

// # C: char *envz_get(const char *envz, size_t len, const char *name)
#[no_mangle]
pub unsafe extern "C" fn envz_get(envz: *const u8, len: usize, name: *const u8) -> *mut u8 {
    // SAFETY: envz/name as above. Returns a pointer to VALUE (after '='), or
    // null if the entry is absent or has no '=' (a "null" entry).
    unsafe {
        let e = envz_entry(envz, len, name);
        if e.is_null() { return core::ptr::null_mut(); }
        let nl = name_len(e);
        if *e.add(nl) == b'=' { e.add(nl + 1) } else { core::ptr::null_mut() }
    }
}

// # C: error_t envz_add(char **envz, size_t *len, const char *name, const char *value)
#[no_mangle]
pub unsafe extern "C" fn envz_add(envz: *mut *mut u8, len: *mut usize, name: *const u8, value: *const u8) -> i32 {
    // SAFETY: envz/len a valid pair; name NUL-terminated, value null or
    // NUL-terminated. Remove any existing entry then append "NAME[=VALUE]".
    unsafe {
        let existing = envz_entry(*envz, *len, name);
        if !existing.is_null() { argz_delete(envz, len, existing); }
        if value.is_null() { return argz_add(envz, len, name); }
        // build "NAME=VALUE\0" then argz_append it.
        let nl = strlen_impl(name);
        let vl = strlen_impl(value);
        let total = nl + 1 + vl + 1;
        let buf = heap::malloc(total);
        if buf.is_null() { return ENOMEM; }
        core::ptr::copy_nonoverlapping(name, buf, nl);
        *buf.add(nl) = b'=';
        core::ptr::copy_nonoverlapping(value, buf.add(nl + 1), vl);
        *buf.add(total - 1) = 0;
        let r = argz_append(envz, len, buf, total);
        heap::free(buf);
        r
    }
}

// # C: error_t envz_merge(char **envz, size_t *len, const char *envz2, size_t envz2_len, int override)
#[no_mangle]
pub unsafe extern "C" fn envz_merge(envz: *mut *mut u8, len: *mut usize, envz2: *const u8, envz2_len: usize, ovr: i32) -> i32 {
    // SAFETY: envz/len a valid pair; envz2 is `envz2_len` bytes of argz. Fold
    // each entry of envz2 into envz; with `ovr`, envz2 supersedes.
    unsafe {
        let mut e = argz_next(envz2, envz2_len, core::ptr::null());
        while !e.is_null() {
            let nl = name_len(e);
            // does envz already have this NAME?
            let cur = {
                // need a temporary NUL-terminated NAME to query
                let tmp = heap::malloc(nl + 1);
                if tmp.is_null() { return ENOMEM; }
                core::ptr::copy_nonoverlapping(e, tmp, nl);
                *tmp.add(nl) = 0;
                let c = envz_entry(*envz, *len, tmp);
                heap::free(tmp);
                c
            };
            if cur.is_null() || ovr != 0 {
                if !cur.is_null() { argz_delete(envz, len, cur); }
                let elen = strlen_impl(e) + 1;
                if argz_append(envz, len, e, elen) != 0 { return ENOMEM; }
            }
            e = argz_next(envz2, envz2_len, e);
        }
        0
    }
}

// # C: void envz_remove(char **envz, size_t *len, const char *name)
#[no_mangle]
pub unsafe extern "C" fn envz_remove(envz: *mut *mut u8, len: *mut usize, name: *const u8) {
    // SAFETY: envz/len a valid pair; name NUL-terminated. Delete the matching
    // entry if present.
    unsafe {
        let e = envz_entry(*envz, *len, name);
        if !e.is_null() { argz_delete(envz, len, e); }
    }
}

// # C: void envz_strip(char **envz, size_t *len)
#[no_mangle]
pub unsafe extern "C" fn envz_strip(envz: *mut *mut u8, len: *mut usize) {
    // SAFETY: envz/len a valid pair. Remove every "null" entry (NAME with no
    // '=' value), iterating until none remain.
    unsafe {
        loop {
            let mut found: *mut u8 = core::ptr::null_mut();
            let mut e = argz_next(*envz, *len, core::ptr::null());
            while !e.is_null() {
                if *e.add(name_len(e)) == 0 { found = e; break; }
                e = argz_next(*envz, *len, e);
            }
            if found.is_null() { return; }
            argz_delete(envz, len, found);
        }
    }
}
