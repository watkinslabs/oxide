// <argz.h> (docs/59§6) — GNU "argz vectors": a malloc'd buffer holding a run of
// NUL-terminated strings, with a separate length. Used for argument/env lists.
// error_t return = 0 on success, ENOMEM on allocation failure. C ABI only.
#![cfg(feature = "freestanding")]
use crate::malloc::heap;
use crate::string::len::strlen_impl;

const ENOMEM: i32 = 12;

// grow *argz to new_len, copying the old contents; updates *argz. false=OOM.
unsafe fn resize(argz: *mut *mut u8, old: usize, new_len: usize) -> bool {
    // SAFETY: *argz is null (old==0) or a heap block of `old` bytes; realloc to
    // new_len preserving the prefix.
    unsafe {
        let p = heap::realloc(*argz, new_len);
        if p.is_null() && new_len != 0 { return false; }
        let _ = old;
        *argz = p;
        true
    }
}

// # C: error_t argz_add(char **argz, size_t *len, const char *str)
#[no_mangle]
pub unsafe extern "C" fn argz_add(argz: *mut *mut u8, len: *mut usize, str: *const u8) -> i32 {
    // SAFETY: argz/len are a valid argz pair; str is NUL-terminated. Append
    // str + its NUL to the buffer.
    unsafe {
        let sl = strlen_impl(str) + 1;
        let old = *len;
        if !resize(argz, old, old + sl) { return ENOMEM; }
        core::ptr::copy_nonoverlapping(str, (*argz).add(old), sl);
        *len = old + sl;
        0
    }
}

// # C: error_t argz_append(char **argz, size_t *len, const char *buf, size_t buflen)
#[no_mangle]
pub unsafe extern "C" fn argz_append(argz: *mut *mut u8, len: *mut usize, buf: *const u8, buflen: usize) -> i32 {
    // SAFETY: argz/len valid; buf is a readable argz fragment of buflen bytes.
    unsafe {
        let old = *len;
        if !resize(argz, old, old + buflen) { return ENOMEM; }
        core::ptr::copy_nonoverlapping(buf, (*argz).add(old), buflen);
        *len = old + buflen;
        0
    }
}

// # C: error_t argz_create_sep(const char *str, int sep, char **argz, size_t *len)
#[no_mangle]
pub unsafe extern "C" fn argz_create_sep(s: *const u8, sep: i32, argz: *mut *mut u8, len: *mut usize) -> i32 {
    // SAFETY: s is NUL-terminated; split on `sep` into argz entries, dropping
    // empty fields (glibc behaviour). argz/len receive a fresh allocation.
    unsafe {
        *argz = core::ptr::null_mut();
        *len = 0;
        let sepb = sep as u8;
        let total = strlen_impl(s);
        let mut i = 0;
        while i < total {
            while i < total && *s.add(i) == sepb { i += 1; }
            let start = i;
            while i < total && *s.add(i) != sepb { i += 1; }
            if i > start {
                let old = *len;
                let seg = i - start;
                if !resize(argz, old, old + seg + 1) { return ENOMEM; }
                core::ptr::copy_nonoverlapping(s.add(start), (*argz).add(old), seg);
                *(*argz).add(old + seg) = 0;
                *len = old + seg + 1;
            }
        }
        0
    }
}

// # C: error_t argz_create(char *const argv[], char **argz, size_t *len)
#[no_mangle]
pub unsafe extern "C" fn argz_create(argv: *const *const u8, argz: *mut *mut u8, len: *mut usize) -> i32 {
    // SAFETY: argv is a NULL-terminated array of NUL-terminated strings.
    unsafe {
        *argz = core::ptr::null_mut();
        *len = 0;
        let mut i = 0;
        while !(*argv.add(i)).is_null() {
            let r = argz_add(argz, len, *argv.add(i));
            if r != 0 { return r; }
            i += 1;
        }
        0
    }
}

// # C: size_t argz_count(const char *argz, size_t len)
#[no_mangle]
pub unsafe extern "C" fn argz_count(argz: *const u8, len: usize) -> usize {
    // SAFETY: argz is a buffer of `len` bytes; count the NUL terminators.
    unsafe {
        let mut n = 0;
        let mut i = 0;
        while i < len { if *argz.add(i) == 0 { n += 1; } i += 1; }
        n
    }
}
// # C: size_t __argz_count(const char *argz, size_t len)
#[no_mangle]
pub unsafe extern "C" fn __argz_count(argz: *const u8, len: usize) -> usize {
    // SAFETY: internal alias has the same argz buffer contract as argz_count.
    unsafe { argz_count(argz, len) }
}

// # C: void argz_extract(const char *argz, size_t len, char **argv)
#[no_mangle]
pub unsafe extern "C" fn argz_extract(argz: *const u8, len: usize, argv: *mut *mut u8) {
    // SAFETY: argv has room for argz_count(argz,len)+1 pointers; fill it with a
    // pointer to each entry, terminated by NULL.
    unsafe {
        let mut k = 0;
        let mut i = 0;
        while i < len {
            *argv.add(k) = argz.add(i) as *mut u8;
            k += 1;
            while i < len && *argz.add(i) != 0 { i += 1; }
            i += 1; // skip the NUL
        }
        *argv.add(k) = core::ptr::null_mut();
    }
}

// # C: void argz_stringify(char *argz, size_t len, int sep)
#[no_mangle]
pub unsafe extern "C" fn argz_stringify(argz: *mut u8, len: usize, sep: i32) {
    // SAFETY: argz is `len` bytes; replace the inter-string NULs (all but the
    // last) with `sep`, yielding a printable string.
    unsafe {
        if len == 0 { return; }
        let mut i = 0;
        while i < len - 1 { if *argz.add(i) == 0 { *argz.add(i) = sep as u8; } i += 1; }
    }
}
// # C: void __argz_stringify(char *argz, size_t len, int sep)
#[no_mangle]
pub unsafe extern "C" fn __argz_stringify(argz: *mut u8, len: usize, sep: i32) {
    // SAFETY: internal alias has the same mutable argz contract as argz_stringify.
    unsafe { argz_stringify(argz, len, sep) }
}

// # C: char *argz_next(const char *argz, size_t len, const char *entry)
#[no_mangle]
pub unsafe extern "C" fn argz_next(argz: *const u8, len: usize, entry: *const u8) -> *mut u8 {
    // SAFETY: argz is `len` bytes; entry is null (→ first) or points at a
    // current entry within argz. Returns the next entry or null at the end.
    unsafe {
        if entry.is_null() { return if len > 0 { argz as *mut u8 } else { core::ptr::null_mut() }; }
        let next = entry.add(strlen_impl(entry) + 1);
        let end = argz.add(len);
        if next < end { next as *mut u8 } else { core::ptr::null_mut() }
    }
}
// # C: char *__argz_next(const char *argz, size_t len, const char *entry)
#[no_mangle]
pub unsafe extern "C" fn __argz_next(argz: *const u8, len: usize, entry: *const u8) -> *mut u8 {
    // SAFETY: internal alias has the same traversal contract as argz_next.
    unsafe { argz_next(argz, len, entry) }
}

// # C: error_t argz_add_sep(char **argz, size_t *len, const char *str, int delim)
#[no_mangle]
pub unsafe extern "C" fn argz_add_sep(argz: *mut *mut u8, len: *mut usize, s: *const u8, delim: i32) -> i32 {
    // SAFETY: argz/len a valid pair; s NUL-terminated. Split s on `delim` and
    // append each (non-empty) field as a new argz entry.
    unsafe {
        let d = delim as u8;
        let total = strlen_impl(s);
        let mut i = 0;
        while i < total {
            while i < total && *s.add(i) == d { i += 1; }
            let start = i;
            while i < total && *s.add(i) != d { i += 1; }
            if i > start {
                let old = *len;
                let seg = i - start;
                if !resize(argz, old, old + seg + 1) { return ENOMEM; }
                core::ptr::copy_nonoverlapping(s.add(start), (*argz).add(old), seg);
                *(*argz).add(old + seg) = 0;
                *len = old + seg + 1;
            }
        }
        0
    }
}

// # C: void argz_delete(char **argz, size_t *len, char *entry)
#[no_mangle]
pub unsafe extern "C" fn argz_delete(argz: *mut *mut u8, len: *mut usize, entry: *mut u8) {
    // SAFETY: argz/len a valid pair; entry is null (no-op) or points at an
    // entry within the buffer. Splice out the entry + its NUL and shrink.
    unsafe {
        if entry.is_null() { return; }
        let base = *argz;
        let off = (entry as usize) - (base as usize);
        let elen = strlen_impl(entry) + 1;
        let old = *len;
        let tail = old - off - elen;
        core::ptr::copy(entry.add(elen), entry, tail);
        let nl = old - elen;
        if nl == 0 { heap::free(base); *argz = core::ptr::null_mut(); *len = 0; return; }
        let p = heap::realloc(base, nl);
        if !p.is_null() { *argz = p; }
        *len = nl;
    }
}

// # C: error_t argz_insert(char **argz, size_t *len, char *before, const char *entry)
#[no_mangle]
pub unsafe extern "C" fn argz_insert(argz: *mut *mut u8, len: *mut usize, before: *mut u8, entry: *const u8) -> i32 {
    // SAFETY: argz/len a valid pair; before is null (append) or points at an
    // entry within the buffer; entry NUL-terminated. Grow + open a gap + copy.
    unsafe {
        let elen = strlen_impl(entry) + 1;
        let old = *len;
        if before.is_null() { return argz_add(argz, len, entry); }
        let off = (before as usize) - (*argz as usize);
        if !resize(argz, old, old + elen) { return ENOMEM; }
        let base = *argz;
        core::ptr::copy(base.add(off), base.add(off + elen), old - off);
        core::ptr::copy_nonoverlapping(entry, base.add(off), elen);
        *len = old + elen;
        0
    }
}

// # C: error_t argz_replace(char **argz, size_t *len, const char *str, const char *with, unsigned *replace_count)
#[no_mangle]
pub unsafe extern "C" fn argz_replace(argz: *mut *mut u8, len: *mut usize, str: *const u8, with: *const u8, replace_count: *mut u32) -> i32 {
    // SAFETY: argz/len a valid pair; str/with NUL-terminated. Replace every
    // entry equal to `str` with `with`, rebuilding the buffer; report count.
    unsafe {
        use crate::string::cmp::strcmp_impl;
        let mut nz: *mut u8 = core::ptr::null_mut();
        let mut nl = 0usize;
        let mut count = 0u32;
        let mut e = argz_next(*argz, *len, core::ptr::null());
        while !e.is_null() {
            let rep = strcmp_impl(e, str) == 0;
            let src = if rep { count += 1; with } else { e as *const u8 };
            if argz_add(&mut nz, &mut nl, src) != 0 { heap::free(nz); return ENOMEM; }
            e = argz_next(*argz, *len, e);
        }
        heap::free(*argz);
        *argz = nz;
        *len = nl;
        if !replace_count.is_null() { *replace_count += count; }
        0
    }
}
