// GNU/BSD string extras (docs/59§6 G4): stpcpy/stpncpy/mempcpy/strsep/
// memmem/memrchr. Scalar reference impls; pure inner hosted-tested, C ABI
// freestanding.
#![allow(clippy::missing_safety_doc)]

/// # C: char *stpcpy(char *dst, const char *src) — copy incl NUL, return &NUL
pub(crate) unsafe fn stpcpy_impl(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: dst has room for strlen(src)+1; src 0-terminated.
    unsafe { let mut i = 0; loop { let c = *src.add(i); *dst.add(i) = c; if c == 0 { return dst.add(i); } i += 1; } }
}
/// # C: char *stpncpy(char *dst, const char *src, size_t n)
pub(crate) unsafe fn stpncpy_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: dst writable for n; src 0-terminated. Copies up to a NUL, then
    // NUL-pads to n; returns the address after the last non-pad byte.
    unsafe {
        let mut i = 0;
        while i < n && *src.add(i) != 0 { *dst.add(i) = *src.add(i); i += 1; }
        let end = dst.add(i);
        while i < n { *dst.add(i) = 0; i += 1; }
        end
    }
}
/// # C: void *mempcpy(void *dst, const void *src, size_t n) — memcpy → dst+n
pub(crate) unsafe fn mempcpy_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: dst and src are each valid for n non-overlapping bytes (memcpy).
    unsafe { core::ptr::copy_nonoverlapping(src, dst, n); dst.add(n) }
}
/// # C: void *memrchr(const void *s, int c, size_t n) — last c in s[..n]
pub(crate) unsafe fn memrchr_impl(s: *const u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: s is readable for n bytes; scans backward for the byte value c.
    unsafe {
        let mut i = n;
        while i > 0 { i -= 1; if *s.add(i) == c as u8 { return s.add(i) as *mut u8; } }
        core::ptr::null_mut()
    }
}
/// # C: void *memccpy(void *dst, const void *src, int c, size_t n) — copy until c
pub(crate) unsafe fn memccpy_impl(dst: *mut u8, src: *const u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: dst and src are valid for n bytes; copy bytes one at a time,
    // stopping right after the first byte equal to c is written. Returns the
    // address just past that byte in dst, or null if c is absent in src[..n].
    unsafe {
        let cb = c as u8;
        let mut i = 0;
        while i < n {
            *dst.add(i) = *src.add(i);
            if *src.add(i) == cb { return dst.add(i + 1); }
            i += 1;
        }
        core::ptr::null_mut()
    }
}
/// # C: void *memmem(haystack, hl, needle, nl) — first needle in haystack
pub(crate) unsafe fn memmem_impl(h: *const u8, hl: usize, ne: *const u8, nl: usize) -> *mut u8 {
    // SAFETY: h is readable for hl bytes and ne for nl bytes; substring scan.
    unsafe {
        if nl == 0 { return h as *mut u8; }
        if nl > hl { return core::ptr::null_mut(); }
        let hs = core::slice::from_raw_parts(h, hl);
        let ns = core::slice::from_raw_parts(ne, nl);
        let mut i = 0;
        while i + nl <= hl { if &hs[i..i + nl] == ns { return h.add(i) as *mut u8; } i += 1; }
        core::ptr::null_mut()
    }
}

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    // # C: char *stpcpy(char *, const char *)
    // SAFETY: d has room for strlen(s)+1; s is a NUL-terminated C string.
    #[no_mangle] pub unsafe extern "C" fn stpcpy(d: *mut u8, s: *const u8) -> *mut u8 { unsafe { stpcpy_impl(d, s) } }
    // # C: char *__stpcpy(char *, const char *)
    // SAFETY: __stpcpy has the same destination/source contract as stpcpy.
    #[no_mangle] pub unsafe extern "C" fn __stpcpy(d: *mut u8, s: *const u8) -> *mut u8 { unsafe { stpcpy(d, s) } }
    // # C: char *stpncpy(char *, const char *, size_t)
    // SAFETY: d is writable for n bytes; s is a NUL-terminated C string.
    #[no_mangle] pub unsafe extern "C" fn stpncpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 { unsafe { stpncpy_impl(d, s, n) } }
    // # C: char *__stpncpy(char *, const char *, size_t)
    // SAFETY: __stpncpy has the same destination/source contract as stpncpy.
    #[no_mangle] pub unsafe extern "C" fn __stpncpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 { unsafe { stpncpy(d, s, n) } }
    // # C: void *mempcpy(void *, const void *, size_t)
    // SAFETY: d and s are valid for n non-overlapping bytes per memcpy.
    #[no_mangle] pub unsafe extern "C" fn mempcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 { unsafe { mempcpy_impl(d, s, n) } }
    // # C: void *__mempcpy(void *, const void *, size_t)
    // SAFETY: __mempcpy has the same non-overlap buffer contract as mempcpy.
    #[no_mangle] pub unsafe extern "C" fn __mempcpy(d: *mut u8, s: *const u8, n: usize) -> *mut u8 { unsafe { mempcpy(d, s, n) } }
    // # C: void *memrchr(const void *, int, size_t)
    // SAFETY: s is readable for n bytes; scans backward for the byte c.
    #[no_mangle] pub unsafe extern "C" fn memrchr(s: *const u8, c: i32, n: usize) -> *mut u8 { unsafe { memrchr_impl(s, c, n) } }
    // # C: void *memccpy(void *, const void *, int, size_t)
    // SAFETY: dst and src are valid for n bytes; copies until byte c is written.
    #[no_mangle] pub unsafe extern "C" fn memccpy(d: *mut u8, s: *const u8, c: i32, n: usize) -> *mut u8 { unsafe { memccpy_impl(d, s, c, n) } }
    // # C: void *memmem(const void *, size_t, const void *, size_t)
    // SAFETY: h is readable for hl bytes and ne for nl bytes (substring search).
    #[no_mangle] pub unsafe extern "C" fn memmem(h: *const u8, hl: usize, ne: *const u8, nl: usize) -> *mut u8 { unsafe { memmem_impl(h, hl, ne, nl) } }
    // # C: void *memfrob(void *s, size_t n) — XOR each byte with 42 (GNU)
    #[no_mangle]
    pub unsafe extern "C" fn memfrob(s: *mut u8, n: usize) -> *mut u8 {
        // SAFETY: s is writable for n bytes; XOR each with the constant 42 (the
        // GNU obfuscation; applying it twice restores the original).
        unsafe { let mut i = 0; while i < n { *s.add(i) ^= 42; i += 1; } s }
    }

    // # C: char *basename(const char *path) — GNU <string.h> form: pointer to
    // the part after the last '/', or the whole string if none. Does NOT modify
    // the buffer and never strips trailing slashes (that is __xpg_basename).
    #[no_mangle]
    pub unsafe extern "C" fn basename(path: *const u8) -> *mut u8 {
        // SAFETY: path null (→path) or a NUL-terminated string; returns a pointer
        // just past the last '/' within it, scanning forward to the terminator.
        unsafe {
            if path.is_null() { return path as *mut u8; }
            let mut last = path;
            let mut p = path;
            loop {
                let c = *p;
                p = p.add(1);
                if c == b'/' { last = p; }
                if c == 0 { return last as *mut u8; }
            }
        }
    }

    // # C: char *strfry(char *string) — randomly permute string in place (GNU)
    #[no_mangle]
    pub unsafe extern "C" fn strfry(string: *mut u8) -> *mut u8 {
        // SAFETY: string is a NUL-terminated mutable buffer; Fisher-Yates shuffle
        // over its bytes via the process random() source, in place (no realloc).
        unsafe {
            let mut n = 0usize;
            while *string.add(n) != 0 { n += 1; }
            let mut i = 0usize;
            while i + 1 < n {
                let span = (n - i) as u64;
                let r = crate::stdlib::rand48::random() as u64;
                let j = i + (r % span) as usize;
                let t = *string.add(i); *string.add(i) = *string.add(j); *string.add(j) = t;
                i += 1;
            }
            string
        }
    }

    // # C: char *strsep(char **stringp, const char *delim)
    #[no_mangle]
    pub unsafe extern "C" fn strsep(stringp: *mut *mut u8, delim: *const u8) -> *mut u8 {
        // SAFETY: *stringp is null or a NUL-terminated mutable string; delim a
        // NUL-terminated set. Writes a NUL at the first delimiter, advances *stringp.
        unsafe {
            let s = *stringp;
            if s.is_null() { return core::ptr::null_mut(); }
            let mut p = s;
            loop {
                let c = *p;
                if c == 0 { *stringp = core::ptr::null_mut(); return s; }
                let mut d = delim;
                while *d != 0 { if *d == c { *p = 0; *stringp = p.add(1); return s; } d = d.add(1); }
                p = p.add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extras() {
        // SAFETY: all buffers below are valid for the bytes touched.
        unsafe {
            let mut b = [0u8; 8];
            let e = stpcpy_impl(b.as_mut_ptr(), b"hi\0".as_ptr());
            assert_eq!(e as usize - b.as_ptr() as usize, 2);
            let mut d = [9u8; 8];
            let p = mempcpy_impl(d.as_mut_ptr(), b"abc".as_ptr(), 3);
            assert_eq!(p as usize - d.as_ptr() as usize, 3);
            assert_eq!(memrchr_impl(b"a/b/c".as_ptr(), b'/' as i32, 5) as usize - b"a/b/c".as_ptr() as usize, 3);
            assert_eq!(memmem_impl(b"hello".as_ptr(), 5, b"ll".as_ptr(), 2) as usize - b"hello".as_ptr() as usize, 2);
            assert!(memmem_impl(b"hello".as_ptr(), 5, b"zz".as_ptr(), 2).is_null());
            let mut m = [0u8; 8];
            let r = memccpy_impl(m.as_mut_ptr(), b"ab:cd".as_ptr(), b':' as i32, 8);
            assert_eq!(r as usize - m.as_ptr() as usize, 3); // just past ':'
            assert_eq!(&m[..3], b"ab:");
            assert!(memccpy_impl(m.as_mut_ptr(), b"abcd".as_ptr(), b':' as i32, 4).is_null());
        }
    }
}
