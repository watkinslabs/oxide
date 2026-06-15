// Wide-string functions (docs/59§6 G16): wchar_t = i32 (Linux). The mem*/str*
// analogues over NUL(0)-terminated wchar_t arrays. Pure inner hosted-tested
// (vs an &[i32] model); C ABI freestanding.
#![allow(clippy::missing_safety_doc)]

/// # C: size_t wcslen(const wchar_t *)
pub(crate) unsafe fn wcslen_impl(s: *const i32) -> usize {
    // SAFETY: s is a 0-terminated wchar_t array.
    unsafe { let mut n = 0; while *s.add(n) != 0 { n += 1; } n }
}
/// # C: int wcscmp(const wchar_t *, const wchar_t *)
pub(crate) unsafe fn wcscmp_impl(a: *const i32, b: *const i32) -> i32 {
    // SAFETY: a/b are 0-terminated wchar_t arrays.
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y { return if x < y { -1 } else { 1 }; }
            if x == 0 { return 0; }
            i += 1;
        }
    }
}
/// # C: int wcsncmp(const wchar_t *, const wchar_t *, size_t)
pub(crate) unsafe fn wcsncmp_impl(a: *const i32, b: *const i32, n: usize) -> i32 {
    // SAFETY: a/b readable for up to n wchars or to a 0 terminator.
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y { return if x < y { -1 } else { 1 }; }
            if x == 0 { return 0; }
            i += 1;
        }
        0
    }
}
/// # C: wchar_t *wcscpy(wchar_t *dst, const wchar_t *src)
pub(crate) unsafe fn wcscpy_impl(dst: *mut i32, src: *const i32) -> *mut i32 {
    // SAFETY: dst has room for wcslen(src)+1; src 0-terminated.
    unsafe {
        let mut i = 0;
        loop {
            let c = *src.add(i);
            *dst.add(i) = c;
            if c == 0 { break; }
            i += 1;
        }
        dst
    }
}
/// # C: wchar_t *wcschr(const wchar_t *, wchar_t)
pub(crate) unsafe fn wcschr_impl(s: *const i32, c: i32) -> *mut i32 {
    // SAFETY: s 0-terminated; the terminator matches c==0 like strchr.
    unsafe {
        let mut i = 0;
        loop {
            let x = *s.add(i);
            if x == c { return s.add(i) as *mut i32; }
            if x == 0 { return core::ptr::null_mut(); }
            i += 1;
        }
    }
}

/// # C: wchar_t *wcpcpy(wchar_t *dst, const wchar_t *src) — copy incl 0, ret &0
pub(crate) unsafe fn wcpcpy_impl(dst: *mut i32, src: *const i32) -> *mut i32 {
    // SAFETY: dst has room for wcslen(src)+1; src 0-terminated. Returns the
    // address of the written terminator (stpcpy analog).
    unsafe { let mut i = 0; loop { let c = *src.add(i); *dst.add(i) = c; if c == 0 { return dst.add(i); } i += 1; } }
}
/// # C: wchar_t *wcpncpy(wchar_t *dst, const wchar_t *src, size_t n)
pub(crate) unsafe fn wcpncpy_impl(dst: *mut i32, src: *const i32, n: usize) -> *mut i32 {
    // SAFETY: dst writable for n wchars; copy up to a 0 then 0-pad to n;
    // returns the address after the last non-pad wchar (stpncpy analog).
    unsafe {
        let mut i = 0;
        while i < n && *src.add(i) != 0 { *dst.add(i) = *src.add(i); i += 1; }
        let end = dst.add(i);
        while i < n { *dst.add(i) = 0; i += 1; }
        end
    }
}
/// # C: wchar_t *wcschrnul(const wchar_t *s, wchar_t c) — &c or &terminator
pub(crate) unsafe fn wcschrnul_impl(s: *const i32, c: i32) -> *mut i32 {
    // SAFETY: s 0-terminated; returns the first c, or the terminator if absent.
    unsafe { let mut i = 0; loop { let x = *s.add(i); if x == c || x == 0 { return s.add(i) as *mut i32; } i += 1; } }
}
/// # C: size_t wcsnlen(const wchar_t *s, size_t maxlen)
pub(crate) unsafe fn wcsnlen_impl(s: *const i32, maxlen: usize) -> usize {
    // SAFETY: s readable for up to maxlen wchars or a 0 terminator.
    unsafe { let mut n = 0; while n < maxlen && *s.add(n) != 0 { n += 1; } n }
}
/// # C: size_t wcsxfrm(wchar_t *dst, const wchar_t *src, size_t n) — C-locale id
pub(crate) unsafe fn wcsxfrm_impl(dst: *mut i32, src: *const i32, n: usize) -> usize {
    // SAFETY: src 0-terminated; C/POSIX collation is the identity, so copy up
    // to n-1 wchars + 0 and return the source length (C11 7.29.4.4.4).
    unsafe {
        let len = wcslen_impl(src);
        if n > 0 { let c = if len < n { len } else { n - 1 }; core::ptr::copy_nonoverlapping(src, dst, c); *dst.add(c) = 0; }
        len
    }
}
/// # C: wchar_t *wcsncpy(wchar_t *dst, const wchar_t *src, size_t n)
pub(crate) unsafe fn wcsncpy_impl(dst: *mut i32, src: *const i32, n: usize) -> *mut i32 {
    // SAFETY: dst writable for n wchars; src 0-terminated. Copy up to a 0, then
    // 0-pad to n (C wcsncpy contract).
    unsafe {
        let mut i = 0;
        while i < n && *src.add(i) != 0 { *dst.add(i) = *src.add(i); i += 1; }
        while i < n { *dst.add(i) = 0; i += 1; }
        dst
    }
}
/// # C: wchar_t *wcscat(wchar_t *dst, const wchar_t *src)
pub(crate) unsafe fn wcscat_impl(dst: *mut i32, src: *const i32) -> *mut i32 {
    // SAFETY: dst is 0-terminated with room for the concatenation; src 0-terminated.
    unsafe { let e = dst.add(wcslen_impl(dst)); wcscpy_impl(e, src); dst }
}
/// # C: wchar_t *wcsncat(wchar_t *dst, const wchar_t *src, size_t n)
pub(crate) unsafe fn wcsncat_impl(dst: *mut i32, src: *const i32, n: usize) -> *mut i32 {
    // SAFETY: dst 0-terminated with room; appends up to n src wchars then a 0.
    unsafe {
        let mut d = dst.add(wcslen_impl(dst));
        let mut i = 0;
        while i < n && *src.add(i) != 0 { *d = *src.add(i); d = d.add(1); i += 1; }
        *d = 0;
        dst
    }
}
/// # C: wchar_t *wcsrchr(const wchar_t *s, wchar_t c)
pub(crate) unsafe fn wcsrchr_impl(s: *const i32, c: i32) -> *mut i32 {
    // SAFETY: s 0-terminated; scan to the terminator tracking the last match.
    unsafe {
        let mut last = core::ptr::null_mut();
        let mut i = 0;
        loop {
            let x = *s.add(i);
            if x == c { last = s.add(i) as *mut i32; }
            if x == 0 { return last; }
            i += 1;
        }
    }
}
unsafe fn w_in(set: *const i32, c: i32) -> bool {
    // SAFETY: set is a 0-terminated wchar_t array; scan to the terminator.
    unsafe {
        let mut k = 0;
        loop {
            let s = *set.add(k);
            if s == 0 { return false; }
            if s == c { return true; }
            k += 1;
        }
    }
}
/// # C: size_t wcsspn(const wchar_t *s, const wchar_t *accept)
pub(crate) unsafe fn wcsspn_impl(s: *const i32, accept: *const i32) -> usize {
    // SAFETY: both 0-terminated; count leading run present in accept.
    unsafe { let mut i = 0; while *s.add(i) != 0 && w_in(accept, *s.add(i)) { i += 1; } i }
}
/// # C: size_t wcscspn(const wchar_t *s, const wchar_t *reject)
pub(crate) unsafe fn wcscspn_impl(s: *const i32, reject: *const i32) -> usize {
    // SAFETY: both 0-terminated; count leading run absent from reject.
    unsafe { let mut i = 0; while *s.add(i) != 0 && !w_in(reject, *s.add(i)) { i += 1; } i }
}
/// # C: wchar_t *wcspbrk(const wchar_t *s, const wchar_t *accept)
pub(crate) unsafe fn wcspbrk_impl(s: *const i32, accept: *const i32) -> *mut i32 {
    // SAFETY: both 0-terminated; first s wchar present in accept, else null.
    unsafe {
        let mut i = 0;
        loop {
            let b = *s.add(i);
            if b == 0 { return core::ptr::null_mut(); }
            if w_in(accept, b) { return s.add(i) as *mut i32; }
            i += 1;
        }
    }
}
/// # C: wchar_t *wcsstr(const wchar_t *hay, const wchar_t *needle)
pub(crate) unsafe fn wcsstr_impl(hay: *const i32, needle: *const i32) -> *mut i32 {
    // SAFETY: both 0-terminated; naive substring scan within bounds.
    unsafe {
        let nlen = wcslen_impl(needle);
        if nlen == 0 { return hay as *mut i32; }
        let mut i = 0;
        loop {
            let mut j = 0;
            while j < nlen && *hay.add(i + j) == *needle.add(j) { j += 1; }
            if j == nlen { return hay.add(i) as *mut i32; }
            if *hay.add(i) == 0 { return core::ptr::null_mut(); }
            i += 1;
        }
    }
}
/// # C: wchar_t *wmemset(wchar_t *s, wchar_t c, size_t n)
pub(crate) unsafe fn wmemset_impl(s: *mut i32, c: i32, n: usize) -> *mut i32 {
    // SAFETY: s is writable for n wchar_t elements; fill each with c.
    unsafe { let mut i = 0; while i < n { *s.add(i) = c; i += 1; } s }
}
/// # C: wchar_t *wmemcpy(wchar_t *d, const wchar_t *s, size_t n)
pub(crate) unsafe fn wmemcpy_impl(d: *mut i32, s: *const i32, n: usize) -> *mut i32 {
    // SAFETY: d and s are valid for n non-overlapping wchars.
    unsafe { core::ptr::copy_nonoverlapping(s, d, n); d }
}
/// # C: wchar_t *wmemmove(wchar_t *d, const wchar_t *s, size_t n)
pub(crate) unsafe fn wmemmove_impl(d: *mut i32, s: *const i32, n: usize) -> *mut i32 {
    // SAFETY: d and s are valid for n wchars; may overlap (copy handles it).
    unsafe { core::ptr::copy(s, d, n); d }
}
/// # C: int wmemcmp(const wchar_t *a, const wchar_t *b, size_t n)
pub(crate) unsafe fn wmemcmp_impl(a: *const i32, b: *const i32, n: usize) -> i32 {
    // SAFETY: a and b are readable for n wchars.
    unsafe {
        let mut i = 0;
        while i < n { let (x, y) = (*a.add(i), *b.add(i)); if x != y { return if x < y { -1 } else { 1 }; } i += 1; }
        0
    }
}
/// # C: wchar_t *wmemchr(const wchar_t *s, wchar_t c, size_t n)
pub(crate) unsafe fn wmemchr_impl(s: *const i32, c: i32, n: usize) -> *mut i32 {
    // SAFETY: s is readable for n wchar_t elements; scan for the value c.
    unsafe { let mut i = 0; while i < n { if *s.add(i) == c { return s.add(i) as *mut i32; } i += 1; } core::ptr::null_mut() }
}

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    // # C: size_t wcslen(const wchar_t *s)
    #[no_mangle]
    pub unsafe extern "C" fn wcslen(s: *const i32) -> usize {
        // SAFETY: s is a 0-terminated wchar_t array; forwards wcslen_impl.
        unsafe { wcslen_impl(s) }
    }
    // # C: int wcscmp(const wchar_t *a, const wchar_t *b)
    #[no_mangle]
    pub unsafe extern "C" fn wcscmp(a: *const i32, b: *const i32) -> i32 {
        // SAFETY: a/b are 0-terminated wchar_t arrays; forwards wcscmp_impl.
        unsafe { wcscmp_impl(a, b) }
    }
    // # C: int wcsncmp(const wchar_t *a, const wchar_t *b, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn wcsncmp(a: *const i32, b: *const i32, n: usize) -> i32 {
        // SAFETY: a/b readable for up to n wchars or a 0 terminator.
        unsafe { wcsncmp_impl(a, b, n) }
    }
    // # C: wchar_t *wcscpy(wchar_t *dst, const wchar_t *src)
    #[no_mangle]
    pub unsafe extern "C" fn wcscpy(dst: *mut i32, src: *const i32) -> *mut i32 {
        // SAFETY: dst has room for wcslen(src)+1; src 0-terminated.
        unsafe { wcscpy_impl(dst, src) }
    }
    // # C: wchar_t *wcschr(const wchar_t *s, wchar_t c)
    #[no_mangle]
    pub unsafe extern "C" fn wcschr(s: *const i32, c: i32) -> *mut i32 {
        // SAFETY: s is a 0-terminated wchar_t array; forwards wcschr_impl.
        unsafe { wcschr_impl(s, c) }
    }
    // # C: wchar_t *wcsncpy(wchar_t *, const wchar_t *, size_t)
    // SAFETY: dst writable for n wchars; src 0-terminated. Forwards.
    #[no_mangle] pub unsafe extern "C" fn wcsncpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32 { unsafe { wcsncpy_impl(d, s, n) } }
    // # C: wchar_t *wcpcpy(wchar_t *, const wchar_t *)
    // SAFETY: dst has room for wcslen(src)+1; forwards wcpcpy_impl.
    #[no_mangle] pub unsafe extern "C" fn wcpcpy(d: *mut i32, s: *const i32) -> *mut i32 { unsafe { wcpcpy_impl(d, s) } }
    // # C: wchar_t *wcpncpy(wchar_t *, const wchar_t *, size_t)
    // SAFETY: dst writable for n wchars; forwards wcpncpy_impl.
    #[no_mangle] pub unsafe extern "C" fn wcpncpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32 { unsafe { wcpncpy_impl(d, s, n) } }
    // # C: wchar_t *wcschrnul(const wchar_t *, wchar_t)
    // SAFETY: s 0-terminated; forwards wcschrnul_impl.
    #[no_mangle] pub unsafe extern "C" fn wcschrnul(s: *const i32, c: i32) -> *mut i32 { unsafe { wcschrnul_impl(s, c) } }
    // # C: size_t wcsnlen(const wchar_t *, size_t)
    // SAFETY: s readable for up to maxlen wchars; forwards wcsnlen_impl.
    #[no_mangle] pub unsafe extern "C" fn wcsnlen(s: *const i32, maxlen: usize) -> usize { unsafe { wcsnlen_impl(s, maxlen) } }
    // # C: int wcscoll(const wchar_t *, const wchar_t *) — C locale == wcscmp
    // SAFETY: both 0-terminated; C/POSIX collation is byte order.
    #[no_mangle] pub unsafe extern "C" fn wcscoll(a: *const i32, b: *const i32) -> i32 { unsafe { wcscmp_impl(a, b) } }
    // # C: size_t wcsxfrm(wchar_t *, const wchar_t *, size_t)
    // SAFETY: src 0-terminated; forwards wcsxfrm_impl.
    #[no_mangle] pub unsafe extern "C" fn wcsxfrm(d: *mut i32, s: *const i32, n: usize) -> usize { unsafe { wcsxfrm_impl(d, s, n) } }
    // # C: wchar_t *wcscat(wchar_t *, const wchar_t *)
    // SAFETY: dst 0-terminated with room; src 0-terminated. Forwards.
    #[no_mangle] pub unsafe extern "C" fn wcscat(d: *mut i32, s: *const i32) -> *mut i32 { unsafe { wcscat_impl(d, s) } }
    // # C: wchar_t *wcsncat(wchar_t *, const wchar_t *, size_t)
    // SAFETY: dst 0-terminated with room; appends up to n wchars. Forwards.
    #[no_mangle] pub unsafe extern "C" fn wcsncat(d: *mut i32, s: *const i32, n: usize) -> *mut i32 { unsafe { wcsncat_impl(d, s, n) } }
    // # C: wchar_t *wcsrchr(const wchar_t *, wchar_t)
    // SAFETY: s 0-terminated; forwards wcsrchr_impl.
    #[no_mangle] pub unsafe extern "C" fn wcsrchr(s: *const i32, c: i32) -> *mut i32 { unsafe { wcsrchr_impl(s, c) } }
    // # C: size_t wcsspn(const wchar_t *, const wchar_t *)
    // SAFETY: both 0-terminated; forwards wcsspn_impl.
    #[no_mangle] pub unsafe extern "C" fn wcsspn(s: *const i32, a: *const i32) -> usize { unsafe { wcsspn_impl(s, a) } }
    // # C: size_t wcscspn(const wchar_t *, const wchar_t *)
    // SAFETY: both 0-terminated; forwards wcscspn_impl.
    #[no_mangle] pub unsafe extern "C" fn wcscspn(s: *const i32, r: *const i32) -> usize { unsafe { wcscspn_impl(s, r) } }
    // # C: wchar_t *wcspbrk(const wchar_t *, const wchar_t *)
    // SAFETY: both 0-terminated; forwards wcspbrk_impl.
    #[no_mangle] pub unsafe extern "C" fn wcspbrk(s: *const i32, a: *const i32) -> *mut i32 { unsafe { wcspbrk_impl(s, a) } }
    // # C: wchar_t *wcsstr(const wchar_t *, const wchar_t *)
    // SAFETY: both 0-terminated; forwards wcsstr_impl.
    #[no_mangle] pub unsafe extern "C" fn wcsstr(h: *const i32, n: *const i32) -> *mut i32 { unsafe { wcsstr_impl(h, n) } }
    // # C: wchar_t *wmemset(wchar_t *, wchar_t, size_t)
    // SAFETY: s writable for n wchars; forwards wmemset_impl.
    #[no_mangle] pub unsafe extern "C" fn wmemset(s: *mut i32, c: i32, n: usize) -> *mut i32 { unsafe { wmemset_impl(s, c, n) } }
    // # C: wchar_t *wmemcpy(wchar_t *, const wchar_t *, size_t)
    // SAFETY: d and s valid for n non-overlapping wchars; forwards.
    #[no_mangle] pub unsafe extern "C" fn wmemcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32 { unsafe { wmemcpy_impl(d, s, n) } }
    // # C: wchar_t *wmemmove(wchar_t *, const wchar_t *, size_t)
    // SAFETY: d and s valid for n wchars, possibly overlapping; forwards.
    #[no_mangle] pub unsafe extern "C" fn wmemmove(d: *mut i32, s: *const i32, n: usize) -> *mut i32 { unsafe { wmemmove_impl(d, s, n) } }
    // # C: int wmemcmp(const wchar_t *, const wchar_t *, size_t)
    // SAFETY: a and b readable for n wchars; forwards wmemcmp_impl.
    #[no_mangle] pub unsafe extern "C" fn wmemcmp(a: *const i32, b: *const i32, n: usize) -> i32 { unsafe { wmemcmp_impl(a, b, n) } }
    // # C: wchar_t *wmemchr(const wchar_t *, wchar_t, size_t)
    // SAFETY: s readable for n wchars; forwards wmemchr_impl.
    #[no_mangle] pub unsafe extern "C" fn wmemchr(s: *const i32, c: i32, n: usize) -> *mut i32 { unsafe { wmemchr_impl(s, c, n) } }

    // # C: wchar_t *wcsdup(const wchar_t *s) — malloc a copy
    #[no_mangle]
    pub unsafe extern "C" fn wcsdup(s: *const i32) -> *mut i32 {
        // SAFETY: s 0-terminated; allocate (wcslen+1)*4 bytes via malloc and copy.
        unsafe {
            extern "C" { fn malloc(n: usize) -> *mut core::ffi::c_void; }
            let n = wcslen_impl(s) + 1;
            let p = malloc(n * 4) as *mut i32;
            if p.is_null() { return p; }
            wmemcpy_impl(p, s, n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_ops() {
        let a = [104i32, 105, 0]; // "hi"
        let b = [104i32, 105, 0];
        let c = [104i32, 106, 0]; // "hj"
        // SAFETY: all are 0-terminated i32 arrays.
        unsafe {
            assert_eq!(wcslen_impl(a.as_ptr()), 2);
            assert_eq!(wcscmp_impl(a.as_ptr(), b.as_ptr()), 0);
            assert!(wcscmp_impl(a.as_ptr(), c.as_ptr()) < 0);
            assert_eq!(wcsncmp_impl(a.as_ptr(), c.as_ptr(), 1), 0);
            assert_eq!(wcschr_impl(a.as_ptr(), 105), a.as_ptr().add(1) as *mut i32);
            assert!(wcschr_impl(a.as_ptr(), 999).is_null());
            let mut d = [0i32; 4];
            wcscpy_impl(d.as_mut_ptr(), a.as_ptr());
            assert_eq!(wcslen_impl(d.as_ptr()), 2);
        }
    }
    #[test]
    fn wide_extras() {
        // SAFETY: all arrays are 0-terminated / sized for the bytes touched.
        unsafe {
            let mut buf = [104i32, 105, 0, 0, 0, 0]; // "hi"
            wcscat_impl(buf.as_mut_ptr(), [33i32, 0].as_ptr()); // + "!"
            assert_eq!(wcslen_impl(buf.as_ptr()), 3);
            assert_eq!(buf[2], 33);
            let s = [97i32, 98, 99, 98, 0]; // "abcb"
            assert_eq!(wcsrchr_impl(s.as_ptr(), 98) as usize - s.as_ptr() as usize, 3 * 4);
            let acc = [99i32, 0]; // "c"
            assert_eq!(wcscspn_impl(s.as_ptr(), acc.as_ptr()), 2);
            assert_eq!(wcsspn_impl([99i32, 99, 97, 0].as_ptr(), acc.as_ptr()), 2);
            assert_eq!(wcsstr_impl(s.as_ptr(), [98i32, 99, 0].as_ptr()) as usize - s.as_ptr() as usize, 4);
            let mut m = [0i32; 4];
            wmemset_impl(m.as_mut_ptr(), 7, 4);
            assert_eq!(m, [7, 7, 7, 7]);
            assert!(wmemcmp_impl([1i32, 2].as_ptr(), [1i32, 3].as_ptr(), 2) < 0);
            assert_eq!(wmemchr_impl(s.as_ptr(), 99, 4) as usize - s.as_ptr() as usize, 2 * 4);
            let mut n = [0i32; 4];
            wcsncpy_impl(n.as_mut_ptr(), [65i32, 0].as_ptr(), 4); // "A" + 0-pad
            assert_eq!(n, [65, 0, 0, 0]);
        }
    }
}
