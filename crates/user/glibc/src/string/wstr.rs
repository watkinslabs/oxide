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
}
