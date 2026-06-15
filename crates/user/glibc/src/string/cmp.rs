// strcmp / strncmp (docs/59§6 G4). Comparison is on unsigned char, per C.

pub(crate) unsafe fn strcmp_impl(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: C strcmp contract — a and b are NUL-terminated; the scan
    // stops at the first difference or shared terminator.
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y { return x as i32 - y as i32; }
            if x == 0 { return 0; }
            i += 1;
        }
    }
}

#[inline]
fn lc(b: u8) -> u8 { if b.is_ascii_uppercase() { b + 32 } else { b } }

/// # C: int strcasecmp(const char *, const char *) — ASCII case-insensitive
pub(crate) unsafe fn strcasecmp_impl(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: a/b NUL-terminated; compare lowercased bytes to the terminator.
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (lc(*a.add(i)), lc(*b.add(i)));
            if x != y { return x as i32 - y as i32; }
            if *a.add(i) == 0 { return 0; }
            i += 1;
        }
    }
}
/// # C: int strncasecmp(const char *, const char *, size_t)
pub(crate) unsafe fn strncasecmp_impl(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: a/b valid for up to n bytes or a NUL; compare lowercased.
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (lc(*a.add(i)), lc(*b.add(i)));
            if x != y { return x as i32 - y as i32; }
            if *a.add(i) == 0 { return 0; }
            i += 1;
        }
        0
    }
}

pub(crate) unsafe fn strncmp_impl(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: C strncmp contract — a and b are valid for up to `n` bytes or
    // until a NUL; we never read past either bound.
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y { return x as i32 - y as i32; }
            if x == 0 { return 0; }
            i += 1;
        }
    }
    0
}

/// # C: size_t strxfrm(char *dst, const char *src, size_t n) — C-locale identity
pub(crate) unsafe fn strxfrm_impl(dst: *mut u8, src: *const u8, n: usize) -> usize {
    // SAFETY: src is NUL-terminated; in the C/POSIX locale the collation
    // transform is the identity, so copy up to n-1 bytes + NUL and return the
    // source length (caller compares lengths against n per C11 7.24.4.5).
    unsafe {
        let len = crate::string::len::strlen_impl(src);
        if n > 0 {
            let c = if len < n { len } else { n - 1 };
            core::ptr::copy_nonoverlapping(src, dst, c);
            *dst.add(c) = 0;
        }
        len
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: int strcmp(const char *a, const char *b)
    #[no_mangle]
    pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
        // SAFETY: forwards the C strcmp contract to strcmp_impl unchanged.
        unsafe { strcmp_impl(a, b) }
    }
    // # C: int strncmp(const char *a, const char *b, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        // SAFETY: forwards the C strncmp contract to strncmp_impl unchanged.
        unsafe { strncmp_impl(a, b, n) }
    }
    // # C: int strcasecmp(const char *a, const char *b)
    #[no_mangle]
    pub unsafe extern "C" fn strcasecmp(a: *const u8, b: *const u8) -> i32 {
        // SAFETY: forwards the C strcasecmp contract to strcasecmp_impl.
        unsafe { strcasecmp_impl(a, b) }
    }
    // # C: int strncasecmp(const char *a, const char *b, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn strncasecmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        // SAFETY: forwards the C strncasecmp contract to strncasecmp_impl.
        unsafe { strncasecmp_impl(a, b, n) }
    }
    // # C: int strcoll(const char *a, const char *b) — C locale == strcmp
    #[no_mangle]
    pub unsafe extern "C" fn strcoll(a: *const u8, b: *const u8) -> i32 {
        // SAFETY: C/POSIX-locale collation order equals byte order; defer to strcmp.
        unsafe { strcmp_impl(a, b) }
    }
    // # C: size_t strxfrm(char *dst, const char *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn strxfrm(dst: *mut u8, src: *const u8, n: usize) -> usize {
        // SAFETY: forwards the C strxfrm contract to strxfrm_impl unchanged.
        unsafe { strxfrm_impl(dst, src, n) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use proptest::prelude::*;
    fn cstr(bytes: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = bytes.iter().map(|&b| if b == 0 { 1 } else { b }).collect();
        v.push(0);
        v
    }
    #[test]
    fn strxfrm_identity() {
        // SAFETY: dst is 8 bytes; src "hello\0" is NUL-terminated.
        unsafe {
            let mut dst = [0u8; 8];
            let n = strxfrm_impl(dst.as_mut_ptr(), b"hello\0".as_ptr(), 8);
            assert_eq!(n, 5);
            assert_eq!(&dst[..6], b"hello\0");
            // short buffer: returns source length, dst truncated + NUL
            let mut s = [0u8; 3];
            let n2 = strxfrm_impl(s.as_mut_ptr(), b"world\0".as_ptr(), 3);
            assert_eq!(n2, 5);
            assert_eq!(&s, b"wo\0");
        }
    }
    proptest! {
        #[test]
        fn strcmp_sign_matches(x in proptest::collection::vec(any::<u8>(), 0..64),
                               y in proptest::collection::vec(any::<u8>(), 0..64)) {
            let (a, b) = (cstr(&x), cstr(&y));
            // SAFETY: a and b are NUL-terminated buffers valid for the scan.
            let (ours, theirs) = unsafe {
                (strcmp_impl(a.as_ptr(), b.as_ptr()),
                 libc::strcmp(a.as_ptr() as *const _, b.as_ptr() as *const _))
            };
            prop_assert_eq!(ours.signum(), theirs.signum());
        }
        #[test]
        fn strncmp_sign_matches(x in proptest::collection::vec(any::<u8>(), 0..64),
                                y in proptest::collection::vec(any::<u8>(), 0..64),
                                n in 0usize..80) {
            let (a, b) = (cstr(&x), cstr(&y));
            // SAFETY: a and b are NUL-terminated; strncmp reads at most n bytes.
            let (ours, theirs) = unsafe {
                (strncmp_impl(a.as_ptr(), b.as_ptr(), n),
                 libc::strncmp(a.as_ptr() as *const _, b.as_ptr() as *const _, n))
            };
            prop_assert_eq!(ours.signum(), theirs.signum());
        }
    }
}
