// mem* family (docs/59§6 G4). Scalar reference impls; IFUNC-selected SIMD
// variants are a post-rtld refinement (G12+, needs IRELATIVE). Inner
// `*_impl` fns are always built + differentially tested vs host glibc;
// the #[no_mangle] C exports are freestanding-only.

pub(crate) unsafe fn memcpy_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: C memcpy contract — caller guarantees src and dst are each
    // valid for `n` bytes and do not overlap; we copy forward in range.
    unsafe {
        let mut i = 0;
        while i < n { *dst.add(i) = *src.add(i); i += 1; }
    }
    dst
}

pub(crate) unsafe fn memmove_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: C memmove contract — src/dst valid for `n` bytes; overlap is
    // allowed, so copy direction is chosen to preserve overlapping bytes.
    unsafe {
        if (dst as usize) < (src as usize) {
            let mut i = 0;
            while i < n { *dst.add(i) = *src.add(i); i += 1; }
        } else {
            let mut i = n;
            while i > 0 { i -= 1; *dst.add(i) = *src.add(i); }
        }
    }
    dst
}

pub(crate) unsafe fn memset_impl(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: C memset contract — dst is valid for `n` bytes; we store the
    // low byte of `c` across the whole range.
    unsafe {
        let b = c as u8;
        let mut i = 0;
        while i < n { *dst.add(i) = b; i += 1; }
    }
    dst
}

pub(crate) unsafe fn memcmp_impl(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: C memcmp contract — a and b are each valid for `n` bytes;
    // we read up to the first difference.
    unsafe {
        let mut i = 0;
        while i < n {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y { return x as i32 - y as i32; }
            i += 1;
        }
    }
    0
}

pub(crate) unsafe fn memchr_impl(s: *const u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: C memchr contract — s is valid for `n` bytes; we scan and
    // return the first match or null without writing.
    unsafe {
        let b = c as u8;
        let mut i = 0;
        while i < n {
            if *s.add(i) == b { return s.add(i) as *mut u8; }
            i += 1;
        }
    }
    core::ptr::null_mut()
}

// ---- C ABI exports (freestanding) ----
#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: void *memcpy(void *dst, const void *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        // SAFETY: forwards the C memcpy contract to memcpy_impl unchanged.
        unsafe { memcpy_impl(dst, src, n) }
    }
    // # C: void *memmove(void *dst, const void *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        // SAFETY: forwards the C memmove contract to memmove_impl unchanged.
        unsafe { memmove_impl(dst, src, n) }
    }
    // # C: void *memset(void *dst, int c, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
        // SAFETY: forwards the C memset contract to memset_impl unchanged.
        unsafe { memset_impl(dst, c, n) }
    }
    // # C: int memcmp(const void *a, const void *b, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        // SAFETY: forwards the C memcmp contract to memcmp_impl unchanged.
        unsafe { memcmp_impl(a, b, n) }
    }
    // # C: int bcmp(const void *a, const void *b, size_t n) — like memcmp but
    // only zero/non-zero matters; the compiler lowers slice-equality to it.
    #[no_mangle]
    pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        // SAFETY: forwards to memcmp_impl; same buffer contract.
        unsafe { memcmp_impl(a, b, n) }
    }
    // # C: void *memchr(const void *s, int c, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
        // SAFETY: forwards the C memchr contract to memchr_impl unchanged.
        unsafe { memchr_impl(s, c, n) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn memcpy_matches(src in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut a = vec![0u8; src.len()];
            let mut b = vec![0u8; src.len()];
            // SAFETY: a and b are sized to src.len(); all pointers are valid for the copy.
            unsafe {
                memcpy_impl(a.as_mut_ptr(), src.as_ptr(), src.len());
                libc::memcpy(b.as_mut_ptr() as *mut _, src.as_ptr() as *const _, src.len());
            }
            prop_assert_eq!(a, b);
        }
        #[test]
        fn memset_matches(n in 0usize..256, c in any::<u8>()) {
            let mut a = vec![0xAAu8; n];
            let mut b = vec![0xAAu8; n];
            // SAFETY: a and b are each n bytes; memset writes exactly n bytes.
            unsafe {
                memset_impl(a.as_mut_ptr(), c as i32, n);
                libc::memset(b.as_mut_ptr() as *mut _, c as i32, n);
            }
            prop_assert_eq!(a, b);
        }
        #[test]
        fn memcmp_sign_matches(x in proptest::collection::vec(any::<u8>(), 1..64),
                               y in proptest::collection::vec(any::<u8>(), 1..64)) {
            let n = x.len().min(y.len());
            // SAFETY: x and y are each at least n bytes; memcmp reads n bytes.
            let (ours, theirs) = unsafe {
                (memcmp_impl(x.as_ptr(), y.as_ptr(), n),
                 libc::memcmp(x.as_ptr() as *const _, y.as_ptr() as *const _, n))
            };
            prop_assert_eq!(ours.signum(), theirs.signum());
        }
        #[test]
        fn memchr_matches(buf in proptest::collection::vec(any::<u8>(), 0..256), c in any::<u8>()) {
            // SAFETY: buf is buf.len() bytes; memchr scans exactly that range.
            let (ours, theirs) = unsafe {
                (memchr_impl(buf.as_ptr(), c as i32, buf.len()),
                 libc::memchr(buf.as_ptr() as *const _, c as i32, buf.len()) as *mut u8)
            };
            prop_assert_eq!(ours, theirs);
        }
        #[test]
        fn memmove_overlap_matches(data in proptest::collection::vec(any::<u8>(), 1..128), shift in 0usize..16) {
            // overlapping move within one buffer; compare to libc on a clone
            let n = data.len().saturating_sub(shift);
            let mut a = data.clone();
            let mut b = data.clone();
            if n > 0 {
                // SAFETY: [shift, shift+n) and [0, n) are in bounds of a/b (len ≥ shift+n).
                unsafe {
                    memmove_impl(a.as_mut_ptr().add(shift), a.as_ptr(), n);
                    libc::memmove(b.as_mut_ptr().add(shift) as *mut _, b.as_ptr() as *const _, n);
                }
            }
            prop_assert_eq!(a, b);
        }
    }
}
