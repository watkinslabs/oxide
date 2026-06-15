// strcpy / strncpy / strcat / strncat (docs/59§6 G4). C semantics:
// strncpy NUL-pads to n and does NOT terminate if src is longer; strncat
// always NUL-terminates.
use crate::string::len::strlen_impl;

pub(crate) unsafe fn strcpy_impl(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: C strcpy contract — src is NUL-terminated and dst has room
    // for strlen(src)+1 bytes; we copy through the terminator.
    unsafe {
        let mut i = 0;
        loop {
            let b = *src.add(i);
            *dst.add(i) = b;
            if b == 0 { break; }
            i += 1;
        }
    }
    dst
}

pub(crate) unsafe fn strncpy_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: C strncpy contract — dst is valid for `n` bytes; src is read
    // until NUL or n; remainder is NUL-padded.
    unsafe {
        let mut i = 0;
        while i < n {
            let b = *src.add(i);
            *dst.add(i) = b;
            if b == 0 { break; }
            i += 1;
        }
        while i < n { *dst.add(i) = 0; i += 1; }
    }
    dst
}

pub(crate) unsafe fn strcat_impl(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: C strcat contract — dst is NUL-terminated with room for the
    // concatenation; we append src starting at dst's terminator.
    unsafe {
        let off = strlen_impl(dst);
        strcpy_impl(dst.add(off), src);
    }
    dst
}

pub(crate) unsafe fn strncat_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: C strncat contract — append up to `n` bytes of src then a
    // NUL; dst is NUL-terminated with room for the result.
    unsafe {
        let mut d = strlen_impl(dst);
        let mut i = 0;
        while i < n {
            let b = *src.add(i);
            if b == 0 { break; }
            *dst.add(d) = b;
            d += 1;
            i += 1;
        }
        *dst.add(d) = 0;
    }
    dst
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: char *strcpy(char *dst, const char *src)
    #[no_mangle]
    pub unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
        // SAFETY: forwards the C strcpy contract to strcpy_impl unchanged.
        unsafe { strcpy_impl(dst, src) }
    }
    // # C: char *strncpy(char *dst, const char *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        // SAFETY: forwards the C strncpy contract to strncpy_impl unchanged.
        unsafe { strncpy_impl(dst, src, n) }
    }
    // # C: char *strcat(char *dst, const char *src)
    #[no_mangle]
    pub unsafe extern "C" fn strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
        // SAFETY: forwards the C strcat contract to strcat_impl unchanged.
        unsafe { strcat_impl(dst, src) }
    }
    // # C: char *strncat(char *dst, const char *src, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn strncat(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        // SAFETY: forwards the C strncat contract to strncat_impl unchanged.
        unsafe { strncat_impl(dst, src, n) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use proptest::prelude::*;
    fn cstr(bytes: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = bytes.iter().map(|&b| if b == 0 { 1 } else { b }).collect();
        v.push(0);
        v
    }
    proptest! {
        #[test]
        fn strcpy_matches(src in proptest::collection::vec(any::<u8>(), 0..128)) {
            let s = cstr(&src);
            let mut a = vec![0xFFu8; s.len() + 8];
            let mut b = vec![0xFFu8; s.len() + 8];
            // SAFETY: a and b have room for s (NUL-terminated) plus slack.
            unsafe {
                strcpy_impl(a.as_mut_ptr(), s.as_ptr());
                libc::strcpy(b.as_mut_ptr() as *mut _, s.as_ptr() as *const _);
            }
            prop_assert_eq!(a, b);
        }
        #[test]
        fn strncpy_matches(src in proptest::collection::vec(any::<u8>(), 0..128), n in 0usize..160) {
            let s = cstr(&src);
            let mut a = vec![0xFFu8; n + 8];
            let mut b = vec![0xFFu8; n + 8];
            // SAFETY: a and b are each n+8 bytes; strncpy writes exactly n.
            unsafe {
                strncpy_impl(a.as_mut_ptr(), s.as_ptr(), n);
                libc::strncpy(b.as_mut_ptr() as *mut _, s.as_ptr() as *const _, n);
            }
            prop_assert_eq!(a, b);
        }
        #[test]
        fn strcat_matches(pre in proptest::collection::vec(any::<u8>(), 0..64),
                          add in proptest::collection::vec(any::<u8>(), 0..64)) {
            let p = cstr(&pre);
            let s = cstr(&add);
            let cap = p.len() + s.len() + 8;
            let mut a = vec![0xFFu8; cap]; a[..p.len()].copy_from_slice(&p);
            let mut b = vec![0xFFu8; cap]; b[..p.len()].copy_from_slice(&p);
            // SAFETY: a/b start with the NUL-terminated prefix and have room for s.
            unsafe {
                strcat_impl(a.as_mut_ptr(), s.as_ptr());
                libc::strcat(b.as_mut_ptr() as *mut _, s.as_ptr() as *const _);
            }
            prop_assert_eq!(a, b);
        }
    }
}
