// strdup / strndup (docs/59§6 G5 — need malloc). Allocate via the heap
// and copy; caller frees with free().
use crate::malloc::heap::malloc;
use crate::string::len::{strlen_impl, strnlen_impl};
use crate::string::mem::memcpy_impl;

pub(crate) unsafe fn strdup_impl(s: *const u8) -> *mut u8 {
    // SAFETY: s is NUL-terminated; we allocate strlen+1 and copy it whole.
    unsafe {
        let n = strlen_impl(s) + 1;
        let p = malloc(n);
        if !p.is_null() { memcpy_impl(p, s, n); }
        p
    }
}

pub(crate) unsafe fn strndup_impl(s: *const u8, maxlen: usize) -> *mut u8 {
    // SAFETY: s is valid for up to maxlen bytes; we copy strnlen bytes and
    // NUL-terminate the fresh allocation.
    unsafe {
        let n = strnlen_impl(s, maxlen);
        let p = malloc(n + 1);
        if !p.is_null() {
            memcpy_impl(p, s, n);
            *p.add(n) = 0;
        }
        p
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: char *strdup(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn strdup(s: *const u8) -> *mut u8 {
        // SAFETY: forwards the C strdup contract to strdup_impl unchanged.
        unsafe { strdup_impl(s) }
    }
    // # C: char *__strdup(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn __strdup(s: *const u8) -> *mut u8 {
        // SAFETY: __strdup has the same C-string contract as strdup.
        unsafe { strdup(s) }
    }
    // # C: char *strndup(const char *s, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn strndup(s: *const u8, n: usize) -> *mut u8 {
        // SAFETY: forwards the C strndup contract to strndup_impl unchanged.
        unsafe { strndup_impl(s, n) }
    }
    // # C: char *__strndup(const char *s, size_t n)
    #[no_mangle]
    pub unsafe extern "C" fn __strndup(s: *const u8, n: usize) -> *mut u8 {
        // SAFETY: __strndup has the same bounded C-string contract as strndup.
        unsafe { strndup(s, n) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::malloc::heap::{free, usable_size};
    use alloc::vec::Vec;
    use proptest::prelude::*;
    fn cstr(bytes: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = bytes.iter().map(|&b| if b == 0 { 1 } else { b }).collect();
        v.push(0);
        v
    }
    proptest! {
        #[test]
        fn strdup_copies(bytes in proptest::collection::vec(1u8..=255, 0..128)) {
            let s = cstr(&bytes);
            // SAFETY: s is NUL-terminated; p is a fresh strdup we read then free.
            unsafe {
                let p = strdup_impl(s.as_ptr());
                prop_assert!(!p.is_null());
                prop_assert!(usable_size(p) >= s.len());
                let same = (0..s.len()).all(|k| *p.add(k) == s[k]);
                prop_assert!(same);
                free(p);
            }
        }
        #[test]
        fn strndup_truncates(bytes in proptest::collection::vec(1u8..=255, 0..128), max in 0usize..64) {
            let s = cstr(&bytes);
            let want = s.len().saturating_sub(1).min(max);
            // SAFETY: s NUL-terminated; p is strndup(max) we read then free.
            unsafe {
                let p = strndup_impl(s.as_ptr(), max);
                prop_assert!(!p.is_null());
                let prefix_ok = (0..want).all(|k| *p.add(k) == s[k]);
                prop_assert!(prefix_ok);
                prop_assert_eq!(*p.add(want), 0u8);
                free(p);
            }
        }
    }
}
