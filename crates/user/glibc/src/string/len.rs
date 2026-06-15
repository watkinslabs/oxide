// strlen / strnlen (docs/59§6 G4).

pub(crate) unsafe fn strlen_impl(s: *const u8) -> usize {
    // SAFETY: C strlen contract — s points at a NUL-terminated string, so
    // the scan stops at the terminator within the string's allocation.
    unsafe {
        let mut n = 0;
        while *s.add(n) != 0 { n += 1; }
        n
    }
}

pub(crate) unsafe fn strnlen_impl(s: *const u8, maxlen: usize) -> usize {
    // SAFETY: C strnlen contract — s is valid for up to `maxlen` bytes; we
    // never read past maxlen even if no NUL is present.
    unsafe {
        let mut n = 0;
        while n < maxlen && *s.add(n) != 0 { n += 1; }
        n
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: size_t strlen(const char *s)
    #[no_mangle]
    pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
        // SAFETY: forwards the C strlen contract to strlen_impl unchanged.
        unsafe { strlen_impl(s) }
    }
    // # C: size_t strnlen(const char *s, size_t maxlen)
    #[no_mangle]
    pub unsafe extern "C" fn strnlen(s: *const u8, maxlen: usize) -> usize {
        // SAFETY: forwards the C strnlen contract to strnlen_impl unchanged.
        unsafe { strnlen_impl(s, maxlen) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use proptest::prelude::*;
    // build a NUL-terminated C buffer from arbitrary non-NUL bytes
    fn cstr(bytes: &[u8]) -> Vec<u8> {
        let mut v: Vec<u8> = bytes.iter().map(|&b| if b == 0 { 1 } else { b }).collect();
        v.push(0);
        v
    }
    proptest! {
        #[test]
        fn strlen_matches(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let s = cstr(&bytes);
            // SAFETY: s is a NUL-terminated buffer valid for both reads.
            let (ours, theirs) = unsafe {
                (strlen_impl(s.as_ptr()), libc::strlen(s.as_ptr() as *const _))
            };
            prop_assert_eq!(ours, theirs);
        }
        #[test]
        fn strnlen_matches(bytes in proptest::collection::vec(any::<u8>(), 0..256), max in 0usize..300) {
            let s = cstr(&bytes);
            // SAFETY: s is NUL-terminated; strnlen reads at most `max` bytes.
            let (ours, theirs) = unsafe {
                (strnlen_impl(s.as_ptr(), max), libc::strnlen(s.as_ptr() as *const _, max))
            };
            prop_assert_eq!(ours, theirs);
        }
    }
}
