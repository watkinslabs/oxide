// Character/substring search (docs/59§6 G4): strchr/strrchr/strchrnul,
// strstr, strspn/strcspn/strpbrk. C: the NUL is part of the string for
// strchr/strrchr (so searching for '\0' finds the terminator).
use crate::string::len::strlen_impl;

pub(crate) unsafe fn strchr_impl(s: *const u8, c: i32) -> *mut u8 {
    // SAFETY: C strchr contract — s is NUL-terminated; scan includes the
    // terminator so strchr(s,0) returns it, else null.
    unsafe {
        let want = c as u8;
        let mut i = 0;
        loop {
            let b = *s.add(i);
            if b == want { return s.add(i) as *mut u8; }
            if b == 0 { return core::ptr::null_mut(); }
            i += 1;
        }
    }
}

pub(crate) unsafe fn strchrnul_impl(s: *const u8, c: i32) -> *mut u8 {
    // SAFETY: C strchrnul (GNU) — like strchr but returns the terminator
    // pointer instead of null when not found; s is NUL-terminated.
    unsafe {
        let want = c as u8;
        let mut i = 0;
        loop {
            let b = *s.add(i);
            if b == want || b == 0 { return s.add(i) as *mut u8; }
            i += 1;
        }
    }
}

pub(crate) unsafe fn strrchr_impl(s: *const u8, c: i32) -> *mut u8 {
    // SAFETY: C strrchr contract — s is NUL-terminated; we scan the whole
    // string (incl terminator) and remember the last match.
    unsafe {
        let want = c as u8;
        let mut last = core::ptr::null_mut();
        let mut i = 0;
        loop {
            let b = *s.add(i);
            if b == want { last = s.add(i) as *mut u8; }
            if b == 0 { return last; }
            i += 1;
        }
    }
}

pub(crate) unsafe fn strstr_impl(hay: *const u8, needle: *const u8) -> *mut u8 {
    // SAFETY: C strstr contract — both are NUL-terminated; naive O(n*m)
    // scan staying within each string's bounds.
    unsafe {
        let nlen = strlen_impl(needle);
        if nlen == 0 { return hay as *mut u8; }
        let mut i = 0;
        loop {
            let mut j = 0;
            while j < nlen && *hay.add(i + j) == *needle.add(j) { j += 1; }
            if j == nlen { return hay.add(i) as *mut u8; }
            if *hay.add(i) == 0 { return core::ptr::null_mut(); }
            i += 1;
        }
    }
}

unsafe fn in_set(set: *const u8, b: u8) -> bool {
    // SAFETY: set is a NUL-terminated string; scan stops at terminator.
    unsafe {
        let mut k = 0;
        loop {
            let s = *set.add(k);
            if s == 0 { return false; }
            if s == b { return true; }
            k += 1;
        }
    }
}

pub(crate) unsafe fn strspn_impl(s: *const u8, accept: *const u8) -> usize {
    // SAFETY: C strspn contract — both NUL-terminated; count leading run of
    // chars present in `accept`.
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 && in_set(accept, *s.add(i)) { i += 1; }
        i
    }
}

pub(crate) unsafe fn strcspn_impl(s: *const u8, reject: *const u8) -> usize {
    // SAFETY: C strcspn contract — both NUL-terminated; count leading run of
    // chars absent from `reject`.
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 && !in_set(reject, *s.add(i)) { i += 1; }
        i
    }
}

pub(crate) unsafe fn strpbrk_impl(s: *const u8, accept: *const u8) -> *mut u8 {
    // SAFETY: C strpbrk contract — both NUL-terminated; return first char of
    // s present in accept, else null.
    unsafe {
        let mut i = 0;
        loop {
            let b = *s.add(i);
            if b == 0 { return core::ptr::null_mut(); }
            if in_set(accept, b) { return s.add(i) as *mut u8; }
            i += 1;
        }
    }
}

#[cfg(feature = "freestanding")]
mod exports {
    use super::*;
    // # C: char *strchr(const char *s, int c)
    #[no_mangle]
    pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *mut u8 {
        // SAFETY: forwards the C strchr contract to strchr_impl unchanged.
        unsafe { strchr_impl(s, c) }
    }
    // # C: char *strchrnul(const char *s, int c)
    #[no_mangle]
    pub unsafe extern "C" fn strchrnul(s: *const u8, c: i32) -> *mut u8 {
        // SAFETY: forwards the GNU strchrnul contract to strchrnul_impl.
        unsafe { strchrnul_impl(s, c) }
    }
    // # C: char *strrchr(const char *s, int c)
    #[no_mangle]
    pub unsafe extern "C" fn strrchr(s: *const u8, c: i32) -> *mut u8 {
        // SAFETY: forwards the C strrchr contract to strrchr_impl unchanged.
        unsafe { strrchr_impl(s, c) }
    }
    // # C: char *strstr(const char *hay, const char *needle)
    #[no_mangle]
    pub unsafe extern "C" fn strstr(hay: *const u8, needle: *const u8) -> *mut u8 {
        // SAFETY: forwards the C strstr contract to strstr_impl unchanged.
        unsafe { strstr_impl(hay, needle) }
    }
    // # C: size_t strspn(const char *s, const char *accept)
    #[no_mangle]
    pub unsafe extern "C" fn strspn(s: *const u8, accept: *const u8) -> usize {
        // SAFETY: forwards the C strspn contract to strspn_impl unchanged.
        unsafe { strspn_impl(s, accept) }
    }
    // # C: size_t strcspn(const char *s, const char *reject)
    #[no_mangle]
    pub unsafe extern "C" fn strcspn(s: *const u8, reject: *const u8) -> usize {
        // SAFETY: forwards the C strcspn contract to strcspn_impl unchanged.
        unsafe { strcspn_impl(s, reject) }
    }
    // # C: char *strpbrk(const char *s, const char *accept)
    #[no_mangle]
    pub unsafe extern "C" fn strpbrk(s: *const u8, accept: *const u8) -> *mut u8 {
        // SAFETY: forwards the C strpbrk contract to strpbrk_impl unchanged.
        unsafe { strpbrk_impl(s, accept) }
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
    proptest! {
        #[test]
        fn strchr_matches(bytes in proptest::collection::vec(1u8..=255, 0..128), c in any::<u8>()) {
            let s = cstr(&bytes);
            // SAFETY: s is NUL-terminated; strchr scans within it.
            let (ours, theirs) = unsafe {
                (strchr_impl(s.as_ptr(), c as i32),
                 libc::strchr(s.as_ptr() as *const _, c as i32) as *mut u8)
            };
            prop_assert_eq!(ours, theirs);
        }
        #[test]
        fn strrchr_matches(bytes in proptest::collection::vec(1u8..=255, 0..128), c in any::<u8>()) {
            let s = cstr(&bytes);
            // SAFETY: s is NUL-terminated; strrchr scans within it.
            let (ours, theirs) = unsafe {
                (strrchr_impl(s.as_ptr(), c as i32),
                 libc::strrchr(s.as_ptr() as *const _, c as i32) as *mut u8)
            };
            prop_assert_eq!(ours, theirs);
        }
        #[test]
        fn strstr_matches(h in proptest::collection::vec(1u8..=4, 0..64), n in proptest::collection::vec(1u8..=4, 0..6)) {
            let hay = cstr(&h);
            let needle = cstr(&n);
            // SAFETY: hay and needle are NUL-terminated; strstr scans within them.
            let (ours, theirs) = unsafe {
                (strstr_impl(hay.as_ptr(), needle.as_ptr()),
                 libc::strstr(hay.as_ptr() as *const _, needle.as_ptr() as *const _) as *mut u8)
            };
            prop_assert_eq!(ours, theirs);
        }
        #[test]
        fn strspn_matches(s in proptest::collection::vec(1u8..=4, 0..64), acc in proptest::collection::vec(1u8..=4, 0..6)) {
            let cs = cstr(&s); let ca = cstr(&acc);
            // SAFETY: cs and ca are NUL-terminated; strspn scans within them.
            let (ours, theirs) = unsafe {
                (strspn_impl(cs.as_ptr(), ca.as_ptr()),
                 libc::strspn(cs.as_ptr() as *const _, ca.as_ptr() as *const _))
            };
            prop_assert_eq!(ours, theirs);
        }
        #[test]
        fn strcspn_matches(s in proptest::collection::vec(1u8..=4, 0..64), rej in proptest::collection::vec(1u8..=4, 0..6)) {
            let cs = cstr(&s); let cr = cstr(&rej);
            // SAFETY: cs and cr are NUL-terminated; strcspn scans within them.
            let (ours, theirs) = unsafe {
                (strcspn_impl(cs.as_ptr(), cr.as_ptr()),
                 libc::strcspn(cs.as_ptr() as *const _, cr.as_ptr() as *const _))
            };
            prop_assert_eq!(ours, theirs);
        }
    }
}
