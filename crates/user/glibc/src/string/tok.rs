// strtok / strtok_r (docs/59§6 G4). Tokenise in place on a delimiter set,
// reusing the span scanners. strtok_r is the reentrant core; strtok keeps a
// process-global save pointer. Pure inner hosted-tested; C ABI freestanding.
use super::chr::{strcspn_impl, strspn_impl};

/// Reentrant strtok core. `s` null continues from `*save`.
/// # C: char *strtok_r(char *s, const char *delim, char **saveptr)
pub(crate) unsafe fn strtok_r_impl(s: *mut u8, delim: *const u8, save: *mut *mut u8) -> *mut u8 {
    // SAFETY: s/*save is null or a NUL-terminated mutable string; delim is a
    // NUL-terminated set; we write a NUL at the token end and advance *save.
    unsafe {
        let mut p = if s.is_null() { *save } else { s };
        if p.is_null() { return core::ptr::null_mut(); }
        p = p.add(strspn_impl(p, delim)); // skip leading delimiters
        if *p == 0 { *save = p; return core::ptr::null_mut(); }
        let tok = p;
        let end = p.add(strcspn_impl(p, delim)); // first delimiter (or NUL)
        if *end == 0 {
            *save = end;
        } else {
            *end = 0;
            *save = end.add(1);
        }
        tok
    }
}

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::cell::UnsafeCell;

    struct Save(UnsafeCell<*mut u8>);
    // SAFETY: strtok's hidden save pointer; single-threaded contract (callers
    // needing thread-safety use strtok_r), matching glibc's non-reentrant strtok.
    unsafe impl Sync for Save {}
    static SAVE: Save = Save(UnsafeCell::new(core::ptr::null_mut()));

    // # C: char *strtok_r(char *s, const char *delim, char **saveptr)
    #[no_mangle]
    pub unsafe extern "C" fn strtok_r(s: *mut u8, delim: *const u8, save: *mut *mut u8) -> *mut u8 {
        // SAFETY: forwards the C strtok_r contract unchanged.
        unsafe { strtok_r_impl(s, delim, save) }
    }
    // # C: char *strtok(char *s, const char *delim)
    #[no_mangle]
    pub unsafe extern "C" fn strtok(s: *mut u8, delim: *const u8) -> *mut u8 {
        // SAFETY: uses the process-global save pointer (non-reentrant, per C).
        unsafe { strtok_r_impl(s, delim, SAVE.0.get()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    #[test]
    fn tokenises() {
        let mut s = *b"a,b,,c\0";
        let delim = b",\0".as_ptr(); // NUL-terminated delimiter set
        let mut save: *mut u8 = core::ptr::null_mut();
        let mut toks: Vec<u8> = Vec::new();
        // SAFETY: s is a NUL-terminated mutable buffer; strtok_r tokenises it.
        unsafe {
            let mut t = strtok_r_impl(s.as_mut_ptr(), delim, &mut save);
            while !t.is_null() {
                toks.push(*t); // first char of each token
                t = strtok_r_impl(core::ptr::null_mut(), delim, &mut save);
            }
        }
        assert_eq!(toks, b"abc"); // "a","b","c" (empty field between ,, skipped)
    }
}
