// strerror(3) (docs/59§6 G4). errno → canonical glibc message (Linux errno
// numbering). Messages match glibc exactly so callers (perror, error paths,
// test oracles) render identically. Unknown codes → "Unknown error". Pure
// table hosted-tested; C ABI exports freestanding-gated.

/// glibc message for `e` (NUL-terminated, 'static). # C: errno → message
pub(crate) fn msg(e: i32) -> &'static [u8] {
    // Single complete table lives in errname.rs (shared with strerror{name,desc}_np).
    crate::string::errname::desc(e).unwrap_or(b"Unknown error\0")
}

#[cfg(feature = "freestanding")]
mod imp {
    use super::msg;
    // # C: char *strerror(int errnum)
    #[no_mangle]
    pub extern "C" fn strerror(errnum: i32) -> *mut u8 { msg(errnum).as_ptr() as *mut u8 }

    // # C: int strerror_r(int errnum, char *buf, size_t buflen) — XSI/POSIX form
    #[no_mangle]
    pub unsafe extern "C" fn __xpg_strerror_r(errnum: i32, buf: *mut u8, buflen: usize) -> i32 {
        // SAFETY: buf is writable for buflen bytes; copy the message + NUL, ERANGE
        // (34) if it does not fit.
        unsafe {
            let m = msg(errnum);
            let n = m.len() - 1; // without the source NUL
            if buflen == 0 { return 34; }
            if n + 1 > buflen {
                core::ptr::copy_nonoverlapping(m.as_ptr(), buf, buflen - 1);
                *buf.add(buflen - 1) = 0;
                return 34; // ERANGE
            }
            core::ptr::copy_nonoverlapping(m.as_ptr(), buf, n + 1);
            0
        }
    }

    // # C: char *strerror_r(int errnum, char *buf, size_t buflen) — GNU form.
    // Returns the 'static message pointer (glibc returns the immutable string for
    // a defined code and ignores buf); buf is the fallback scratch for unknowns.
    #[no_mangle]
    pub unsafe extern "C" fn strerror_r(errnum: i32, _buf: *mut u8, _buflen: usize) -> *mut u8 {
        // SAFETY: msg() yields a 'static NUL-terminated message; the GNU contract
        // permits returning it directly without writing the caller's buffer.
        msg(errnum).as_ptr() as *mut u8
    }
    // # C: char *__strerror_r(int errnum, char *buf, size_t buflen)
    #[no_mangle]
    pub unsafe extern "C" fn __strerror_r(errnum: i32, buf: *mut u8, buflen: usize) -> *mut u8 {
        // SAFETY: __strerror_r has the same scratch-buffer contract as strerror_r.
        unsafe { strerror_r(errnum, buf, buflen) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_messages() {
        assert_eq!(msg(2), b"No such file or directory\0");
        assert_eq!(msg(22), b"Invalid argument\0");
        assert_eq!(msg(0), b"Success\0");
        assert_eq!(msg(99999), b"Unknown error\0");
    }
}
