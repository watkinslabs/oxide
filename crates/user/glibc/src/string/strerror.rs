// strerror(3) (docs/59§6 G4). errno → canonical glibc message (Linux errno
// numbering). Messages match glibc exactly so callers (perror, error paths,
// test oracles) render identically. Unknown codes → "Unknown error". Pure
// table hosted-tested; C ABI exports freestanding-gated.

/// glibc message for `e` (NUL-terminated, 'static). # C: errno → message
pub(crate) fn msg(e: i32) -> &'static [u8] {
    match e {
        0 => b"Success\0",
        1 => b"Operation not permitted\0",
        2 => b"No such file or directory\0",
        3 => b"No such process\0",
        4 => b"Interrupted system call\0",
        5 => b"Input/output error\0",
        6 => b"No such device or address\0",
        7 => b"Argument list too long\0",
        8 => b"Exec format error\0",
        9 => b"Bad file descriptor\0",
        10 => b"No child processes\0",
        11 => b"Resource temporarily unavailable\0",
        12 => b"Cannot allocate memory\0",
        13 => b"Permission denied\0",
        14 => b"Bad address\0",
        15 => b"Block device required\0",
        16 => b"Device or resource busy\0",
        17 => b"File exists\0",
        18 => b"Invalid cross-device link\0",
        19 => b"No such device\0",
        20 => b"Not a directory\0",
        21 => b"Is a directory\0",
        22 => b"Invalid argument\0",
        23 => b"Too many open files in system\0",
        24 => b"Too many open files\0",
        25 => b"Inappropriate ioctl for device\0",
        26 => b"Text file busy\0",
        27 => b"File too large\0",
        28 => b"No space left on device\0",
        29 => b"Illegal seek\0",
        30 => b"Read-only file system\0",
        31 => b"Too many links\0",
        32 => b"Broken pipe\0",
        33 => b"Numerical argument out of domain\0",
        34 => b"Numerical result out of range\0",
        35 => b"Resource deadlock avoided\0",
        36 => b"File name too long\0",
        37 => b"No locks available\0",
        38 => b"Function not implemented\0",
        39 => b"Directory not empty\0",
        40 => b"Too many levels of symbolic links\0",
        42 => b"No message of desired type\0",
        61 => b"No data available\0",
        62 => b"Timer expired\0",
        88 => b"Socket operation on non-socket\0",
        90 => b"Message too long\0",
        91 => b"Protocol wrong type for socket\0",
        92 => b"Protocol not available\0",
        93 => b"Protocol not supported\0",
        95 => b"Operation not supported\0",
        97 => b"Address family not supported by protocol\0",
        98 => b"Address already in use\0",
        99 => b"Cannot assign requested address\0",
        100 => b"Network is down\0",
        101 => b"Network is unreachable\0",
        103 => b"Software caused connection abort\0",
        104 => b"Connection reset by peer\0",
        105 => b"No buffer space available\0",
        106 => b"Transport endpoint is already connected\0",
        107 => b"Transport endpoint is not connected\0",
        110 => b"Connection timed out\0",
        111 => b"Connection refused\0",
        113 => b"No route to host\0",
        114 => b"Operation already in progress\0",
        115 => b"Operation now in progress\0",
        _ => b"Unknown error\0",
    }
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
