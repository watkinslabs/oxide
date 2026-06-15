// libgen.h — POSIX basename(3) / dirname(3) (docs/59§6 G8). These may modify
// the input string in place and return a pointer into it (or a static "."/"/"),
// per POSIX. Pure inner logic hosted-tested; the C ABI is freestanding.
// (The GNU basename in <string.h> is a separate, non-modifying function;
// libgen.h's POSIX basename is exported as __xpg_basename.)

/// POSIX basename: last path component. Empty/NULL → ".". Trailing slashes
/// stripped; all-slashes → "/". Returns the start offset + new length (the
/// component lives within `p` after in-place truncation of trailing slashes).
/// # C: char *basename(char *path)
pub(crate) fn basename_range(p: &[u8]) -> (&'static [u8], usize, usize) {
    // returns (override, start, len): if override non-empty use it ("." or "/")
    if p.is_empty() { return (b".", 0, 0); }
    let mut end = p.len();
    while end > 1 && p[end - 1] == b'/' { end -= 1; }
    if end == 1 && p[0] == b'/' { return (b"/", 0, 0); }
    let mut start = end;
    while start > 0 && p[start - 1] != b'/' { start -= 1; }
    (b"", start, end - start)
}

/// POSIX dirname: parent directory. No slash → ".". Returns the truncated
/// length, or an override ("." or "/").
/// # C: char *dirname(char *path)
pub(crate) fn dirname_len(p: &[u8]) -> (&'static [u8], usize) {
    if p.is_empty() { return (b".", 0); }
    let mut end = p.len();
    while end > 1 && p[end - 1] == b'/' { end -= 1; } // strip trailing slashes
    // find last slash before the final component
    let mut i = end;
    while i > 0 && p[i - 1] != b'/' { i -= 1; }
    if i == 0 { return (b".", 0); } // no slash at all
    // strip the slash(es) separating dir from base
    let mut d = i;
    while d > 1 && p[d - 1] == b'/' { d -= 1; }
    if d == 1 && p[0] == b'/' { return (b"/", 1); }
    (b"", d)
}

#[cfg(feature = "freestanding")]
#[allow(clippy::manual_c_str_literals)] // byte literals are arch-portable (c_char signedness)
mod imp {
    use super::*;
    use crate::string::len::strlen_impl;

    // # C: char *__xpg_basename(char *path)  (POSIX basename)
    #[no_mangle]
    pub unsafe extern "C" fn __xpg_basename(path: *mut u8) -> *mut u8 {
        // SAFETY: path is null or a NUL-terminated, writable C string; the
        // returned pointer is into it or a static literal.
        unsafe {
            if path.is_null() { return c_dot(); }
            let n = strlen_impl(path);
            let (ovr, start, len) = basename_range(core::slice::from_raw_parts(path, n));
            if !ovr.is_empty() { return if ovr[0] == b'/' { c_slash() } else { c_dot() }; }
            *path.add(start + len) = 0; // truncate trailing slashes
            path.add(start)
        }
    }
    // # C: char *dirname(char *path)
    #[no_mangle]
    pub unsafe extern "C" fn dirname(path: *mut u8) -> *mut u8 {
        // SAFETY: path is null or a NUL-terminated, writable C string.
        unsafe {
            if path.is_null() { return c_dot(); }
            let n = strlen_impl(path);
            let (ovr, end) = dirname_len(core::slice::from_raw_parts(path, n));
            if !ovr.is_empty() { return if ovr[0] == b'/' { c_slash() } else { c_dot() }; }
            *path.add(end) = 0;
            path
        }
    }

    fn c_dot() -> *mut u8 { b".\0".as_ptr() as *mut u8 }
    fn c_slash() -> *mut u8 { b"/\0".as_ptr() as *mut u8 }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths() {
        assert_eq!(basename_range(b"/usr/local/bin/prog"), (&b""[..], 15, 4)); // "prog"
        assert_eq!(basename_range(b"noslash"), (&b""[..], 0, 7));
        assert_eq!(basename_range(b"/"), (&b"/"[..], 0, 0));
        assert_eq!(basename_range(b"/a/b/"), (&b""[..], 3, 1)); // "b"
        assert_eq!(dirname_len(b"/usr/local/bin/prog"), (&b""[..], 14)); // "/usr/local/bin"
        assert_eq!(dirname_len(b"noslash"), (&b"."[..], 0));
        assert_eq!(dirname_len(b"/"), (&b"/"[..], 1));
        assert_eq!(dirname_len(b"/usr/"), (&b"/"[..], 1)); // "/usr/" → "/"... actually "/"
    }
}
