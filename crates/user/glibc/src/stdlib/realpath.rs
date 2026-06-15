// realpath(3) (docs/59§6 G7). Canonicalises a path: makes it absolute (via
// getcwd), resolves "." and ".." lexically, and verifies the result exists
// (faccessat F_OK). Symlink resolution per component is a follow-up; the
// lexical+existence form matches glibc for symlink-free paths. C ABI only.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys2, sys4};
use crate::internal::{errno, nr};
use crate::string::len::strlen_impl;

const AT_FDCWD: usize = (-100i64) as usize;
const F_OK: usize = 0;
const PATH_MAX: usize = 4096;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;
const ENAMETOOLONG: i32 = 36;

// Canonicalise `abs` (a NUL-free byte slice that starts with '/') into `out`,
// resolving "." and "..". Returns the output length (out is not NUL-terminated).
fn canon(abs: &[u8], out: &mut [u8; PATH_MAX]) -> usize {
    out[0] = b'/';
    let mut olen = 1usize;
    let mut i = 1usize;
    while i < abs.len() {
        let mut j = i;
        while j < abs.len() && abs[j] != b'/' { j += 1; }
        let comp = &abs[i..j];
        if comp.is_empty() || comp == b"." {
            // skip
        } else if comp == b".." {
            // pop the last component (back to the previous '/')
            if olen > 1 {
                olen -= 1; // drop the trailing position
                while olen > 1 && out[olen - 1] != b'/' { olen -= 1; }
                if olen > 1 { olen -= 1; } // drop the separator too
                if olen == 0 { out[0] = b'/'; olen = 1; }
            }
        } else {
            if olen > 1 { out[olen] = b'/'; olen += 1; }
            else { olen = 1; } // root already has '/'
            for &c in comp { if olen < PATH_MAX { out[olen] = c; olen += 1; } }
        }
        i = j + 1;
    }
    if olen == 0 { out[0] = b'/'; olen = 1; }
    olen
}

// # C: char *realpath(const char *path, char *resolved_path)
#[no_mangle]
pub unsafe extern "C" fn realpath(path: *const u8, resolved: *mut u8) -> *mut u8 {
    extern "C" { fn malloc(n: usize) -> *mut core::ffi::c_void; }
    // SAFETY: path is null or a NUL-terminated C string; resolved is null or a
    // PATH_MAX buffer. We build an absolute path, canonicalise, verify F_OK.
    unsafe {
        if path.is_null() || *path == 0 { errno::set(EINVAL); return core::ptr::null_mut(); }
        let plen = strlen_impl(path);
        let mut abs = [0u8; PATH_MAX];
        let mut alen;
        if *path != b'/' {
            let r = sys2(nr::GETCWD, abs.as_mut_ptr() as usize, PATH_MAX);
            if r < 0 { errno::set(ENAMETOOLONG); return core::ptr::null_mut(); }
            alen = strlen_impl(abs.as_ptr());
            if alen + 1 + plen >= PATH_MAX { errno::set(ENAMETOOLONG); return core::ptr::null_mut(); }
            abs[alen] = b'/'; alen += 1;
        } else {
            abs[0] = b'/'; alen = 1;
        }
        if alen + plen >= PATH_MAX { errno::set(ENAMETOOLONG); return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(path, abs.as_mut_ptr().add(alen), plen);
        alen += plen;

        let mut out = [0u8; PATH_MAX];
        let olen = canon(&abs[..alen], &mut out);
        out[olen] = 0;

        // verify the resolved path exists
        if sys4(nr::FACCESSAT, AT_FDCWD, out.as_ptr() as usize, F_OK, 0) < 0 {
            errno::set(ENOENT);
            return core::ptr::null_mut();
        }
        let dst = if resolved.is_null() { malloc(olen + 1) as *mut u8 } else { resolved };
        if dst.is_null() { return core::ptr::null_mut(); }
        core::ptr::copy_nonoverlapping(out.as_ptr(), dst, olen);
        *dst.add(olen) = 0;
        dst
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonicalises() {
        let mut o = [0u8; PATH_MAX];
        let mk = |s: &[u8], o: &mut [u8; PATH_MAX]| { let n = canon(s, o); core::str::from_utf8(&o[..n]).unwrap().to_string() };
        assert_eq!(mk(b"/tmp/../tmp", &mut o), "/tmp");
        assert_eq!(mk(b"/a/b/../c", &mut o), "/a/c");
        assert_eq!(mk(b"/a/./b/", &mut o), "/a/b");
        assert_eq!(mk(b"/", &mut o), "/");
        assert_eq!(mk(b"/../..", &mut o), "/");
        assert_eq!(mk(b"/x/y/z/../../w", &mut o), "/x/w");
    }
}
