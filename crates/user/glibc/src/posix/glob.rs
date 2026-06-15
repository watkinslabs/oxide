// glob / globfree (docs/59§6 G8). Single-directory globbing: split the
// pattern at the last '/', readdir the (literal) directory part and
// fnmatch each entry against the last component. Multi-wildcard-component
// patterns (e.g. /a*/b*) are a tracked follow-up. glob_t matches the
// glibc layout (sizeof 72) incl the GLOB_ALTDIRFUNC fn-ptr fields we
// don't use. Smoke-verified (glob("/dev/n*")).
#![cfg(feature = "freestanding")]
#![allow(clippy::manual_c_str_literals)]

use crate::malloc::heap;
use crate::posix::fnmatch::fnmatch_slice;
use crate::string::len::strlen_impl;
use core::ffi::c_void;

#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
pub struct glob_t {
    pub gl_pathc: usize,
    pub gl_pathv: *mut *mut u8,
    pub gl_offs: usize,
    gl_flags: i32,
    gl_closedir: usize,
    gl_readdir: usize,
    gl_opendir: usize,
    gl_lstat: usize,
    gl_stat: usize,
}
const _: () = assert!(core::mem::size_of::<glob_t>() == 72);

const GLOB_MARK: i32 = 2;
const GLOB_NOSORT: i32 = 4;
const GLOB_DOOFFS: i32 = 8;
const GLOB_NOCHECK: i32 = 16;
const GLOB_APPEND: i32 = 32;
const GLOB_NOESCAPE: i32 = 64;
const GLOB_NOMATCH: i32 = 3;
const GLOB_NOSPACE: i32 = 1;
const FNM_PERIOD: i32 = 4;
const FNM_NOESCAPE: i32 = 2;

unsafe fn dup_range(prefix: *const u8, plen: usize, name: *const u8, nlen: usize) -> *mut u8 {
    // SAFETY: prefix[..plen] and name[..nlen] are readable; allocate the
    // concatenation + NUL.
    unsafe {
        let p = heap::malloc(plen + nlen + 1);
        if p.is_null() { return p; }
        core::ptr::copy_nonoverlapping(prefix, p, plen);
        core::ptr::copy_nonoverlapping(name, p.add(plen), nlen);
        *p.add(plen + nlen) = 0;
        p
    }
}

extern "C" fn cmp_pathptr(a: *const c_void, b: *const c_void) -> i32 {
    // SAFETY: a/b point at char* elements of the gl_pathv array.
    unsafe {
        let pa = *(a as *const *const u8);
        let pb = *(b as *const *const u8);
        crate::string::cmp::strcmp_impl(pa, pb)
    }
}

// # C: int glob(const char *pattern, int flags, errfn, glob_t *pglob)
#[no_mangle]
pub unsafe extern "C" fn glob(pattern: *const u8, flags: i32, _errfunc: *const c_void, pglob: *mut glob_t) -> i32 {
    // SAFETY: pattern NUL-terminated; pglob a valid glob_t. We open the
    // literal dir part and fnmatch entries against the last component.
    unsafe {
        let plen = strlen_impl(pattern);
        // split at last '/'
        let mut slash: isize = -1;
        for i in 0..plen { if *pattern.add(i) == b'/' { slash = i as isize; } }
        let (dir_open, prefix_len, base, base_len) = if slash < 0 {
            (b".\0".as_ptr(), 0usize, pattern, plen)
        } else {
            let s = slash as usize;
            // opendir path: pattern[..s] or "/" if s==0
            let dpath = if s == 0 { b"/\0".as_ptr() } else {
                // need a NUL-terminated copy of pattern[..s]
                let d = heap::malloc(s + 1);
                if d.is_null() { return GLOB_NOSPACE; }
                core::ptr::copy_nonoverlapping(pattern, d, s);
                *d.add(s) = 0;
                d as *const u8
            };
            (dpath, s + 1, pattern.add(s + 1), plen - s - 1)
        };

        let dirp = crate::posix::dirent::opendir(dir_open);
        // collect matches into a growable array
        let mut cap = 16usize;
        let mut arr = heap::malloc(cap * 8) as *mut *mut u8;
        let mut n = 0usize;
        let fnm_flags = FNM_PERIOD | if flags & GLOB_NOESCAPE != 0 { FNM_NOESCAPE } else { 0 };
        if !dirp.is_null() {
            let base_slice = core::slice::from_raw_parts(base, base_len);
            loop {
                let e = crate::posix::dirent::readdir(dirp);
                if e.is_null() { break; }
                let name = (*e).d_name.as_ptr();
                let nlen = strlen_impl(name);
                if fnmatch_slice(base_slice, core::slice::from_raw_parts(name, nlen), fnm_flags) {
                    let full = dup_range(pattern, prefix_len, name, nlen);
                    if full.is_null() { break; }
                    if n == cap { cap *= 2; arr = heap::realloc(arr as *mut u8, cap * 8) as *mut *mut u8; }
                    *arr.add(n) = full;
                    n += 1;
                }
            }
            crate::posix::dirent::closedir(dirp);
        }

        if n == 0 {
            if flags & GLOB_NOCHECK != 0 {
                let lit = dup_range(pattern, plen, b"\0".as_ptr(), 0);
                *arr.add(0) = lit;
                n = 1;
            } else {
                heap::free(arr as *mut u8);
                return GLOB_NOMATCH;
            }
        }

        if flags & GLOB_NOSORT == 0 {
            crate::stdlib::sort::qsort_impl(arr as *mut u8, n, 8, cmp_pathptr);
        }
        if flags & GLOB_MARK != 0 { mark_dirs(arr, n); }

        // assemble gl_pathv (DOOFFS slots + APPEND old + new + NULL)
        let offs = if flags & GLOB_DOOFFS != 0 { (*pglob).gl_offs } else { 0 };
        let (old_c, old_v) = if flags & GLOB_APPEND != 0 { ((*pglob).gl_pathc, (*pglob).gl_pathv) } else { (0, core::ptr::null_mut()) };
        let total = offs + old_c + n;
        let outv = heap::malloc((total + 1) * 8) as *mut *mut u8;
        if outv.is_null() { heap::free(arr as *mut u8); return GLOB_NOSPACE; }
        let mut w = 0usize;
        for _ in 0..offs { *outv.add(w) = core::ptr::null_mut(); w += 1; }
        for i in 0..old_c { *outv.add(w) = *old_v.add(offs + i); w += 1; }
        for i in 0..n { *outv.add(w) = *arr.add(i); w += 1; }
        *outv.add(w) = core::ptr::null_mut();
        heap::free(arr as *mut u8);
        if flags & GLOB_APPEND != 0 && !old_v.is_null() { heap::free(old_v as *mut u8); }

        (*pglob).gl_pathc = old_c + n;
        (*pglob).gl_pathv = outv;
        (*pglob).gl_offs = offs;
        0
    }
}

unsafe fn mark_dirs(arr: *mut *mut u8, n: usize) {
    // SAFETY: arr[0..n] are malloc'd path strings; append '/' to dirs.
    unsafe {
        for i in 0..n {
            let p = *arr.add(i);
            let len = strlen_impl(p);
            let mut st = [0u8; 160]; // struct stat is 144 (x86_64) / 128 (aarch64)
            if crate::posix::stat::stat_raw(p, st.as_mut_ptr()) == 0 {
                let mode = stat_mode(&st);
                if mode & 0o170000 == 0o040000 {
                    let np = heap::realloc(p, len + 2);
                    if !np.is_null() { *np.add(len) = b'/'; *np.add(len + 1) = 0; *arr.add(i) = np; }
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn stat_mode(st: &[u8; 160]) -> u32 {
    // st_mode @24 on x86_64
    u32::from_ne_bytes([st[24], st[25], st[26], st[27]])
}
#[cfg(not(target_arch = "x86_64"))]
fn stat_mode(st: &[u8; 160]) -> u32 {
    // st_mode @16 on aarch64
    u32::from_ne_bytes([st[16], st[17], st[18], st[19]])
}

// # C: void globfree(glob_t *pglob)
#[no_mangle]
pub unsafe extern "C" fn globfree(pglob: *mut glob_t) {
    // SAFETY: pglob was filled by glob(); free each path + the vector.
    unsafe {
        if pglob.is_null() || (*pglob).gl_pathv.is_null() { return; }
        let v = (*pglob).gl_pathv;
        let offs = (*pglob).gl_offs;
        for i in 0..(*pglob).gl_pathc { heap::free(*v.add(offs + i)); }
        heap::free(v as *mut u8);
        (*pglob).gl_pathv = core::ptr::null_mut();
        (*pglob).gl_pathc = 0;
    }
}
