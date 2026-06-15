// <ftw.h> (docs/59§6) — ftw/nftw recursive directory tree walk. Shared walker
// over opendir/readdir + stat/lstat; pre-order by default, post-order (the
// visited dir last) for nftw FTW_DEPTH; FTW_PHYS uses lstat. C ABI only.
#![cfg(feature = "freestanding")]
use crate::posix::dirent::dirent;
use crate::posix::stat::stat;
use crate::string::len::strlen_impl;
use core::ffi::c_void;

extern "C" {
    fn opendir(p: *const u8) -> *mut c_void;
    fn readdir(d: *mut c_void) -> *mut dirent;
    fn closedir(d: *mut c_void) -> i32;
    fn stat(p: *const u8, b: *mut stat) -> i32;
    fn lstat(p: *const u8, b: *mut stat) -> i32;
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
// typeflags
const FTW_F: i32 = 0; const FTW_D: i32 = 1; const FTW_DNR: i32 = 2;
const FTW_NS: i32 = 3; const FTW_SL: i32 = 4; const FTW_DP: i32 = 5;
// nftw flags
const FTW_PHYS: i32 = 1; const FTW_DEPTH: i32 = 8;

#[repr(C)]
pub struct FTW { pub base: i32, pub level: i32 }

type Fn3 = extern "C" fn(*const u8, *const stat, i32) -> i32;
type Fn4 = extern "C" fn(*const u8, *const stat, i32, *mut FTW) -> i32;

fn zst() -> stat {
    // SAFETY: struct stat is all integer/pointer fields, so all-zero is a valid
    // initialised value to be overwritten by stat()/lstat().
    unsafe { core::mem::zeroed() }
}

fn call(cb3: Option<Fn3>, cb4: Option<Fn4>, p: *const u8, s: *const stat, flag: i32, base: i32, level: i32) -> i32 {
    // exactly one callback is set; invoke it with the entry info (calling a C
    // fn pointer is safe; the pointers it receives are the caller's contract).
    if let Some(f) = cb3 { f(p, s, flag) }
    else { let mut w = FTW { base, level }; (cb4.unwrap())(p, s, flag, &mut w) }
}

// Walk the tree rooted at the NUL-terminated path in `buf` (len bytes before
// the NUL). Returns the callback's nonzero stop code, or 0.
unsafe fn walk(buf: *mut u8, len: usize, level: i32, base: i32, flags: i32, cb3: Option<Fn3>, cb4: Option<Fn4>) -> i32 {
    // SAFETY: buf is a writable >=4096-byte path buffer NUL-terminated at len;
    // recursion depth bounded by the tree depth.
    unsafe {
        let mut st = zst();
        let phys = flags & FTW_PHYS != 0;
        let sr = if phys { lstat(buf, &mut st) } else { stat(buf, &mut st) };
        let is_dir = sr == 0 && (st.st_mode & S_IFMT) == S_IFDIR;
        let is_lnk = sr == 0 && (st.st_mode & S_IFMT) == S_IFLNK;
        let leaf_flag = if sr != 0 { FTW_NS } else if is_lnk { FTW_SL } else { FTW_F };
        let depth = flags & FTW_DEPTH != 0;

        if !is_dir && !depth { return call(cb3, cb4, buf, &st, leaf_flag, base, level); }
        if !is_dir { return call(cb3, cb4, buf, &st, leaf_flag, base, level); }

        // directory
        if !depth {
            let r = call(cb3, cb4, buf, &st, FTW_D, base, level);
            if r != 0 { return r; }
        }
        let d = opendir(buf);
        if d.is_null() {
            // unreadable dir → FTW_DNR (only meaningful pre-order)
            if !depth { return 0; }
            return call(cb3, cb4, buf, &st, FTW_DNR, base, level);
        }
        loop {
            let e = readdir(d);
            if e.is_null() { break; }
            let name = (*e).d_name.as_ptr();
            // skip "." and ".."
            if *name == b'.' && (*name.add(1) == 0 || (*name.add(1) == b'.' && *name.add(2) == 0)) { continue; }
            let nlen = strlen_impl(name);
            *buf.add(len) = b'/';
            core::ptr::copy_nonoverlapping(name, buf.add(len + 1), nlen);
            *buf.add(len + 1 + nlen) = 0;
            let r = walk(buf, len + 1 + nlen, level + 1, (len + 1) as i32, flags, cb3, cb4);
            *buf.add(len) = 0; // restore parent path
            if r != 0 { closedir(d); return r; }
        }
        closedir(d);
        if depth { return call(cb3, cb4, buf, &st, FTW_DP, base, level); }
        0
    }
}

unsafe fn run(path: *const u8, flags: i32, cb3: Option<Fn3>, cb4: Option<Fn4>) -> i32 {
    // SAFETY: path NUL-terminated; copy into a 4096 path buffer and walk.
    unsafe {
        let mut buf = [0u8; 4096];
        let plen = strlen_impl(path).min(4095);
        core::ptr::copy_nonoverlapping(path, buf.as_mut_ptr(), plen);
        buf[plen] = 0;
        // base = offset of the last path component
        let base = buf[..plen].iter().rposition(|&c| c == b'/').map_or(0, |i| i + 1);
        walk(buf.as_mut_ptr(), plen, 0, base as i32, flags, cb3, cb4)
    }
}

// # C: int ftw(const char *dirpath, int (*fn)(const char*, const struct stat*, int), int nopenfd)
#[no_mangle]
pub unsafe extern "C" fn ftw(path: *const u8, f: Fn3, _nopenfd: i32) -> i32 {
    // SAFETY: path NUL-terminated; f a valid ftw callback.
    unsafe { run(path, 0, Some(f), None) }
}
// # C: int nftw(const char *dirpath, fn, int nopenfd, int flags)
#[no_mangle]
pub unsafe extern "C" fn nftw(path: *const u8, f: Fn4, _nopenfd: i32, flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; f a valid nftw callback.
    unsafe { run(path, flags, None, Some(f)) }
}
