// <fstab.h> (docs/59§6) — /etc/fstab access. getfsent reads one entry per
// call into a process-global struct fstab whose string fields point into a
// mntent backed by a static line buffer; getfsfile/getfsspec scan from the
// start for a matching mount point / special file. fs_type is the FSTAB_*
// token (rw/ro/rq/sw/xx) found in fs_mntops, defaulting to "rw" (glibc
// fstab.c). C ABI only.
#![cfg(feature = "freestanding")]
use crate::posix::mntent::{getmntent, hasmntopt, mntent, setmntent};
use crate::stdio::file::FILE;
use crate::string::cmp::strcmp_impl;
use crate::string::len::strlen_impl;
use core::cell::UnsafeCell;

#[repr(C)]
pub struct fstab {
    pub fs_spec: *mut u8,
    pub fs_file: *mut u8,
    pub fs_vfstype: *mut u8,
    pub fs_mntops: *mut u8,
    pub fs_type: *const u8,
    pub fs_freq: i32,
    pub fs_passno: i32,
}

const _PATH_FSTAB: &[u8] = b"/etc/fstab\0";
const MODE_R: &[u8] = b"r\0";

// FSTAB_* tokens (host fstab.h); fs_type points at one of these static strings.
const FSTAB_RW: &[u8] = b"rw\0";
const FSTAB_RQ: &[u8] = b"rq\0";
const FSTAB_RO: &[u8] = b"ro\0";
const FSTAB_SW: &[u8] = b"sw\0";
// glibc fstab_convert returns the literal "??" when no rw/ro/rq/sw token is
// present in fs_mntops (it never returns FSTAB_XX as a default).
const FSTAB_UNKNOWN: &[u8] = b"??\0";

extern "C" {
    fn fclose(f: *mut FILE) -> i32;
}

struct Stream(UnsafeCell<*mut FILE>);
// SAFETY: process-global fstab stream handle; single-threaded until TLS lands.
unsafe impl Sync for Stream {}
static STREAM: Stream = Stream(UnsafeCell::new(core::ptr::null_mut()));

struct Ent(UnsafeCell<fstab>);
// SAFETY: process-global struct fstab returned by getfsent/getfsfile/getfsspec.
unsafe impl Sync for Ent {}
static ENT: Ent = Ent(UnsafeCell::new(fstab {
    fs_spec: core::ptr::null_mut(), fs_file: core::ptr::null_mut(),
    fs_vfstype: core::ptr::null_mut(), fs_mntops: core::ptr::null_mut(),
    fs_type: core::ptr::null(), fs_freq: 0, fs_passno: 0,
}));

// fs_type per glibc fstab_convert: first of RW/RQ/RO/SW present in mnt_opts
// (whole-option match via hasmntopt), else the literal "??".
unsafe fn derive_type(m: *const mntent) -> *const u8 {
    // SAFETY: m is a valid mntent; hasmntopt scans its comma-separated mnt_opts
    // for each FSTAB_* token in glibc's precedence order.
    unsafe {
        if !hasmntopt(m, FSTAB_RW.as_ptr()).is_null() { return FSTAB_RW.as_ptr(); }
        if !hasmntopt(m, FSTAB_RQ.as_ptr()).is_null() { return FSTAB_RQ.as_ptr(); }
        if !hasmntopt(m, FSTAB_RO.as_ptr()).is_null() { return FSTAB_RO.as_ptr(); }
        if !hasmntopt(m, FSTAB_SW.as_ptr()).is_null() { return FSTAB_SW.as_ptr(); }
        FSTAB_UNKNOWN.as_ptr()
    }
}

// Map a struct mntent (from getmntent) onto the process-global struct fstab.
unsafe fn from_mntent(m: *const mntent) -> *mut fstab {
    // SAFETY: m is a valid mntent whose fields point into the static line buffer;
    // we copy the field pointers into ENT and derive fs_type from fs_mntops.
    unsafe {
        let e = ENT.0.get();
        (*e).fs_spec = (*m).mnt_fsname;
        (*e).fs_file = (*m).mnt_dir;
        (*e).fs_vfstype = (*m).mnt_type;
        (*e).fs_mntops = (*m).mnt_opts;
        (*e).fs_type = derive_type(m);
        (*e).fs_freq = (*m).mnt_freq;
        (*e).fs_passno = (*m).mnt_passno;
        e
    }
}

// # C: int setfsent(void)
#[no_mangle]
pub unsafe extern "C" fn setfsent() -> i32 {
    // SAFETY: (re)open /etc/fstab, closing any prior stream. Returns 1 on
    // success / 0 on failure (glibc setfsent).
    unsafe {
        let s = STREAM.0.get();
        if !(*s).is_null() { fclose(*s); }
        *s = setmntent(_PATH_FSTAB.as_ptr(), MODE_R.as_ptr());
        if (*s).is_null() { 0 } else { 1 }
    }
}

// # C: void endfsent(void)
#[no_mangle]
pub unsafe extern "C" fn endfsent() {
    // SAFETY: close the open fstab stream (if any) and clear the handle.
    unsafe {
        let s = STREAM.0.get();
        if !(*s).is_null() { fclose(*s); *s = core::ptr::null_mut(); }
    }
}

// # C: struct fstab *getfsent(void)
#[no_mangle]
pub unsafe extern "C" fn getfsent() -> *mut fstab {
    // SAFETY: open the stream on first use (lazy setfsent), then read one
    // mntent line and map it into the static struct fstab; NULL at EOF.
    unsafe {
        let s = STREAM.0.get();
        if (*s).is_null() && setfsent() == 0 { return core::ptr::null_mut(); }
        let m = getmntent(*s);
        if m.is_null() { return core::ptr::null_mut(); }
        from_mntent(m)
    }
}

// # C: struct fstab *getfsfile(const char *name)
#[no_mangle]
pub unsafe extern "C" fn getfsfile(name: *const u8) -> *mut fstab {
    // SAFETY: name NUL-terminated; rewind and scan for the entry whose fs_file
    // (mount point) equals name. NULL when no match (glibc getfsfile).
    unsafe {
        let _ = strlen_impl(name); // validate readability
        if setfsent() == 0 { return core::ptr::null_mut(); }
        loop {
            let e = getfsent();
            if e.is_null() { return core::ptr::null_mut(); }
            if strcmp_impl((*e).fs_file, name) == 0 { return e; }
        }
    }
}

// # C: struct fstab *getfsspec(const char *name)
#[no_mangle]
pub unsafe extern "C" fn getfsspec(name: *const u8) -> *mut fstab {
    // SAFETY: name NUL-terminated; rewind and scan for the entry whose fs_spec
    // (special device) equals name. NULL when no match (glibc getfsspec).
    unsafe {
        let _ = strlen_impl(name);
        if setfsent() == 0 { return core::ptr::null_mut(); }
        loop {
            let e = getfsent();
            if e.is_null() { return core::ptr::null_mut(); }
            if strcmp_impl((*e).fs_spec, name) == 0 { return e; }
        }
    }
}
