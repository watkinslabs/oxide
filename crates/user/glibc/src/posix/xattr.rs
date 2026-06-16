// Extended attributes (docs/59§6 — G19 userspace; coreutils -Z/cp -a, ls,
// systemd, libcap). 12 thin syscall wrappers: {set,get,list,remove}xattr each
// in plain / l (don't follow symlink) / f (by fd) forms. value/list/name pass
// through as raw byte pointers the kernel reads/writes.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys2, sys3, sys4, sys5};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

macro_rules! set { ($f:ident, $nr:ident) => {
    // # C: int $f(const char *path, const char *name, const void *value, size_t size, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn $f(path: *const c_char, name: *const c_char, value: *const c_void, size: usize, flags: i32) -> i32 {
        // SAFETY: path/name NUL-terminated, value a `size`-byte buffer the kernel reads.
        ret_isize(unsafe { sys5(nr::$nr, path as usize, name as usize, value as usize, size, flags as usize) }) as i32
    }
}}
macro_rules! fset { ($f:ident, $nr:ident) => {
    // # C: int $f(int fd, const char *name, const void *value, size_t size, int flags)
    #[no_mangle]
    pub unsafe extern "C" fn $f(fd: i32, name: *const c_char, value: *const c_void, size: usize, flags: i32) -> i32 {
        // SAFETY: name NUL-terminated, value a `size`-byte buffer the kernel reads.
        ret_isize(unsafe { sys5(nr::$nr, fd as usize, name as usize, value as usize, size, flags as usize) }) as i32
    }
}}
macro_rules! get { ($f:ident, $nr:ident) => {
    // # C: ssize_t $f(const char *path, const char *name, void *value, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn $f(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize {
        // SAFETY: path/name NUL-terminated, value a writable `size`-byte buffer.
        unsafe { ret_isize(sys4(nr::$nr, path as usize, name as usize, value as usize, size)) }
    }
}}
macro_rules! fget { ($f:ident, $nr:ident) => {
    // # C: ssize_t $f(int fd, const char *name, void *value, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn $f(fd: i32, name: *const c_char, value: *mut c_void, size: usize) -> isize {
        // SAFETY: name NUL-terminated, value a writable `size`-byte buffer.
        unsafe { ret_isize(sys4(nr::$nr, fd as usize, name as usize, value as usize, size)) }
    }
}}
macro_rules! list { ($f:ident, $nr:ident) => {
    // # C: ssize_t $f(const char *path, char *list, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn $f(path: *const c_char, list: *mut c_char, size: usize) -> isize {
        // SAFETY: path NUL-terminated, list a writable `size`-byte buffer.
        unsafe { ret_isize(sys3(nr::$nr, path as usize, list as usize, size)) }
    }
}}
macro_rules! flist { ($f:ident, $nr:ident) => {
    // # C: ssize_t $f(int fd, char *list, size_t size)
    #[no_mangle]
    pub unsafe extern "C" fn $f(fd: i32, list: *mut c_char, size: usize) -> isize {
        // SAFETY: list a writable `size`-byte buffer.
        unsafe { ret_isize(sys3(nr::$nr, fd as usize, list as usize, size)) }
    }
}}
macro_rules! rm { ($f:ident, $nr:ident) => {
    // # C: int $f(const char *path, const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn $f(path: *const c_char, name: *const c_char) -> i32 {
        // SAFETY: path/name NUL-terminated user strings.
        ret_isize(unsafe { sys2(nr::$nr, path as usize, name as usize) }) as i32
    }
}}
macro_rules! frm { ($f:ident, $nr:ident) => {
    // # C: int $f(int fd, const char *name)
    #[no_mangle]
    pub unsafe extern "C" fn $f(fd: i32, name: *const c_char) -> i32 {
        // SAFETY: name NUL-terminated user string.
        ret_isize(unsafe { sys2(nr::$nr, fd as usize, name as usize) }) as i32
    }
}}

set!(setxattr, SETXATTR);     set!(lsetxattr, LSETXATTR);     fset!(fsetxattr, FSETXATTR);
get!(getxattr, GETXATTR);     get!(lgetxattr, LGETXATTR);     fget!(fgetxattr, FGETXATTR);
list!(listxattr, LISTXATTR);  list!(llistxattr, LLISTXATTR);  flist!(flistxattr, FLISTXATTR);
rm!(removexattr, REMOVEXATTR); rm!(lremovexattr, LREMOVEXATTR); frm!(fremovexattr, FREMOVEXATTR);
