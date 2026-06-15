// Low-level unistd I/O (docs/59§6; write/read needed by G2 hello, full
// posix io family at G8). libc convention: on error return -1 + set
// errno (internal::errno::ret_isize).

// # C: ssize_t write(int fd, const void *buf, size_t n)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, n: usize) -> isize {
    // SAFETY: write(2); the kernel validates [buf, buf+n) against the
    // caller's address space and faults rather than corrupting libc.
    let r = unsafe { crate::arch::syscall::sys3(crate::internal::nr::WRITE, fd as usize, buf as usize, n) };
    crate::internal::errno::ret_isize(r)
}

// # C: ssize_t read(int fd, void *buf, size_t n)
#[cfg(feature = "freestanding")]
#[no_mangle]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, n: usize) -> isize {
    // SAFETY: read(2); the kernel validates [buf, buf+n) is writable in
    // the caller's address space before storing.
    let r = unsafe { crate::arch::syscall::sys3(crate::internal::nr::READ, fd as usize, buf as usize, n) };
    crate::internal::errno::ret_isize(r)
}
