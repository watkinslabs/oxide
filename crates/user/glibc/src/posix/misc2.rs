// More userspace syscall wrappers (docs/59§6 — G19 audit): chroot, fexecve,
// getdtablesize, daemon, and the SysV shm family. From the export-vs-vendor
// symbol audit. Thin wrappers; kernel structs pass through as pointers.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys1, sys3, sys5};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: int chroot(const char *path)
#[no_mangle]
pub unsafe extern "C" fn chroot(path: *const c_char) -> i32 {
    // SAFETY: path is a NUL-terminated user string the kernel reads.
    ret_isize(unsafe { sys1(nr::CHROOT, path as usize) }) as i32
}

// # C: int fexecve(int fd, char *const argv[], char *const envp[])
// Composed from execveat(fd, "", argv, envp, AT_EMPTY_PATH).
#[no_mangle]
pub unsafe extern "C" fn fexecve(fd: i32, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    let empty = b"\0".as_ptr();
    // SAFETY: fd is an open executable; argv/envp NULL-terminated arrays. The
    // empty path + AT_EMPTY_PATH (0x1000) makes execveat exec the fd itself.
    ret_isize(unsafe { sys5(nr::EXECVEAT, fd as usize, empty as usize, argv as usize, envp as usize, 0x1000) }) as i32
}

// # C: int getdtablesize(void) — RLIMIT_NOFILE soft limit (legacy).
#[no_mangle]
pub unsafe extern "C" fn getdtablesize() -> i32 {
    // SAFETY: prlimit64(0, RLIMIT_NOFILE=7, NULL, &rl) fills rl on this frame.
    unsafe {
        let mut rl = [0u64; 2]; // { rlim_cur, rlim_max }
        let r = crate::arch::syscall::sys4(nr::PRLIMIT64, 0, 7, 0, rl.as_mut_ptr() as usize);
        if r < 0 { 1024 } else { rl[0] as i32 }
    }
}

// # C: int daemon(int nochdir, int noclose)
#[no_mangle]
pub unsafe extern "C" fn daemon(nochdir: i32, noclose: i32) -> i32 {
    // SAFETY: fork (parent exits), setsid, optional chdir("/") + redirect
    // 0/1/2 to /dev/null. All operate on this process's own fds.
    unsafe {
        let p = crate::posix::process::fork();
        if p < 0 { return -1; }
        if p > 0 { crate::stdlib::exit::exit_group(0); }
        if crate::arch::syscall::sys1(nr::SETSID, 0) < 0 { return -1; }
        if nochdir == 0 { crate::arch::syscall::sys1(nr::CHDIR, b"/\0".as_ptr() as usize); }
        if noclose == 0 {
            let fd = crate::posix::io::open(b"/dev/null\0".as_ptr(), 2 /* O_RDWR */, 0);
            if fd >= 0 {
                crate::posix::fd::dup2(fd, 0); crate::posix::fd::dup2(fd, 1); crate::posix::fd::dup2(fd, 2);
                if fd > 2 { crate::posix::io::close(fd); }
            }
        }
        0
    }
}

// --- SysV shared memory -------------------------------------------------
// # C: int shmget(key_t key, size_t size, int shmflg)
#[no_mangle]
pub unsafe extern "C" fn shmget(key: i32, size: usize, shmflg: i32) -> i32 {
    // SAFETY: shmget(2) — scalar args, no user buffers.
    ret_isize(unsafe { sys3(nr::SHMGET, key as usize, size, shmflg as usize) }) as i32
}
// # C: void *shmat(int shmid, const void *shmaddr, int shmflg)
#[no_mangle]
pub unsafe extern "C" fn shmat(shmid: i32, shmaddr: *const c_void, shmflg: i32) -> *mut c_void {
    // SAFETY: shmat(2) maps the segment; returns the attach addr or (void*)-1.
    unsafe { sys3(nr::SHMAT, shmid as usize, shmaddr as usize, shmflg as usize) as *mut c_void }
}
// # C: int shmdt(const void *shmaddr)
#[no_mangle]
pub unsafe extern "C" fn shmdt(shmaddr: *const c_void) -> i32 {
    // SAFETY: shmaddr is an address returned by a prior shmat.
    ret_isize(unsafe { sys1(nr::SHMDT, shmaddr as usize) }) as i32
}
// # C: int shmctl(int shmid, int cmd, struct shmid_ds *buf)
#[no_mangle]
pub unsafe extern "C" fn shmctl(shmid: i32, cmd: i32, buf: *mut c_void) -> i32 {
    // SAFETY: buf is null or a struct shmid_ds the kernel reads/writes.
    ret_isize(unsafe { sys3(nr::SHMCTL, shmid as usize, cmd as usize, buf as usize) }) as i32
}
