// More userspace syscall wrappers (docs/59§6 — G19 audit): chroot, fexecve,
// getdtablesize, daemon, and the SysV shm family. From the export-vs-vendor
// symbol audit. Thin wrappers; kernel structs pass through as pointers.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys1, sys3, sys4, sys5};
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

// # C: int futimesat(int dirfd, const char *path, const struct timeval times[2])
// Composed from utimensat (timeval µs → timespec ns; NULL times = now).
#[no_mangle]
pub unsafe extern "C" fn futimesat(dirfd: i32, path: *const c_char, times: *const [i64; 2]) -> i32 {
    // SAFETY: path NUL-terminated; times null or two timevals {sec,usec}.
    // ts[2] lives on this frame for the utimensat(2) call.
    unsafe {
        if times.is_null() {
            return ret_isize(sys4(nr::UTIMENSAT, dirfd as usize, path as usize, 0, 0)) as i32;
        }
        let tv = &*(times as *const [[i64; 2]; 2]);
        let ts = [[tv[0][0], tv[0][1] * 1000], [tv[1][0], tv[1][1] * 1000]];
        ret_isize(sys4(nr::UTIMENSAT, dirfd as usize, path as usize, ts.as_ptr() as usize, 0)) as i32
    }
}

// # C: int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)
#[no_mangle]
pub unsafe extern "C" fn waitid(idtype: i32, id: u32, infop: *mut c_void, options: i32) -> i32 {
    // SAFETY: infop is null or a writable siginfo_t the kernel fills; the 5th
    // waitid(2) arg (rusage) is NULL.
    ret_isize(unsafe { sys5(nr::WAITID, idtype as usize, id as usize, infop as usize, options as usize, 0) }) as i32
}

// --- legacy / deprecated syscall wrappers ----------------------------------
const ENOSYS: i32 = 38;
const EINVAL: i32 = 22;

// # C: int revoke(const char *path) — no Linux syscall; glibc stub ⇒ ENOSYS.
#[no_mangle]
pub unsafe extern "C" fn revoke(_path: *const c_char) -> i32 {
    crate::internal::errno::set(ENOSYS); -1
}

// # C: int setlogin(const char *name) — BSD login-name setter; glibc stub.
#[no_mangle]
pub unsafe extern "C" fn setlogin(_name: *const c_char) -> i32 {
    crate::internal::errno::set(ENOSYS); -1
}

// # C: int chflags(const char *path, unsigned long flags) — glibc stub.
#[no_mangle]
pub unsafe extern "C" fn chflags(_path: *const c_char, _flags: u64) -> i32 {
    crate::internal::errno::set(ENOSYS); -1
}

// # C: int fchflags(int fd, unsigned long flags) — glibc stub.
#[no_mangle]
pub extern "C" fn fchflags(_fd: i32, _flags: u64) -> i32 {
    crate::internal::errno::set(EINVAL); -1
}

// # C: int profil(unsigned short *sample_buffer, size_t size, size_t offset, unsigned int scale)
#[no_mangle]
pub unsafe extern "C" fn profil(_sample_buffer: *mut u16, _size: usize, _offset: usize, _scale: u32) -> i32 { 0 }

// # C: int sprofil(struct prof *profp, int profcnt, struct timeval *tvp, unsigned int flags)
#[no_mangle]
pub unsafe extern "C" fn sprofil(_profp: *mut c_void, _profcnt: i32, _tvp: *mut c_void, _flags: u32) -> i32 { 0 }

// # C: void monstartup(unsigned long lowpc, unsigned long highpc)
#[no_mangle]
pub extern "C" fn monstartup(_lowpc: usize, _highpc: usize) {}

// # C: void moncontrol(int mode)
#[no_mangle]
pub extern "C" fn moncontrol(_mode: i32) {}

// # C: void mcount(void)
#[no_mangle]
pub extern "C" fn mcount() {}

// # C: int ustat(dev_t dev, struct ustat *ubuf) — deprecated; x86_64 only.
#[no_mangle]
pub unsafe extern "C" fn ustat(dev: u64, ubuf: *mut c_void) -> i32 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: ustat(2); ubuf is a writable struct ustat the kernel fills.
    { ret_isize(unsafe { crate::arch::syscall::sys2(nr::USTAT, dev as usize, ubuf as usize) }) as i32 }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = (dev, ubuf); crate::internal::errno::set(ENOSYS); -1 }
}

// # C: int uselib(const char *library) — obsolete; x86_64 only, else ENOSYS.
#[no_mangle]
pub unsafe extern "C" fn uselib(library: *const c_char) -> i32 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: uselib(2); library is a NUL-terminated path the kernel reads.
    { ret_isize(unsafe { sys1(nr::USELIB, library as usize) }) as i32 }
    #[cfg(not(target_arch = "x86_64"))]
    { let _ = library; crate::internal::errno::set(ENOSYS); -1 }
}

// # C: int modify_ldt(int func, void *ptr, unsigned long bytecount) — x86 only.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn modify_ldt(func: i32, ptr: *mut c_void, bytecount: u64) -> i32 {
    // SAFETY: modify_ldt(2); ptr is a user_desc buffer of bytecount bytes.
    ret_isize(unsafe { sys3(nr::MODIFY_LDT, func as usize, ptr as usize, bytecount as usize) }) as i32
}

// # C: int iopl(int level) — x86 I/O privilege level (needs CAP_SYS_RAWIO).
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn iopl(level: i32) -> i32 {
    // SAFETY: iopl(2) takes a scalar level; dereferences no memory.
    ret_isize(unsafe { sys1(nr::IOPL, level as usize) }) as i32
}

// # C: int ioperm(unsigned long from, unsigned long num, int turn_on) — x86.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn ioperm(from: u64, num: u64, turn_on: i32) -> i32 {
    // SAFETY: ioperm(2) takes scalar port range + flag; dereferences no memory.
    ret_isize(unsafe { sys3(nr::IOPERM, from as usize, num as usize, turn_on as usize) }) as i32
}
