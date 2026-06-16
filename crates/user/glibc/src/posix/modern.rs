// Modern Linux syscall wrappers (docs/59§6 §9.1): close_range/closefrom,
// getcpu, getdents64, getdirentries, renameat2, readahead, remap_file_pages,
// the new mount API (fsopen/fsconfig/fsmount/fspick), fanotify, pidfd,
// process_vm/madvise/mrelease, epoll_pwait2, ptrace, fallocate64, arch_prctl.
// Thin pass-throughs; kernel structs pass as pointers.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::arch::syscall::{sys2, sys3, sys4, sys5, sys6};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: int eaccess(const char *path, int mode) — access(2) by EFFECTIVE ids.
#[no_mangle]
pub unsafe extern "C" fn eaccess(path: *const c_char, mode: i32) -> i32 {
    const AT_FDCWD: usize = (-100i64) as usize;
    const AT_EACCESS: usize = 0x200;
    // SAFETY: path is a NUL-terminated user path; faccessat2 takes a flags arg,
    // and AT_EACCESS selects the effective uid/gid (vs access(2)'s real ids).
    ret_isize(unsafe { sys4(nr::FACCESSAT2, AT_FDCWD, path as usize, mode as usize, AT_EACCESS) }) as i32
}
// # C: int euidaccess(const char *path, int mode) — GNU alias of eaccess.
#[no_mangle]
pub unsafe extern "C" fn euidaccess(path: *const c_char, mode: i32) -> i32 {
    // SAFETY: identical to eaccess (effective-id access check).
    unsafe { eaccess(path, mode) }
}

// # C: int close_range(unsigned first, unsigned last, int flags)
#[no_mangle]
pub unsafe extern "C" fn close_range(first: u32, last: u32, flags: u32) -> i32 {
    // SAFETY: close_range(2) — scalar fd range + flags, no user buffers.
    ret_isize(unsafe { sys3(nr::CLOSE_RANGE, first as usize, last as usize, flags as usize) }) as i32
}
// # C: void closefrom(int lowfd) — BSD: close_range(lowfd, ~0u, 0), errors ignored.
#[no_mangle]
pub unsafe extern "C" fn closefrom(lowfd: i32) {
    // SAFETY: close every fd ≥ lowfd via close_range; the kernel ignores gaps.
    unsafe { sys3(nr::CLOSE_RANGE, lowfd as usize, u32::MAX as usize, 0); }
}
// # C: int getcpu(unsigned *cpu, unsigned *node)
#[no_mangle]
pub unsafe extern "C" fn getcpu(cpu: *mut u32, node: *mut u32) -> i32 {
    // SAFETY: cpu/node are null or writable u32 out-params the kernel fills;
    // the third (tcache) arg is obsolete and passed NULL.
    ret_isize(unsafe { sys3(nr::GETCPU, cpu as usize, node as usize, 0) }) as i32
}
// # C: ssize_t getdents64(int fd, void *buf, size_t count)
#[no_mangle]
pub unsafe extern "C" fn getdents64(fd: i32, buf: *mut c_void, count: usize) -> isize {
    // SAFETY: buf is a writable buffer of `count` bytes the kernel fills with
    // struct linux_dirent64 records.
    ret_isize(unsafe { sys3(nr::GETDENTS64, fd as usize, buf as usize, count) })
}
// # C: ssize_t getdirentries(int fd, char *buf, size_t nbytes, off_t *basep)
// glibc: record the pre-read offset in *basep, then getdents64.
#[no_mangle]
pub unsafe extern "C" fn getdirentries(fd: i32, buf: *mut c_char, nbytes: usize, basep: *mut i64) -> isize {
    // SAFETY: buf is `nbytes` writable; basep null or a writable off_t. We read
    // the current offset (lseek SEEK_CUR=1) into *basep before the getdents64.
    unsafe {
        if !basep.is_null() { *basep = crate::posix::io::lseek(fd, 0, 1); }
        ret_isize(sys3(nr::GETDENTS64, fd as usize, buf as usize, nbytes))
    }
}
// # C: ssize_t getdirentries64(...) — LFS alias on LP64.
// SAFETY: identical to getdirentries on LP64 (off64_t == off_t).
#[no_mangle] pub unsafe extern "C" fn getdirentries64(fd: i32, buf: *mut c_char, n: usize, basep: *mut i64) -> isize { unsafe { getdirentries(fd, buf, n, basep) } }

// # C: int renameat2(int olddfd, const char *old, int newdfd, const char *new, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn renameat2(olddfd: i32, old: *const c_char, newdfd: i32, new: *const c_char, flags: u32) -> i32 {
    // SAFETY: old/new are NUL-terminated user paths the kernel reads.
    ret_isize(unsafe { sys5(nr::RENAMEAT2, olddfd as usize, old as usize, newdfd as usize, new as usize, flags as usize) }) as i32
}
// # C: ssize_t readahead(int fd, off64_t offset, size_t count)
#[no_mangle]
pub unsafe extern "C" fn readahead(fd: i32, offset: i64, count: usize) -> isize {
    // SAFETY: readahead(2) — scalar fd/offset/count, no user buffers.
    ret_isize(unsafe { sys3(nr::READAHEAD, fd as usize, offset as usize, count) })
}
// # C: int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags)
#[no_mangle]
pub unsafe extern "C" fn remap_file_pages(addr: *mut c_void, size: usize, prot: i32, pgoff: usize, flags: i32) -> i32 {
    // SAFETY: addr names an existing mmap region; the kernel re-maps its pages.
    ret_isize(unsafe { sys5(nr::REMAP_FILE_PAGES, addr as usize, size, prot as usize, pgoff, flags as usize) }) as i32
}

// # C: int fallocate64(int fd, int mode, off64_t offset, off64_t len) — LFS alias.
// SAFETY: fallocate64 == fallocate on LP64; scalar args only.
#[no_mangle] pub unsafe extern "C" fn fallocate64(fd: i32, mode: i32, offset: i64, len: i64) -> i32 {
    ret_isize(unsafe { sys4(nr::FALLOCATE, fd as usize, mode as usize, offset as usize, len as usize) }) as i32
}

// --- new mount API ---------------------------------------------------------
// # C: int fsopen(const char *fsname, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn fsopen(fsname: *const c_char, flags: u32) -> i32 {
    // SAFETY: fsname is a NUL-terminated filesystem-type name the kernel reads.
    ret_isize(unsafe { sys2(nr::FSOPEN, fsname as usize, flags as usize) }) as i32
}
// # C: int fsconfig(int fd, unsigned cmd, const char *key, const void *value, int aux)
#[no_mangle]
pub unsafe extern "C" fn fsconfig(fd: i32, cmd: u32, key: *const c_char, value: *const c_void, aux: i32) -> i32 {
    // SAFETY: key/value are null or kernel-read buffers per the fsconfig cmd.
    ret_isize(unsafe { sys5(nr::FSCONFIG, fd as usize, cmd as usize, key as usize, value as usize, aux as usize) }) as i32
}
// # C: int fsmount(int fd, unsigned flags, unsigned ms_flags)
#[no_mangle]
pub unsafe extern "C" fn fsmount(fd: i32, flags: u32, ms_flags: u32) -> i32 {
    // SAFETY: fsmount(2) — scalar args; returns a new mount fd.
    ret_isize(unsafe { sys3(nr::FSMOUNT, fd as usize, flags as usize, ms_flags as usize) }) as i32
}
// # C: int fspick(int dfd, const char *path, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn fspick(dfd: i32, path: *const c_char, flags: u32) -> i32 {
    // SAFETY: path is a NUL-terminated user path the kernel reads.
    ret_isize(unsafe { sys3(nr::FSPICK, dfd as usize, path as usize, flags as usize) }) as i32
}

// --- fanotify --------------------------------------------------------------
// # C: int fanotify_init(unsigned flags, unsigned event_f_flags)
#[no_mangle]
pub unsafe extern "C" fn fanotify_init(flags: u32, event_f_flags: u32) -> i32 {
    // SAFETY: fanotify_init(2) — scalar flags; returns the notification fd.
    ret_isize(unsafe { sys2(nr::FANOTIFY_INIT, flags as usize, event_f_flags as usize) }) as i32
}
// # C: int fanotify_mark(int fd, unsigned flags, uint64_t mask, int dirfd, const char *path)
#[no_mangle]
pub unsafe extern "C" fn fanotify_mark(fd: i32, flags: u32, mask: u64, dirfd: i32, path: *const c_char) -> i32 {
    // SAFETY: path is null or a NUL-terminated user path; mask is a 64-bit
    // event mask passed in a single register on LP64.
    ret_isize(unsafe { sys5(nr::FANOTIFY_MARK, fd as usize, flags as usize, mask as usize, dirfd as usize, path as usize) }) as i32
}

// --- pidfd -----------------------------------------------------------------
// # C: int pidfd_open(pid_t pid, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn pidfd_open(pid: i32, flags: u32) -> i32 {
    // SAFETY: pidfd_open(2) — scalar args; returns a pidfd.
    ret_isize(unsafe { sys2(nr::PIDFD_OPEN, pid as usize, flags as usize) }) as i32
}
// # C: int pidfd_getfd(int pidfd, int targetfd, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn pidfd_getfd(pidfd: i32, targetfd: i32, flags: u32) -> i32 {
    // SAFETY: pidfd_getfd(2) — scalar args; duplicates a remote fd.
    ret_isize(unsafe { sys3(nr::PIDFD_GETFD, pidfd as usize, targetfd as usize, flags as usize) }) as i32
}
// # C: int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn pidfd_send_signal(pidfd: i32, sig: i32, info: *mut c_void, flags: u32) -> i32 {
    // SAFETY: info is null or a siginfo_t the kernel reads.
    ret_isize(unsafe { sys4(nr::PIDFD_SEND_SIGNAL, pidfd as usize, sig as usize, info as usize, flags as usize) }) as i32
}
// # C: pid_t pidfd_getpid(int pidfd) — pid the pidfd refers to (glibc 2.36).
// Reads /proc/self/fdinfo/<pidfd> and parses its "Pid:" line. Pid -1 (reaped) ⇒
// ESRCH; Pid 0 (foreign pid namespace) ⇒ EREMOTE.
#[no_mangle]
pub unsafe extern "C" fn pidfd_getpid(pidfd: i32) -> i32 {
    const ESRCH: i32 = 3; const EREMOTE: i32 = 66; const EBADF: i32 = 9;
    if pidfd < 0 { crate::internal::errno::set(EBADF); return -1; }
    // SAFETY: path/buf are local bounded arrays; the opened fdinfo fd is closed
    // before return; read fills at most buf.len()-1 bytes.
    unsafe {
        let mut path = *b"/proc/self/fdinfo/0000000000\0";
        let mut n = b"/proc/self/fdinfo/".len();
        if pidfd == 0 { path[n] = b'0'; n += 1; }
        else {
            let mut digits = [0u8; 10]; let mut d = 0; let mut v = pidfd as u32;
            while v > 0 { digits[d] = b'0' + (v % 10) as u8; v /= 10; d += 1; }
            while d > 0 { d -= 1; path[n] = digits[d]; n += 1; }
        }
        path[n] = 0;
        let fd = crate::posix::io::open(path.as_ptr(), 0 /* O_RDONLY */, 0);
        if fd < 0 { return -1; }
        let mut buf = [0u8; 512];
        let got = crate::posix::io::read(fd, buf.as_mut_ptr(), buf.len() - 1);
        crate::posix::io::close(fd);
        if got <= 0 { crate::internal::errno::set(EBADF); return -1; }
        let g = got as usize;
        let mut i = 0;
        while i + 4 <= g {
            if &buf[i..i + 4] == b"Pid:" {
                let mut j = i + 4;
                while j < g && (buf[j] == b' ' || buf[j] == b'\t') { j += 1; }
                let neg = j < g && buf[j] == b'-'; if neg { j += 1; }
                let mut val: i64 = 0;
                while j < g && buf[j].is_ascii_digit() { val = val * 10 + (buf[j] - b'0') as i64; j += 1; }
                let val = (if neg { -val } else { val }) as i32;
                if val == -1 { crate::internal::errno::set(ESRCH); return -1; }
                if val == 0 { crate::internal::errno::set(EREMOTE); return -1; }
                return val;
            }
            i += 1;
        }
        crate::internal::errno::set(EBADF); -1
    }
}

// --- cross-process memory --------------------------------------------------
// # C: ssize_t process_vm_readv(pid_t, const struct iovec *local, unsigned long liovcnt,
//                               const struct iovec *remote, unsigned long riovcnt, unsigned long flags)
#[no_mangle]
pub unsafe extern "C" fn process_vm_readv(pid: i32, local: *const c_void, liovcnt: usize, remote: *const c_void, riovcnt: usize, flags: usize) -> isize {
    // SAFETY: local/remote are iovec arrays; the kernel copies remote→local.
    ret_isize(unsafe { sys6(nr::PROCESS_VM_READV, pid as usize, local as usize, liovcnt, remote as usize, riovcnt, flags) })
}
// # C: ssize_t process_vm_writev(...)
#[no_mangle]
pub unsafe extern "C" fn process_vm_writev(pid: i32, local: *const c_void, liovcnt: usize, remote: *const c_void, riovcnt: usize, flags: usize) -> isize {
    // SAFETY: local/remote are iovec arrays; the kernel copies local→remote.
    ret_isize(unsafe { sys6(nr::PROCESS_VM_WRITEV, pid as usize, local as usize, liovcnt, remote as usize, riovcnt, flags) })
}
// # C: ssize_t process_madvise(int pidfd, const struct iovec *iov, size_t iovcnt, int advice, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn process_madvise(pidfd: i32, iov: *const c_void, iovcnt: usize, advice: i32, flags: u32) -> isize {
    // SAFETY: iov is an iovec array naming remote address ranges to advise.
    ret_isize(unsafe { sys5(nr::PROCESS_MADVISE, pidfd as usize, iov as usize, iovcnt, advice as usize, flags as usize) })
}
// # C: int process_mrelease(int pidfd, unsigned flags)
#[no_mangle]
pub unsafe extern "C" fn process_mrelease(pidfd: i32, flags: u32) -> i32 {
    // SAFETY: process_mrelease(2) — scalar args.
    ret_isize(unsafe { sys2(nr::PROCESS_MRELEASE, pidfd as usize, flags as usize) }) as i32
}

// # C: int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
//                       const struct timespec *timeout, const sigset_t *sigmask)
#[no_mangle]
pub unsafe extern "C" fn epoll_pwait2(epfd: i32, events: *mut c_void, maxevents: i32, timeout: *const c_void, sigmask: *const c_void) -> i32 {
    // SAFETY: events is a writable epoll_event array; timeout null or a timespec;
    // sigmask null or a sigset_t; the kernel sigsetsize (8) is the 6th arg.
    ret_isize(unsafe { sys6(nr::EPOLL_PWAIT2, epfd as usize, events as usize, maxevents as usize, timeout as usize, sigmask as usize, 8) }) as i32
}

// # C: long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data)
// PTRACE_PEEK{TEXT,DATA,USER} return the word via the syscall's data out-param.
#[no_mangle]
pub unsafe extern "C" fn ptrace(request: i32, pid: i32, addr: *mut c_void, data: *mut c_void) -> isize {
    // SAFETY: for PEEK requests the kernel writes the fetched word to a local
    // and we surface it; otherwise addr/data pass straight through.
    unsafe {
        if (1..=3).contains(&request) { // PEEKTEXT=1, PEEKDATA=2, PEEKUSER=3
            let mut word: usize = 0;
            let r = sys4(nr::PTRACE, request as usize, pid as usize, addr as usize, &mut word as *mut usize as usize);
            if r < 0 { return ret_isize(r); }
            word as isize
        } else {
            ret_isize(sys4(nr::PTRACE, request as usize, pid as usize, addr as usize, data as usize))
        }
    }
}

// # C: int arch_prctl(int code, unsigned long addr) — x86_64 only.
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn arch_prctl(code: i32, addr: usize) -> i32 {
    // SAFETY: arch_prctl(2) sets/gets FS/GS base; addr is a value or a writable
    // unsigned long out-param per `code`.
    ret_isize(unsafe { sys2(nr::ARCH_PRCTL, code as usize, addr) }) as i32
}
