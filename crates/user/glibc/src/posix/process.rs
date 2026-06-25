// Process control (docs/59§6 G8): fork/vfork, the exec* family, wait*,
// and system(). Syscall wrappers — smoke-verified (fork+exec+wait of a
// real binary), not unit-tested (forking the test process is unsafe).
#![cfg(feature = "freestanding")]
// b"..\0" literals are already *const u8 (no arch-varying c_char cast).
#![allow(clippy::manual_c_str_literals)]
use crate::arch::syscall::{sys3, sys4, sys5};
use crate::internal::errno::ret_isize;
use crate::internal::nr;
use crate::stdlib::env::current_environ;
use crate::stdlib::exit::exit_group;
use crate::string::len::strlen_impl;
use core::ffi::{c_void, VaList};

const SIGCHLD: usize = 17; // same on x86_64 + aarch64

#[cfg(target_arch = "x86_64")]
unsafe fn do_fork() -> isize {
    // SAFETY: raw fork(2); child + parent return per the kernel ABI.
    unsafe { crate::arch::syscall::sys0(nr::FORK) }
}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn do_fork() -> isize {
    // SAFETY: aarch64 has no fork; clone(SIGCHLD) with stack=0 = fork.
    unsafe { crate::arch::syscall::sys5(nr::CLONE, SIGCHLD, 0, 0, 0, 0) }
}

// # C: pid_t fork(void)
#[no_mangle]
pub unsafe extern "C" fn fork() -> i32 {
    // SAFETY: run pthread_atfork prepare handlers (lock held across the fork),
    // do_fork, then run parent/child handlers (releasing the lock) per side; on
    // fork error release the lock without running post handlers.
    unsafe {
        crate::pthread::atfork::run_prepare();
        let r = ret_isize(do_fork()) as i32;
        if r < 0 { crate::pthread::atfork::abort_unlock(); }
        else if r == 0 { crate::pthread::atfork::run_child(); }
        else { crate::pthread::atfork::run_parent(); }
        r
    }
}

// # C: pid_t _Fork(void) — async-signal-safe fork without atfork handlers.
#[no_mangle]
pub unsafe extern "C" fn _Fork() -> i32 {
    // SAFETY: raw fork-like syscall; caller observes parent/child returns.
    ret_isize(unsafe { do_fork() }) as i32
}

// # C: pid_t __fork(void) — glibc compatibility alias.
#[no_mangle]
pub unsafe extern "C" fn __fork() -> i32 {
    // SAFETY: __fork has the same ABI and preconditions as fork.
    unsafe { fork() }
}

// # C: pid_t __libc_fork(void) — glibc internal compatibility alias.
#[no_mangle]
pub unsafe extern "C" fn __libc_fork() -> i32 {
    // SAFETY: __libc_fork has the same ABI and preconditions as fork.
    unsafe { fork() }
}

// # C: pid_t vfork(void) — implemented as fork (POSIX-permitted).
#[no_mangle]
pub unsafe extern "C" fn vfork() -> i32 {
    // SAFETY: fork is a valid vfork implementation (no shared address space).
    ret_isize(unsafe { do_fork() }) as i32
}

// # C: pid_t __vfork(void) — glibc compatibility alias.
#[no_mangle]
pub unsafe extern "C" fn __vfork() -> i32 {
    // SAFETY: __vfork has the same ABI and preconditions as vfork.
    unsafe { vfork() }
}

// # C: int execve(const char *path, char *const argv[], char *const envp[])
#[no_mangle]
pub unsafe extern "C" fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i32 {
    // SAFETY: path NUL-terminated; argv/envp NULL-terminated pointer arrays.
    ret_isize(unsafe { sys3(nr::EXECVE, path as usize, argv as usize, envp as usize) }) as i32
}
// # C: int execveat(int dirfd, const char *path, char *const argv[], char *const envp[], int flags)
#[no_mangle]
pub unsafe extern "C" fn execveat(dirfd: i32, path: *const u8, argv: *const *const u8, envp: *const *const u8, flags: i32) -> i32 {
    // SAFETY: execveat(2); path resolved relative to dirfd (AT_EMPTY_PATH ⇒ dirfd
    // itself). argv/envp NULL-terminated pointer arrays; only returns on error.
    ret_isize(unsafe { sys5(nr::EXECVEAT, dirfd as usize, path as usize, argv as usize, envp as usize, flags as usize) }) as i32
}
// # C: int execv(const char *path, char *const argv[])
#[no_mangle]
pub unsafe extern "C" fn execv(path: *const u8, argv: *const *const u8) -> i32 {
    // SAFETY: forwards to execve with the current environ.
    unsafe { execve(path, argv, current_environ() as *const *const u8) }
}

unsafe fn has_slash(p: *const u8) -> bool {
    // SAFETY: p is NUL-terminated; scan stops at the terminator.
    unsafe { let mut i = 0; loop { let c = *p.add(i); if c == 0 { return false; } else if c == b'/' { return true; } i += 1; } }
}

// # C: int execvp(const char *file, char *const argv[]) — PATH search
#[no_mangle]
pub unsafe extern "C" fn execvp(file: *const u8, argv: *const *const u8) -> i32 {
    // SAFETY: file NUL-terminated; argv a NULL-terminated array. We try
    // each PATH dir into a stack buffer, execve'ing until one succeeds.
    unsafe {
        if has_slash(file) { return execv(file, argv); }
        let env = current_environ() as *const *const u8;
        let path = {
            let p = crate::stdlib::env::find_env(env, b"PATH\0".as_ptr(), 4);
            if p.is_null() { b"/bin:/usr/bin\0".as_ptr() } else { p as *const u8 }
        };
        let flen = strlen_impl(file);
        let mut buf = [0u8; 4096];
        let mut seg = path;
        loop {
            // copy one ':'-delimited dir
            let mut n = 0usize;
            while *seg.add(n) != 0 && *seg.add(n) != b':' { n += 1; }
            if n + flen + 2 <= buf.len() {
                core::ptr::copy_nonoverlapping(seg, buf.as_mut_ptr(), n);
                let mut w = n;
                if w == 0 { buf[w] = b'.'; w += 1; } // empty seg = cwd
                buf[w] = b'/'; w += 1;
                core::ptr::copy_nonoverlapping(file, buf.as_mut_ptr().add(w), flen);
                buf[w + flen] = 0;
                execve(buf.as_ptr(), argv, env);
            }
            if *seg.add(n) == 0 { break; }
            seg = seg.add(n + 1);
        }
        -1
    }
}

// collect a NULL-terminated vararg pointer list into `out`; returns count.
unsafe fn collect(arg0: *const u8, ap: &mut VaList, out: &mut [*const u8]) -> usize {
    // SAFETY: the variadic list is NULL-terminated per execl* contract;
    // `out` is large enough for the program's argv (capped).
    unsafe {
        out[0] = arg0;
        let mut n = 1;
        while n < out.len() - 1 {
            let a = ap.next_arg::<*const c_void>() as *const u8;
            out[n] = a;
            if a.is_null() { return n; }
            n += 1;
        }
        out[n] = core::ptr::null();
        n
    }
}

// # C: int execl(const char *path, const char *arg0, ...)
#[no_mangle]
pub unsafe extern "C" fn execl(path: *const u8, arg0: *const u8, mut ap: ...) -> i32 {
    // SAFETY: varargs are a NULL-terminated argv per execl.
    unsafe { let mut v = [core::ptr::null(); 128]; collect(arg0, &mut ap, &mut v); execv(path, v.as_ptr()) }
}
// # C: int execlp(const char *file, const char *arg0, ...)
#[no_mangle]
pub unsafe extern "C" fn execlp(file: *const u8, arg0: *const u8, mut ap: ...) -> i32 {
    // SAFETY: varargs are a NULL-terminated argv per execlp.
    unsafe { let mut v = [core::ptr::null(); 128]; collect(arg0, &mut ap, &mut v); execvp(file, v.as_ptr()) }
}
// # C: int execle(const char *path, const char *arg0, ..., char *const envp[])
#[no_mangle]
pub unsafe extern "C" fn execle(path: *const u8, arg0: *const u8, mut ap: ...) -> i32 {
    // SAFETY: varargs are a NULL-terminated argv then one envp pointer.
    unsafe {
        let mut v = [core::ptr::null(); 128];
        collect(arg0, &mut ap, &mut v);
        let envp = ap.next_arg::<*const c_void>() as *const *const u8;
        execve(path, v.as_ptr(), envp)
    }
}

// # C: pid_t wait4(pid_t, int *status, int options, struct rusage *)
#[no_mangle]
pub unsafe extern "C" fn wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut c_void) -> i32 {
    // SAFETY: status/rusage are null or valid out-params per wait4(2).
    ret_isize(unsafe { sys4(nr::WAIT4, pid as usize, status as usize, options as usize, rusage as usize) }) as i32
}
// # C: pid_t waitpid(pid_t, int *status, int options)
#[no_mangle]
pub unsafe extern "C" fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32 {
    // SAFETY: status is null or a valid int out-param.
    unsafe { wait4(pid, status, options, core::ptr::null_mut()) }
}
// # C: pid_t wait(int *status)
#[no_mangle]
pub unsafe extern "C" fn wait(status: *mut i32) -> i32 {
    // SAFETY: status is null or a valid int out-param.
    unsafe { wait4(-1, status, 0, core::ptr::null_mut()) }
}
// # C: pid_t wait3(int *status, int options, struct rusage *rusage)
#[no_mangle]
pub unsafe extern "C" fn wait3(status: *mut i32, options: i32, rusage: *mut c_void) -> i32 {
    // SAFETY: wait3 = wait4(-1, ...); status/rusage are null or valid out-params.
    unsafe { wait4(-1, status, options, rusage) }
}

// # C: int system(const char *command)
#[no_mangle]
pub unsafe extern "C" fn system(command: *const u8) -> i32 {
    // SAFETY: command is null (→ "is a shell available?") or NUL-terminated.
    unsafe {
        if command.is_null() { return 1; }
        let pid = fork();
        if pid == 0 {
            let argv: [*const u8; 4] = [b"sh\0".as_ptr(), b"-c\0".as_ptr(), command, core::ptr::null()];
            execve(b"/bin/sh\0".as_ptr(), argv.as_ptr(), current_environ() as *const *const u8);
            exit_group(127);
        }
        if pid < 0 { return -1; }
        let mut status = 0i32;
        waitpid(pid, &mut status, 0);
        status
    }
}
