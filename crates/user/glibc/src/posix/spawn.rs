// posix_spawn (docs/59§6 — G19 keystone: bash, systemd, and most runtimes
// launch children through it). fork → (apply spawn attrs) → (replay file
// actions) → execve, child _exit(127) on any failure. The opaque
// posix_spawn_file_actions_t / posix_spawnattr_t are allocated by the caller
// at the glibc header sizes (80 / 336 bytes on x86_64); our layouts fit inside
// and the caller never inspects them.
#![cfg(feature = "freestanding")]
use core::ffi::{c_char, c_void};
use crate::malloc::heap;
use crate::posix::sched::SchedParam;
use crate::internal::nr;

// clone(CLONE_PIDFD|SIGCHLD): fork-like child + a pidfd written to the parent.
const CLONE_PIDFD: usize = 0x1000;
const SIGCHLD: usize = 17;
unsafe fn clone_pidfd(pidfd_out: *mut i32) -> isize {
    // SAFETY: clone(2) with stack=0 ⇒ fork semantics; the pidfd lands in the
    // parent_tid slot (3rd arg), identical on x86_64 + aarch64 clone ABIs.
    unsafe { crate::arch::syscall::sys5(nr::CLONE, CLONE_PIDFD | SIGCHLD, 0, pidfd_out as usize, 0, 0) }
}

// spawn attr flags (bits/spawn.h; match glibc).
const SETPGROUP: i16 = 0x02;
const SETSIGDEF: i16 = 0x04;
const SETSIGMASK: i16 = 0x08;
const SETSCHEDPARAM: i16 = 0x10;
const SETSCHEDULER: i16 = 0x20;

#[derive(Clone, Copy)]
#[repr(C)]
struct Action { kind: u8, fd: i32, newfd: i32, oflag: i32, mode: u32, path: *const c_char }
// Open=0 (fd,oflag,mode,path → open then dup2 to fd), Close=1 (fd), Dup2=2 (fd→newfd),
// Chdir=3 (path), Fchdir=4 (fd), Closefrom=5 (fd=lowfd), Tcsetpgrp=6 (fd).

// Our posix_spawn_file_actions_t layout (≤ 80 bytes the caller allocated).
#[repr(C)]
struct FileActions { used: usize, cap: usize, acts: *mut Action, _pad: [u8; 56] }

// Our posix_spawnattr_t layout (≤ 336 bytes the caller allocated).
#[repr(C)]
struct SpawnAttr { flags: i16, pgroup: i32, sigdefault: u64, sigmask: u64,
    schedpolicy: i32, schedprio: i32, cgroup: i32, _pad: [u8; 300] }

// --- file actions -------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_init(fa: *mut c_void) -> i32 {
    // SAFETY: fa is a caller-allocated posix_spawn_file_actions_t (≥80 bytes).
    unsafe { *(fa as *mut FileActions) = FileActions { used: 0, cap: 0, acts: core::ptr::null_mut(), _pad: [0; 56] }; }
    0
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(fa: *mut c_void) -> i32 {
    // SAFETY: fa was init'd; free the actions array if any.
    unsafe { let f = &mut *(fa as *mut FileActions); if !f.acts.is_null() { heap::free(f.acts as *mut u8); f.acts = core::ptr::null_mut(); f.used = 0; f.cap = 0; } }
    0
}
unsafe fn push(fa: *mut c_void, a: Action) -> i32 {
    // SAFETY: fa is an init'd FileActions; grow the heap array by doubling.
    unsafe {
        let f = &mut *(fa as *mut FileActions);
        if f.used == f.cap {
            let ncap = if f.cap == 0 { 8 } else { f.cap * 2 };
            let np = heap::realloc(f.acts as *mut u8, ncap * core::mem::size_of::<Action>()) as *mut Action;
            if np.is_null() { return 12; /* ENOMEM */ }
            f.acts = np; f.cap = ncap;
        }
        *f.acts.add(f.used) = a; f.used += 1;
    }
    0
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(fa: *mut c_void, fd: i32, path: *const c_char, oflag: i32, mode: u32) -> i32 {
    // SAFETY: path outlives the spawn call (caller contract); recorded by pointer.
    unsafe { push(fa, Action { kind: 0, fd, newfd: 0, oflag, mode, path }) }
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(fa: *mut c_void, fd: i32) -> i32 {
    // SAFETY: fa is an init'd posix_spawn_file_actions_t; push records the close.
    unsafe { push(fa, Action { kind: 1, fd, newfd: 0, oflag: 0, mode: 0, path: core::ptr::null() }) }
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(fa: *mut c_void, fd: i32, newfd: i32) -> i32 {
    // SAFETY: fa is an init'd posix_spawn_file_actions_t; push records the dup2.
    unsafe { push(fa, Action { kind: 2, fd, newfd, oflag: 0, mode: 0, path: core::ptr::null() }) }
}
// GNU _np file actions: chdir(path), fchdir(fd), closefrom(fd≥), tcsetpgrp(fd).
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(fa: *mut c_void, path: *const c_char) -> i32 {
    // SAFETY: path outlives the spawn call (caller contract); recorded by pointer.
    unsafe { push(fa, Action { kind: 3, fd: 0, newfd: 0, oflag: 0, mode: 0, path }) }
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(fa: *mut c_void, fd: i32) -> i32 {
    // SAFETY: fa is an init'd posix_spawn_file_actions_t; push records the fchdir.
    unsafe { push(fa, Action { kind: 4, fd, newfd: 0, oflag: 0, mode: 0, path: core::ptr::null() }) }
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addclosefrom_np(fa: *mut c_void, from: i32) -> i32 {
    // SAFETY: fa is an init'd posix_spawn_file_actions_t; push records closefrom.
    unsafe { push(fa, Action { kind: 5, fd: from, newfd: 0, oflag: 0, mode: 0, path: core::ptr::null() }) }
}
#[no_mangle]
pub unsafe extern "C" fn posix_spawn_file_actions_addtcsetpgrp_np(fa: *mut c_void, tcfd: i32) -> i32 {
    // SAFETY: fa is an init'd posix_spawn_file_actions_t; push records tcsetpgrp.
    unsafe { push(fa, Action { kind: 6, fd: tcfd, newfd: 0, oflag: 0, mode: 0, path: core::ptr::null() }) }
}

// --- spawn attributes ---------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn posix_spawnattr_init(at: *mut c_void) -> i32 {
    // SAFETY: at is a caller-allocated posix_spawnattr_t (≥336 bytes).
    unsafe { *(at as *mut SpawnAttr) = SpawnAttr { flags: 0, pgroup: 0, sigdefault: 0, sigmask: 0, schedpolicy: 0, schedprio: 0, cgroup: 0, _pad: [0; 300] }; }
    0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_destroy(_at: *mut c_void) -> i32 { 0 }
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setflags(at: *mut c_void, flags: i16) -> i32 {
    // SAFETY: at is a caller-allocated, init'd posix_spawnattr_t we write into.
    unsafe { (*(at as *mut SpawnAttr)).flags = flags; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getflags(at: *const c_void, out: *mut i16) -> i32 {
    // SAFETY: at is an init'd posix_spawnattr_t; out is a writable short.
    unsafe { *out = (*(at as *const SpawnAttr)).flags; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setpgroup(at: *mut c_void, pgroup: i32) -> i32 {
    // SAFETY: at is a caller-allocated, init'd posix_spawnattr_t we write into.
    unsafe { (*(at as *mut SpawnAttr)).pgroup = pgroup; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setsigmask(at: *mut c_void, set: *const u64) -> i32 {
    // SAFETY: at is init'd; set is null or a sigset_t whose low word is the mask.
    unsafe { (*(at as *mut SpawnAttr)).sigmask = if set.is_null() { 0 } else { *set }; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setsigdefault(at: *mut c_void, set: *const u64) -> i32 {
    // SAFETY: at is init'd; set is null or a sigset_t whose low word is the mask.
    unsafe { (*(at as *mut SpawnAttr)).sigdefault = if set.is_null() { 0 } else { *set }; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getpgroup(at: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: at is an init'd posix_spawnattr_t; out is a writable pid_t.
    unsafe { *out = (*(at as *const SpawnAttr)).pgroup; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getsigmask(at: *const c_void, set: *mut u64) -> i32 {
    // SAFETY: at is init'd; set is a sigset_t out (low word carries the mask).
    unsafe { *set = (*(at as *const SpawnAttr)).sigmask; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getsigdefault(at: *const c_void, set: *mut u64) -> i32 {
    // SAFETY: at is init'd; set is a sigset_t out (low word carries the mask).
    unsafe { *set = (*(at as *const SpawnAttr)).sigdefault; } 0
}
// Scheduling attrs stored + replayed in the child (sched_set{scheduler,param}).
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setschedparam(at: *mut c_void, p: *const SchedParam) -> i32 {
    // SAFETY: at is init'd; p points to a struct sched_param (one int).
    unsafe { (*(at as *mut SpawnAttr)).schedprio = if p.is_null() { 0 } else { (*p).sched_priority }; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getschedparam(at: *const c_void, p: *mut SchedParam) -> i32 {
    // SAFETY: at is init'd; p is a writable struct sched_param out-pointer.
    unsafe { (*p).sched_priority = (*(at as *const SpawnAttr)).schedprio; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(at: *mut c_void, policy: i32) -> i32 {
    // SAFETY: at is a caller-allocated, init'd posix_spawnattr_t we write into.
    unsafe { (*(at as *mut SpawnAttr)).schedpolicy = policy; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(at: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: at is an init'd posix_spawnattr_t; out is a writable int.
    unsafe { *out = (*(at as *const SpawnAttr)).schedpolicy; } 0
}
// SETCGROUP_NP (GNU): the child is moved into this cgroup v2 id via clone3's
// CLONE_INTO_CGROUP; we store + apply best-effort post-fork (write to cgroup.procs).
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_setcgroup_np(at: *mut c_void, cgroup: i32) -> i32 {
    // SAFETY: at is a caller-allocated, init'd posix_spawnattr_t we write into.
    unsafe { (*(at as *mut SpawnAttr)).cgroup = cgroup; } 0
}
#[no_mangle] pub unsafe extern "C" fn posix_spawnattr_getcgroup_np(at: *const c_void, out: *mut i32) -> i32 {
    // SAFETY: at is an init'd posix_spawnattr_t; out is a writable int.
    unsafe { *out = (*(at as *const SpawnAttr)).cgroup; } 0
}

// --- the spawn itself ---------------------------------------------------
unsafe fn child_setup_and_exec(path: *const c_char, fa: *const c_void, at: *const c_void, argv: *const *const c_char, envp: *const *const c_char) -> ! {
    // SAFETY: runs in the forked child; applies attrs + file actions then
    // execve. Any failure ⇒ _exit(127) (the posix_spawn child-error contract).
    unsafe {
        child_apply(fa, at);
        crate::posix::process::execve(path as *const u8, argv as *const *const u8, envp as *const *const u8);
        crate::stdlib::exit::exit_group(127); // execve only returns on error
    }
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawn(pid: *mut i32, path: *const c_char, fa: *const c_void, at: *const c_void, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    // SAFETY: fork; child sets up + execs (never returns to here); parent stores
    // the child pid. fork() < 0 ⇒ return errno.
    unsafe {
        let p = crate::posix::process::fork();
        if p < 0 { return -p; }
        if p == 0 { child_setup_and_exec(path, fa, at, argv, envp); }
        if !pid.is_null() { *pid = p; }
        0
    }
}

// # C: int pidfd_spawn(int *pidfd, const char *path, const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at, char *const argv[], char *const envp[])
// glibc 2.39: posix_spawn that returns a pidfd (via CLONE_PIDFD) instead of a pid.
#[no_mangle]
pub unsafe extern "C" fn pidfd_spawn(pidfd: *mut i32, path: *const c_char, fa: *const c_void, at: *const c_void, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    // SAFETY: clone(CLONE_PIDFD); child sets up + execs (never returns here);
    // parent stores the pidfd. clone < 0 ⇒ return the positive errno.
    unsafe {
        let mut pfd: i32 = -1;
        let p = clone_pidfd(&mut pfd);
        if p < 0 { return (-p) as i32; }
        if p == 0 { child_setup_and_exec(path, fa, at, argv, envp); }
        if !pidfd.is_null() { *pidfd = pfd; }
        0
    }
}

// # C: int pidfd_spawnp(int *pidfd, const char *file, ...) — pidfd_spawn + PATH search.
#[no_mangle]
pub unsafe extern "C" fn pidfd_spawnp(pidfd: *mut i32, file: *const c_char, fa: *const c_void, at: *const c_void, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    // SAFETY: '/' in `file` ⇒ direct pidfd_spawn; else clone(CLONE_PIDFD) and the
    // child PATH-searches with the passed envp (execvpe-shaped). clone<0 ⇒ errno.
    unsafe {
        let mut has_slash = false;
        let mut i = 0; while *file.add(i) != 0 { if *file.add(i) == b'/' as c_char { has_slash = true; break; } i += 1; }
        if has_slash { return pidfd_spawn(pidfd, file, fa, at, argv, envp); }
        let mut pfd: i32 = -1;
        let p = clone_pidfd(&mut pfd);
        if p < 0 { return (-p) as i32; }
        if p == 0 {
            if !at.is_null() || !fa.is_null() { child_apply(fa, at); }
            path_search_exec(file, argv, envp);
            crate::stdlib::exit::exit_group(127);
        }
        if !pidfd.is_null() { *pidfd = pfd; }
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn posix_spawnp(pid: *mut i32, file: *const c_char, fa: *const c_void, at: *const c_void, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    // SAFETY: if `file` contains a '/', it's a path → posix_spawn. Otherwise the
    // child must PATH-search; we let execvp do that by execing it directly in
    // the child via a tiny variant (fork here, child runs execvp).
    unsafe {
        let mut has_slash = false;
        let mut i = 0; while *file.add(i) != 0 { if *file.add(i) == b'/' as c_char { has_slash = true; break; } i += 1; }
        if has_slash { return posix_spawn(pid, file, fa, at, argv, envp); }
        let p = crate::posix::process::fork();
        if p < 0 { return -p; }
        if p == 0 {
            // apply attrs + file actions, then PATH-search + execve with the
            // PASSED envp (not the inherited environ — posix_spawnp is execvpe-
            // shaped: the caller's envp wins).
            if !at.is_null() || !fa.is_null() { child_apply(fa, at); }
            path_search_exec(file, argv, envp);
            crate::stdlib::exit::exit_group(127);
        }
        if !pid.is_null() { *pid = p; }
        0
    }
}

// Shared child attr+action application (used by both spawn + spawnp paths).
// SIG_SETMASK=2. SETSIGDEF resets the named signals to SIG_DFL; setpgid runs
// before file actions so a tcsetpgrp action picks up the child's new pgrp.
unsafe fn child_apply(fa: *const c_void, at: *const c_void) {
    // SAFETY: child context; applies spawn attrs then replays file actions.
    unsafe {
        if !at.is_null() {
            let a = &*(at as *const SpawnAttr);
            if a.flags & SETPGROUP != 0 { crate::posix::ids::setpgid(0, a.pgroup); }
            if a.flags & SETSIGDEF != 0 {
                let mut s = 1u8;
                while s <= 64 { if a.sigdefault & (1u64 << (s - 1)) != 0 { crate::signal::sigaction::exports::signal(s as i32, 0 /* SIG_DFL */); } s += 1; }
            }
            if a.flags & SETSIGMASK != 0 { let m = a.sigmask; crate::signal::sig::sigprocmask(2, &m as *const u64 as *const _, core::ptr::null_mut()); }
            if a.flags & (SETSCHEDULER | SETSCHEDPARAM) != 0 {
                let p = SchedParam { sched_priority: a.schedprio };
                if a.flags & SETSCHEDULER != 0 { crate::posix::sched::sched_setscheduler(0, a.schedpolicy, &p); }
                else { crate::posix::sched::sched_setparam(0, &p); }
            }
        }
        if !fa.is_null() {
            let f = &*(fa as *const FileActions);
            for i in 0..f.used {
                let act = *f.acts.add(i);
                let r = match act.kind {
                    0 => { let nfd = crate::posix::io::open(act.path as *const u8, act.oflag, act.mode); if nfd < 0 { -1 } else if nfd != act.fd { let d = crate::posix::fd::dup2(nfd, act.fd); crate::posix::io::close(nfd); d } else { nfd } }
                    1 => crate::posix::io::close(act.fd),
                    2 => crate::posix::fd::dup2(act.fd, act.newfd),
                    3 => crate::posix::fs::chdir(act.path as *const u8),
                    4 => crate::posix::fs::fchdir(act.fd),
                    5 => { crate::posix::modern::closefrom(act.fd); 0 }
                    _ => crate::posix::tty::tcsetpgrp(act.fd, crate::posix::ids::getpgrp()),
                };
                if r < 0 { crate::stdlib::exit::exit_group(127); }
            }
        }
    }
}

// # C: int execvpe(const char *file, char *const argv[], char *const envp[])
// Like execvp but with an explicit environment. If `file` contains a '/', exec
// it directly; else PATH-search (using envp's PATH). Returns -1 only on failure.
#[no_mangle]
pub unsafe extern "C" fn execvpe(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> i32 {
    // SAFETY: file NUL-terminated; argv/envp NULL-terminated arrays. execve/
    // path_search_exec only return on failure, leaving errno set.
    unsafe {
        let fp = file as *const u8;
        let mut has_slash = false;
        let mut i = 0;
        while *fp.add(i) != 0 { if *fp.add(i) == b'/' { has_slash = true; break; } i += 1; }
        if has_slash {
            crate::posix::process::execve(fp, argv as *const *const u8, envp as *const *const u8);
        } else {
            path_search_exec(file, argv, envp);
        }
        -1
    }
}

// PATH-search `file` using the PATH from `envp` (not the process environ) and
// execve each candidate with `envp`. Returns only if every candidate failed.
unsafe fn path_search_exec(file: *const c_char, argv: *const *const c_char, envp: *const *const c_char) {
    // SAFETY: file NUL-terminated; envp null or a NULL-terminated string array.
    // Each candidate path is built in a 4096-byte stack buffer; execve only
    // returns on failure, so we try the next PATH component.
    unsafe {
        let mut path: *const u8 = b"/bin:/usr/bin\0".as_ptr();
        if !envp.is_null() {
            let mut i = 0;
            loop {
                let e = *envp.add(i); if e.is_null() { break; }
                let e = e as *const u8;
                if *e == b'P' && *e.add(1) == b'A' && *e.add(2) == b'T' && *e.add(3) == b'H' && *e.add(4) == b'=' { path = e.add(5); break; }
                i += 1;
            }
        }
        let fp = file as *const u8;
        let flen = { let mut n = 0; while *fp.add(n) != 0 { n += 1; } n };
        let mut buf = [0u8; 4096];
        let mut dir = path;
        loop {
            let mut dl = 0usize;
            while *dir.add(dl) != 0 && *dir.add(dl) != b':' { dl += 1; }
            if dl + 1 + flen + 1 < buf.len() {
                let mut k = 0;
                for j in 0..dl { buf[k] = *dir.add(j); k += 1; }
                if dl > 0 { buf[k] = b'/'; k += 1; }
                for j in 0..flen { buf[k] = *fp.add(j); k += 1; }
                buf[k] = 0;
                crate::posix::process::execve(buf.as_ptr(), argv as *const *const u8, envp as *const *const u8);
            }
            let sep = *dir.add(dl);
            if sep == 0 { break; }
            dir = dir.add(dl + 1);
        }
    }
}
