// sys_execveat (NR_EXECVEAT=322) per docs/53§0 — per-syscall-file
// module. Delegates to sys_execve / execve_inner in s059_execve;
// shared helpers live in execve_common.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::s059_execve::{execve_inner, sys_execve};

/// `execveat(dirfd, path, argv, envp, flags)` per Linux ABI. Honors
/// `AT_EMPTY_PATH` (flag 0x1000): when path is empty, exec the file
/// referenced by `dirfd`. This is the kernel side of `fexecve(3)`
/// (libc translates `fexecve(fd, ...)` to `execveat(fd, "", argv,
/// envp, AT_EMPTY_PATH)`). Non-empty paths route through execve.
/// dirfd is ignored for absolute paths.
/// # C: O(path + dentry depth) + execve_inner cost
pub fn sys_execveat(args: &SyscallArgs) -> i64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let dirfd = args.a0 as i32;
    let pathp = args.a1;
    let argv  = args.a2;
    let envp  = args.a3;
    let flags = args.a4;
    let path_is_empty = if pathp == 0 {
        true
    } else if pathp >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    } else {
        // SAFETY: pathp validated < USER_VA_END; one-byte probe.
        unsafe { core::ptr::read_volatile(pathp as *const u8) == 0 }
    };
    if path_is_empty && (flags & AT_EMPTY_PATH) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task; sole reader of fd_table slot per `13§5`.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // EBADF for a bad dirfd before exec (Linux fexecve contract).
        if fdt.get(dirfd).is_err() { return -(Errno::Ebadf.as_i32() as i64); }
        // fexecve(fd): exec the fd's backing inode DIRECTLY, never by
        // re-resolving a pathname. Route through the magic-fd loader path
        // by handing execve_inner `/proc/self/fd/<dirfd>`: `read_exec`'s
        // `dup_fd_target` fast-path then loads the open file description's
        // inode (`proc_fd_file`). This is the only way a sealed memfd is
        // exec-able — its synthetic d_path (`/memfd:NAME (deleted)`) can
        // never re-resolve on any filesystem (Linux do_open_execat uses
        // the fd's file for AT_EMPTY_PATH, not a path walk).
        let mut kpath = alloc::vec::Vec::new();
        kpath.extend_from_slice(b"/proc/self/fd/");
        {
            use core::fmt::Write as _;
            let mut n = alloc::string::String::new();
            let _ = write!(n, "{}", dirfd);
            kpath.extend_from_slice(n.as_bytes());
        }
        // Synthesise SyscallArgs where execve_inner sees argv/envp
        // in their familiar slots (a1, a2).
        let sa = SyscallArgs { a0: 0, a1: argv, a2: envp, a3: 0, a4: 0, a5: 0 };
        return execve_inner(&sa, kpath);
    }
    // Plain path-based execveat. dirfd ignored; sys_execve does the
    // user-pointer read + path resolution.
    let mut sa = *args;
    sa.a0 = pathp; sa.a1 = argv; sa.a2 = envp; sa.a3 = 0;
    sys_execve(&sa)
}
