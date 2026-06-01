// `sys_open` / `sys_openat` per `15§5` / `16§3`. Split from
// syscall_glue.rs / syscall_glue_fs.rs to keep both under cap.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use vfs::{Dentry, File, OpenFlags};


const O_CREAT:     u32 = 0o100;
const O_TRUNC:     u32 = 0o1000;
const O_DIRECTORY: u32 = 0o200000;
// O_* flag VALUES are arch-specific (Linux fcntl.h per-arch overrides):
// x86_64 = asm-generic (O_NOFOLLOW=0o400000=0x20000); aarch64 uses the
// arm override (O_NOFOLLOW=0o100000=0x8000, while 0x20000 is O_LARGEFILE,
// which musl-aarch64's open() sets). Using the x86 value on arm made the
// kernel read O_LARGEFILE as O_NOFOLLOW and stop following symlinks.
#[cfg(target_arch = "x86_64")]
const O_NOFOLLOW:  u32 = 0o400000;
#[cfg(target_arch = "aarch64")]
const O_NOFOLLOW:  u32 = 0o100000;
/// `__O_TMPFILE` per Linux fcntl.h. The full Linux `O_TMPFILE`
/// macro is `__O_TMPFILE | O_DIRECTORY` (0x410000) — old userspace
/// that issues `open(path, O_TMPFILE | ...)` on a kernel without
/// O_TMPFILE support falls back to opening the directory itself
/// rather than a tempfile. Detect the high bit independently of
/// O_DIRECTORY since we also accept either masking.
const O_TMPFILE:   u32 = 0o20000000;

/// Map a path that should resolve by **duplicating an existing open file
/// description** → `(tid_opt, fd)`. Covers the standard `/dev` fd-links
/// (`/dev/stdin`→0, `stdout`→1, `stderr`→2), `/dev/fd/<n>`, and
/// `/proc/<pid|self>/fd/<n>`. These are symlinks for readlink/ls, but
/// `open(2)` shares the target's fd (Linux magic fd-link semantics) — a
/// path reopen would fail for pipes/sockets. Returns `None` otherwise.
/// # C: O(N_path)
fn dup_fd_target(path: &str) -> Option<(Option<u32>, i32)> {
    match path {
        "/dev/stdin"  => return Some((None, 0)),
        "/dev/stdout" => return Some((None, 1)),
        "/dev/stderr" => return Some((None, 2)),
        _ => {}
    }
    if let Some(rest) = path.strip_prefix("/dev/fd/") {
        return rest.parse::<i32>().ok().map(|n| (None, n));
    }
    parse_proc_fd(path)
}

/// Parse a `/proc/{self|<pid>}/fd/<n>` path → `(tid_opt, fd)` where
/// `self` ⇒ `None`. Returns `None` for any other shape (e.g. a trailing
/// component after `<n>`, or non-numeric fd). Used to route opens of
/// magic fd-links to a dup of the existing open file description.
/// # C: O(N_path)
fn parse_proc_fd(path: &str) -> Option<(Option<u32>, i32)> {
    let rest = path.strip_prefix("/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fd" { return None; }
    let fd: i32 = it.next()?.parse().ok()?;
    let tid = if who == "self" { None } else { Some(who.parse::<u32>().ok()?) };
    Some((tid, fd))
}

/// Open `/proc/<pid>/fd/<n>` by duplicating the target fd's open file
/// description into the caller's fd table — Linux magic-symlink reopen
/// semantics (shares the description; not a path reopen).
/// # C: O(1)
fn open_proc_fd(tid_opt: Option<u32>, fd: i32) -> i64 {
    let file = match sched::proclink::proc_fd_file(tid_opt, fd) {
        Some(f) => f, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.alloc(file) { Ok(n) => n as i64, Err(e) => -(e as i64) }
}

/// Resolve a user-supplied path for open(2)/openat(2). Absolute paths
/// are lexically normalised (trailing slash stripped, `.`/`..`
/// collapsed) so `open("/proc/self/fd/")` hits the same registry key
/// as `open("/proc/self/fd")`; relative paths are joined to cwd then
/// normalised. Bare `.`/`..` are preserved (not collapsed to "") so
/// `ls` (no arg) sending `.` resolves against cwd correctly.
/// # C: O(N)
fn resolve_path_for_open(path_raw: &str) -> Option<alloc::string::String> {
    Some(crate::syscalls::pathresolve::resolve_cwd(path_raw))
}

/// `sys_open(path, flags, mode)` — slot 2.
/// # C: O(N_path)
pub fn sys_open(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let flags    = args.a1 as u32;
    let mode     = args.a2 as u32;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller already ran code from this AS); 256 B bound.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let path_raw = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(path_raw);
    let path_str: &str = resolved.as_deref().unwrap_or(path_raw);
    {
        use ::security::landlock::access as la;
        let mut op = la::READ_FILE;
        if (flags & 0o1) != 0 { op |= la::WRITE_FILE; op &= !la::READ_FILE; }
        if (flags & 0o2) != 0 { op |= la::READ_FILE | la::WRITE_FILE; }
        if (flags & O_CREAT) != 0 { op |= la::MAKE_REG; }
        if (flags & O_TRUNC) != 0 { op |= la::TRUNCATE; }
        if let Err(rv) = crate::syscalls::landlock::check(path_str, op) { return rv; }
    }
    // /dev/{stdin,stdout,stderr}, /dev/fd/<n>, /proc/<pid>/fd/<n>: dup the
    // existing open file description (Linux fd-link semantics — they are
    // symlinks for readlink/ls, but open() shares the target's fd rather
    // than reopening by path, which would fail for pipes/sockets).
    if let Some((tid_opt, n)) = dup_fd_target(path_str) {
        return open_proc_fd(tid_opt, n);
    }
    // Unified mount-table lookup (R67). Special-case /dev/ptmx since
    // it allocates a new pair per open rather than resolving to a
    // pre-registered inode.
    let inode = if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev::pty::allocate_pair();
        master
    } else if path_str == "/dev/tty" {
        // F200: /dev/tty resolves to caller's ctty (POSIX §11.1.3).
        // ENXIO when none, so session-aware userspace can detect it.
        match sched::live::current() {
            // SAFETY: single-mutator per `13§5`; current task on this CPU.
            Some(t) => match unsafe { (*t.ctty.get()).clone() } {
                Some(i) => i,
                None    => return -(Errno::Enxio.as_i32() as i64),
            },
            None => return -(Errno::Enxio.as_i32() as i64),
        }
    } else if let Some(i) = crate::syscalls::pathresolve::resolve(path_str, (flags & O_NOFOLLOW) != 0) {
        // THE resolver (path-walk): per-component, crosses mounts,
        // delegates whole-path filesystems, follows symlinks unless
        // O_NOFOLLOW. Replaces the legacy vfs::mount::lookup + ext4
        // whole-path fallback (still reaches ext4 dirs/non-regular
        // inodes for getdents64 on open(O_DIRECTORY)).
        i
    } else if (flags & O_CREAT) != 0 {
        // O_CREAT: ask the owning mount's FS to create with
        // user-supplied mode masked by the current task's umask.
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = mode & 0o777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, rel)) => match mnt.fs.create(&rel, final_mode) {
                Ok(i) => i,
                Err(_) => return -(Errno::Enoent.as_i32() as i64),
            },
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        return -(Errno::Enoent.as_i32() as i64);
    };
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match vfs::file::install_open(&fdt, inode, path_str, OpenFlags::from_bits_truncate(flags)) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_openat(dirfd, path, flags, mode)` — slot 257.
/// # C: O(N_path)
pub fn sys_openat(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a1;
    let flags    = args.a2 as u32;
    let mode     = args.a3 as u32;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(s);
    let path_str: &str = resolved.as_deref().unwrap_or(s);
    // Landlock check: derive requested access from open flags.
    {
        use ::security::landlock::access as la;
        let mut op = la::READ_FILE;
        if (flags & 0o1) != 0 { op |= la::WRITE_FILE; op &= !la::READ_FILE; }
        if (flags & 0o2) != 0 { op |= la::READ_FILE | la::WRITE_FILE; }
        if (flags & O_CREAT) != 0 { op |= la::MAKE_REG; }
        if (flags & O_TRUNC) != 0 { op |= la::TRUNCATE; }
        if let Err(rv) = crate::syscalls::landlock::check(path_str, op) { return rv; }
    }
    // /dev/{stdin,stdout,stderr}, /dev/fd/<n>, /proc/<pid>/fd/<n>: dup the
    // existing open file description (Linux fd-link semantics — they are
    // symlinks for readlink/ls, but open() shares the target's fd rather
    // than reopening by path, which would fail for pipes/sockets).
    if let Some((tid_opt, n)) = dup_fd_target(path_str) {
        return open_proc_fd(tid_opt, n);
    }
    // Unified mount-table lookup (R67). Special-case /dev/ptmx since
    // it allocates a new pair per open rather than resolving to a
    // pre-registered inode. O_TMPFILE short-circuits to anonymous
    // inode creation (no path lookup, no dir entry).
    let inode = if (flags & O_TMPFILE) != 0 {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = (mode & 0o777 & !umask) as u16;
        match ext4::rootfs::create_anonymous_at(path_str.as_bytes(), final_mode) {
            Some(i) => i,
            None    => return -(Errno::Enospc.as_i32() as i64),
        }
    } else if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev::pty::allocate_pair();
        master
    } else if path_str == "/dev/tty" {
        // F200: Linux /dev/tty resolves to the calling task's
        // controlling terminal (POSIX §11.1.3). No ctty → ENXIO so
        // session-aware userspace (e.g. dropbear's setsid check)
        // observes the absence. The static console alias was the
        // pre-F200 behavior; falls back to it for the boot path.
        match sched::live::current() {
            // SAFETY: single-mutator per `13§5` — current task on this CPU.
            Some(t) => match unsafe { (*t.ctty.get()).clone() } {
                Some(i) => i,
                None    => return -(Errno::Enxio.as_i32() as i64),
            },
            None => return -(Errno::Enxio.as_i32() as i64),
        }
    } else if let Some(i) = crate::syscalls::pathresolve::resolve(path_str, (flags & O_NOFOLLOW) != 0) {
        // THE resolver (path-walk): per-component, crosses mounts,
        // delegates whole-path filesystems, follows symlinks unless
        // O_NOFOLLOW. Replaces the legacy vfs::mount::lookup + ext4
        // whole-path fallback (still reaches ext4 dirs/non-regular
        // inodes for getdents64 on open(O_DIRECTORY)).
        i
    } else if (flags & O_CREAT) != 0 {
        // O_CREAT: ask owning mount's FS to create with the
        // user-supplied mode masked by the task umask.
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let umask = cur.umask.load(core::sync::atomic::Ordering::Acquire);
        let final_mode = mode & 0o777 & !umask;
        match vfs::mount::resolve_mount(path_str) {
            Some((mnt, rel)) => match mnt.fs.create(&rel, final_mode) {
                Ok(i) => i,
                Err(_) => return -(Errno::Enoent.as_i32() as i64),
            },
            None => return -(Errno::Enoent.as_i32() as i64),
        }
    } else {
        return -(Errno::Enoent.as_i32() as i64);
    };
    // O_TMPFILE's macro definition is `__O_TMPFILE | O_DIRECTORY`,
    // so the directory check would fire on every O_TMPFILE call —
    // skip it in that case. The inode we created is a regular file
    // by construction.
    if (flags & O_DIRECTORY) != 0 && (flags & O_TMPFILE) == 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, path_str.to_string(), Arc::clone(&inode));
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new(inode, dentry, oflags);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}
