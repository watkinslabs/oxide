// Shared helpers + O_* flag constants for the open(2)/openat(2) family.
// Split out so each syscall lives in its own file (docs/53 §0); the handlers
// are 002_open.rs / 257_openat.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

pub(crate) const O_CREAT:     u32 = 0o100;
pub(crate) const O_TRUNC:     u32 = 0o1000;
pub(crate) const O_DIRECTORY: u32 = 0o200000;
// O_* flag VALUES are arch-specific (Linux fcntl.h per-arch overrides):
// x86_64 = asm-generic (O_NOFOLLOW=0o400000); aarch64 uses the arm override
// (O_NOFOLLOW=0o100000, while 0x20000 is O_LARGEFILE which musl-aarch64 sets).
#[cfg(target_arch = "x86_64")]
pub(crate) const O_NOFOLLOW:  u32 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_NOFOLLOW:  u32 = 0o100000;
/// `__O_TMPFILE` per Linux fcntl.h (full O_TMPFILE = this | O_DIRECTORY).
pub(crate) const O_TMPFILE:   u32 = 0o20000000;

/// Map a path that resolves by **duplicating an existing open file
/// description** → `(tid_opt, fd)`: `/dev/std{in,out,err}`, `/dev/fd/<n>`,
/// `/proc/<pid|self>/fd/<n>` (Linux magic fd-link open semantics).
/// # C: O(N_path)
pub(crate) fn dup_fd_target(path: &str) -> Option<(Option<u32>, i32)> {
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

/// Parse `/proc/{self|<pid>}/fd/<n>` → `(tid_opt, fd)` (`self` ⇒ `None`).
/// # C: O(N_path)
pub(crate) fn parse_proc_fd(path: &str) -> Option<(Option<u32>, i32)> {
    let rest = path.strip_prefix("/proc/")?;
    let mut it = rest.splitn(3, '/');
    let who = it.next()?;
    if it.next()? != "fd" { return None; }
    let fd: i32 = it.next()?.parse().ok()?;
    let tid = if who == "self" { None } else { Some(who.parse::<u32>().ok()?) };
    Some((tid, fd))
}

/// Open `/proc/<pid>/fd/<n>` by duplicating the target fd's open file
/// description into the caller's fd table (Linux magic-symlink reopen).
/// # C: O(1)
pub(crate) fn open_proc_fd(tid_opt: Option<u32>, fd: i32) -> i64 {
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

/// Resolve a user path for open/openat: absolute lexically normalised,
/// relative joined to cwd then normalised; bare `.`/`..` preserved.
/// # C: O(N)
pub(crate) fn resolve_path_for_open(path_raw: &str) -> Option<alloc::string::String> {
    Some(crate::pathresolve::resolve_cwd(path_raw))
}
