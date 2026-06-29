// Shared helpers + O_* flag constants for the open(2)/openat(2) family.
// Split out so each syscall lives in its own file (docs/53 §0); the handlers
// are 002_open.rs / 257_openat.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

pub(crate) const O_CREAT:     u32 = 0o100;
/// `O_EXCL` (asm-generic, both arches): with `O_CREAT`, an existing final
/// component → `EEXIST` (Linux `do_last`/`lookup_open`).
pub(crate) const O_EXCL:      u32 = 0o200;
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
/// `O_PATH` (asm-generic, both arches): an fd-reference open with no read/write
/// access — bypasses `may_open`'s access-mode permission check.
pub(crate) const O_PATH:      u32 = 0o10000000;
/// `O_ACCMODE` mask + the writable access modes.
pub(crate) const O_ACCMODE:   u32 = 0o3;
pub(crate) const O_WRONLY:    u32 = 0o1;
pub(crate) const O_RDWR:      u32 = 0o2;

/// Linux `do_open` access enforcement, run after path resolution: `EROFS` for a
/// write through a read-only mount (`mnt_want_write`), then the `may_open` DAC
/// check (EACCES / EISDIR). The DAC check is skipped for a freshly `O_CREAT`'d
/// file (Linux passes acc_mode=0), for `O_PATH` descriptors, and for anonymous
/// inodes (`mnt_id == 0`: ptmx/tty/pipe — governed by their own open hooks).
/// Returns `Some(neg_errno)` to fail the open, `None` to allow it.
/// # C: O(ngroups)
pub(crate) fn enforce_open_perm(
    inode: &vfs::InodeRef,
    mnt_id: u64,
    flags: u32,
    created: bool,
) -> Option<i64> {
    use core::sync::atomic::Ordering;
    if (flags & O_PATH) != 0 { return None; }
    let accmode    = flags & O_ACCMODE;
    let want_write = accmode == O_WRONLY || accmode == O_RDWR || (flags & O_TRUNC) != 0;
    let want_read  = accmode != O_WRONLY;
    // EROFS: writing through a read-only mount (Linux `mnt_want_write`).
    if want_write && mnt_id != 0 {
        if let Some(m) = vfs::mount::mount_by_id(mnt_id) {
            if (m.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY) != 0 {
                return Some(-(Errno::Erofs.as_i32() as i64));
            }
        }
    }
    if created || mnt_id == 0 { return None; }
    if let Err(e) = vfs::may_open(inode, want_read, want_write, &crate::pathresolve::current_cred()) {
        return Some(-(e as i64));
    }
    None
}

/// Map a path that resolves by **duplicating an existing open file
/// description** → `(tid_opt, fd)`: `/dev/std{in,out,err}`, `/dev/fd/<n>`,
/// `/proc/<pid|self>/fd/<n>` (Linux magic fd-link open semantics).
/// Delegates to the hosted-tested `vfs::path::dup_fd_target` so the
/// parsing contract is locked by `vfs` unit tests (T8).
/// # C: O(N_path)
pub(crate) fn dup_fd_target(path: &str) -> Option<(Option<u32>, i32)> {
    vfs::path::dup_fd_target(path)
}

/// Parse `/proc/{self|<pid>}/fd/<n>` → `(tid_opt, fd)` (`self` ⇒ `None`).
/// # C: O(N_path)
pub(crate) fn parse_proc_fd(path: &str) -> Option<(Option<u32>, i32)> {
    vfs::path::parse_proc_fd(path)
}

/// Open `/proc/<pid>/fd/<n>` by duplicating the target fd's open file
/// description into the caller's fd table (Linux magic-symlink reopen).
/// # C: O(1)
pub(crate) fn open_proc_fd(tid_opt: Option<u32>, fd: i32, flags: u32) -> i64 {
    const O_CLOEXEC: u32 = 0o2000000;
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
    // RLIMIT_NOFILE soft limit caps fd allocation (Linux `__alloc_fd`
    // against `rlimit(RLIMIT_NOFILE)`); exceeding it → EMFILE.
    // SAFETY: rlimits slot single-mutator per `13§5`; cur is the running task on this CPU.
    let nofile = unsafe { (*cur.rlimits.get())[sched::rlimit::rlim::NOFILE].0 } as usize;
    match fdt.alloc_limit(file, nofile) {
        Ok(n) => {
            if (flags & O_CLOEXEC) != 0 {
                if let Err(e) = fdt.set_cloexec(n, true) { return -(e as i64); }
            }
            n as i64
        }
        Err(e) => -(e as i64),
    }
}

/// Resolve a user path for open/openat: absolute lexically normalised,
/// relative joined to cwd then normalised; bare `.`/`..` preserved.
/// # C: O(N)
pub(crate) fn resolve_path_for_open(path_raw: &str) -> Option<alloc::string::String> {
    Some(crate::pathresolve::resolve_cwd(path_raw))
}
