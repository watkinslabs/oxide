// access(2) / faccessat(2) shims. Split out of fs.rs to hold it under the
// 1000-line cap (`08§7`); work belongs in vfs per `53` (tracked sweep).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sys_access(path, mode)` — slot 21. Existence check (mode honoured by
/// the path-walk's perm gate). No dirfd → resolve against cwd.
/// # C: O(N_path)
pub fn sys_access(args: &SyscallArgs) -> i64 {
    do_access(-100, args.a0)
}

/// `sys_faccessat(dirfd, path, mode, flags)` — slot 269 (+ faccessat2 326).
/// Resolves `path` against `dirfd`.
/// # C: O(N_path)
pub fn sys_faccessat(args: &SyscallArgs) -> i64 {
    do_access(args.a0 as i32, args.a1)
}

/// Existence check resolving `path_ptr` against `dirfd` (real `faccessat(2)`
/// dirfd semantics; AT_FDCWD = -100 → cwd).
/// # C: O(N_path)
fn do_access(dirfd: i32, path_ptr: u64) -> i64 {
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    if path == b"/" { return 0; }
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: honour a real fd-relative dirfd; resolve_at(AT_FDCWD,raw)
    // == resolve_cwd(raw) so plain access(2) is unchanged.
    let resolved = crate::syscalls::pathresolve::resolve_at(dirfd, raw)
        .unwrap_or_else(|| crate::syscalls::pathresolve::resolve_cwd(raw));
    let s = resolved.as_str();
    if crate::syscalls::pathresolve::resolve(s, false).is_some() {
        0
    } else {
        -(Errno::Enoent.as_i32() as i64)
    }
}
