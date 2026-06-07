// Shared helper for access(2) / faccessat(2) handlers. Split per
// `08§7` / `53§0`; work belongs in vfs per `53` (tracked sweep).
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use hal::USER_VA_END;

/// Existence check resolving `path_ptr` against `dirfd` (real `faccessat(2)`
/// dirfd semantics; AT_FDCWD = -100 → cwd).
/// # C: O(N_path)
pub(crate) fn do_access(dirfd: i32, path_ptr: u64) -> i64 {
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    if path == b"/" { return 0; }
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    // BUG D follow-up: honour a real fd-relative dirfd; resolve_at(AT_FDCWD,raw)
    // == resolve_cwd(raw) so plain access(2) is unchanged.
    let resolved = crate::pathresolve::resolve_at(dirfd, raw)
        .unwrap_or_else(|| crate::pathresolve::resolve_cwd(raw));
    let s = resolved.as_str();
    if crate::pathresolve::resolve(s, false).is_some() {
        0
    } else {
        -(Errno::Enoent.as_i32() as i64)
    }
}
