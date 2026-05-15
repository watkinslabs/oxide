// Shared path-resolution helpers used by every syscall that takes a
// user-mode path argument. Centralizes the cwd-join + lexical-normalize
// dance so we don't fork the rule (skip "." vs preserve ".", etc.) per
// callsite.
//
// All resolution is lexical only (no FS lookup, no symlink expansion).
// Caller hands the result to vfs::mount::lookup / ext4::rootfs::* /
// other backends.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

/// Resolve `raw` against the running task's cwd. Absolute paths
/// short-circuit through the lexical normalizer (collapses `.` /
/// `..`); relative paths are joined to cwd then normalized.
/// Falls back to the raw string only when no current task or the
/// normalize step rejected `..`-escapes-root.
/// # C: O(N_path components)
pub fn resolve_cwd(raw: &str) -> String {
    if raw.starts_with('/') {
        return vfs::path::lexical_normalize(raw).unwrap_or_else(|| raw.into());
    }
    let Some(cur) = sched::live::current() else { return raw.into(); };
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, raw).unwrap_or_else(|| raw.into())
}
