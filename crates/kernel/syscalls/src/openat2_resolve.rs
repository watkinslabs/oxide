//! `openat2(2)` slot 437 — the `struct open_how::resolve` word: its validation
//! and its mapping onto `vfs::LookupFlags`, for BOTH walk phases.
//!
//! Lives outside the kernel-only slot file because `257_openat.rs` is
//! `#![cfg(target_os = "oxide-kernel")]`, which silently compiles any
//! `#[cfg(test)] mod tests` inside it away (CLAUDE.md phantom-test rule,
//! `docs/53`). This is the decision that determines whether an `openat2`
//! sandbox actually holds, so it is the last thing that may ship untested.
//!
//! Linux keeps every `RESOLVE_*` bit in `op->lookup_flags`
//! (`build_open_flags`) and hands that single word to
//! `do_filp_open` → `path_openat`, which uses it for the WHOLE walk —
//! the `LOOKUP_PARENT` phase that `O_CREAT` needs included
//! (Linux's `path_openat` → `link_path_walk` with `nd->flags`).
//! There is no branch on which `RESOLVE_*` bits survive a create.

use syscall::errno::Errno;

// openat2 UAPI `RESOLVE_*` bits.
pub const RESOLVE_NO_XDEV: u64 = 0x01;
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub const RESOLVE_BENEATH: u64 = 0x08;
pub const RESOLVE_IN_ROOT: u64 = 0x10;
pub const RESOLVE_CACHED: u64 = 0x20;
/// `VALID_RESOLVE_FLAGS`.
pub const RESOLVE_VALID: u64 = RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED;

/// `build_open_flags` resolve-word admission: unknown bits are
/// `EINVAL`, and the two scoping flags are mutually exclusive.
/// # C: O(1)
pub fn validate_resolve(resolve: u64) -> Result<(), Errno> {
    if resolve & !RESOLVE_VALID != 0 { return Err(Errno::Einval); }
    if (resolve & RESOLVE_BENEATH != 0) && (resolve & RESOLVE_IN_ROOT != 0) { return Err(Errno::Einval); }
    Ok(())
}

/// `RESOLVE_*` → `LookupFlags`, mirroring the `lookup_flags |= LOOKUP_*`
/// ladder at the tail of `build_open_flags`.
/// # C: O(1)
pub fn lookup_flags_from_resolve(resolve: u64) -> vfs::LookupFlags {
    vfs::LookupFlags {
        no_xdev:       resolve & RESOLVE_NO_XDEV != 0,
        no_magiclinks: resolve & RESOLVE_NO_MAGICLINKS != 0,
        no_symlinks:   resolve & RESOLVE_NO_SYMLINKS != 0,
        beneath_exdev: resolve & RESOLVE_BENEATH != 0,
        in_root:       resolve & RESOLVE_IN_ROOT != 0,
        cached:        resolve & RESOLVE_CACHED != 0,
        ..Default::default()
    }
}

/// True when any `RESOLVE_*` modifier is set, so the open takes the flag-aware
/// resolve route that surfaces `EXDEV`/`ELOOP`/`EAGAIN` instead of collapsing
/// an escape attempt to `ENOENT`. # C: O(1)
pub fn resolve_active(x: &vfs::LookupFlags) -> bool {
    x.no_xdev || x.no_magiclinks || x.no_symlinks || x.beneath_exdev || x.in_root || x.cached
}

/// `LookupFlags` for the `LOOKUP_PARENT` phase of an `O_CREAT` open.
///
/// Every scoping bit SURVIVES: Linux never rebuilds `nd->flags` between the
/// parent walk and the final component, so `RESOLVE_BENEATH`/`IN_ROOT`/
/// `NO_SYMLINKS`/`NO_MAGICLINKS`/`NO_XDEV` constrain the directory the new
/// file is created in exactly as they constrain an ordinary open. Dropping
/// them is a sandbox escape: `openat2(dirfd, "/etc/x", O_CREAT, {RESOLVE_IN_ROOT})`
/// would create at the REAL `/etc`.
///
/// Three bits deliberately do not carry over, matching where Linux applies
/// them:
/// - `no_follow_final` (`O_NOFOLLOW`) scopes the FINAL component only; the
///   parent walk's own last component must still be followed.
/// - `directory` (`LOOKUP_DIRECTORY`) likewise constrains the final component,
///   and `O_DIRECTORY|O_CREAT` is `EINVAL` before this point anyway.
/// - `cached` (`RESOLVE_CACHED`) cannot coexist with `O_CREAT` — `EAGAIN` is
///   returned by `build_open_flags` long before any walk.
/// # C: O(1)
pub fn parent_lookup_flags(x: &vfs::LookupFlags) -> vfs::LookupFlags {
    vfs::LookupFlags {
        parent:        true,
        no_xdev:       x.no_xdev,
        no_magiclinks: x.no_magiclinks,
        no_symlinks:   x.no_symlinks,
        beneath_exdev: x.beneath_exdev,
        in_root:       x.in_root,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
