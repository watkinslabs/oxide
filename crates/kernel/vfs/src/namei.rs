//! `path_lookup` per `docs/16§3` — the single component-walking name
//! resolver. Walks a path one component at a time via the dentry cache
//! (`Dentry::cached_child`) falling back to `Inode::lookup(name)`,
//! crosses mount points, follows symlinks with a depth limit, and
//! honors dirfd-relative bases + RESOLVE flags. Returns the final
//! `(InodeRef, Dentry)`.
//!
//! Mount crossing is keyed by absolute path during the string-mount-
//! table transition (stage V2..V5); it becomes a dentry→mount map at
//! stage V5. The walker itself is filesystem-agnostic: it only needs
//! `Inode::lookup`/`readlink`/`file_type`, so it works over ext4,
//! tmpfs, and any backend that implements per-component lookup.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{FileType, KResult, VfsError};

/// Max symlinks followed in one resolution (Linux `MAXSYMLINKS` = 40,
/// invariant 5 in `16§1`).
pub const MAX_SYMLINK_DEPTH: u32 = 40;

/// Resolution modifiers (subset of `openat2(2)` RESOLVE_* + O_NOFOLLOW).
#[derive(Clone, Copy, Default)]
pub struct LookupFlags {
    /// O_NOFOLLOW: a symlink as the FINAL component is returned as-is
    /// rather than followed.
    pub no_follow_final: bool,
    /// RESOLVE_NO_SYMLINKS: any symlink anywhere → ELOOP.
    pub no_symlinks: bool,
    /// RESOLVE_BENEATH: `..` may not ascend above `root`.
    pub beneath: bool,
}

/// Mount-crossing hook: given the absolute path of a just-resolved
/// directory entry, return the mounted-fs ROOT inode if a filesystem
/// is mounted there, else `None`. Installed by the kernel to bridge to
/// `vfs::mount`; `None` when unset (hosted tests with no mounts).
type MountResolver = fn(&str) -> Option<InodeRef>;
static MOUNT_RESOLVER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the mount-crossing bridge. Called once at boot.
/// # C: O(1)
pub fn set_mount_resolver(f: MountResolver) {
    MOUNT_RESOLVER.store(f as *mut (), Ordering::Release);
}

fn resolve_mount(abs: &str) -> Option<InodeRef> {
    let p = MOUNT_RESOLVER.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_RESOLVER only ever holds a value stored by
    // set_mount_resolver, which takes a `MountResolver` fn pointer; the
    // round-trip through *mut () preserves the fn's address.
    let f: MountResolver = unsafe { core::mem::transmute(p) };
    f(abs)
}

/// Split `path` into non-empty components, preserving `.`/`..` (the
/// walker interprets them). Leading/trailing/duplicate `/` collapse.
/// # C: O(len)
fn components(path: &str) -> Vec<String> {
    path.split('/').filter(|c| !c.is_empty()).map(String::from).collect()
}

/// Resolve `path` from `start` (the dirfd base or cwd dentry), with
/// `root` as the resolution root for absolute paths and `..` clamping.
/// Returns the final `(inode, dentry)`.
///
/// - absolute `path` restarts at `root`.
/// - `.` no-op; `..` ascends (clamped at `root` under BENEATH).
/// - a directory entry that is a mount point switches to the mount root.
/// - a symlink is followed (depth ≤ MAX_SYMLINK_DEPTH) unless it is the
///   final component and `no_follow_final`, or `no_symlinks` (→ ELOOP).
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
) -> KResult<(InodeRef, Arc<Dentry>)> {
    let mut cur_dentry = if path.starts_with('/') { root.clone() } else { start };
    let mut cur_inode = cur_dentry.inode().ok_or(VfsError::Enoent)?;
    let mut queue: Vec<String> = components(path);
    let mut idx = 0usize;
    let mut symlinks = 0u32;

    while idx < queue.len() {
        let comp = queue[idx].clone();
        idx += 1;
        let is_final = idx == queue.len();

        if comp == "." { continue; }
        if comp == ".." {
            // `..` at the resolution root (or BENEATH clamp) stays put,
            // matching Linux `/.. == /`.
            if !(flags.beneath && Arc::ptr_eq(&cur_dentry, &root)) {
                if let Some(par) = cur_dentry.parent() {
                    let par = par.clone();
                    if let Some(pi) = par.inode() { cur_inode = pi; cur_dentry = par; }
                }
            }
            continue;
        }

        // Resolve the named child: dentry-cache hit, else Inode::lookup.
        // The cache lock is never held across the Inode lookup (lock
        // order Inode < Dentry per 06§3.6).
        let child = match cur_dentry.cached_child(&comp) {
            Some(d) => d,
            None => {
                let ci = cur_inode.lookup(&comp)?;
                let d = Dentry::new(Some(cur_dentry.clone()), comp.clone(), ci);
                cur_dentry.cache_child(&comp, d)
            }
        };
        let mut child_inode = child.inode().ok_or(VfsError::Enoent)?;

        // Mount crossing: if a filesystem is mounted on this entry,
        // continue from its root inode (keep the mountpoint dentry as
        // the path node).
        let abs = String::from_utf8_lossy(&child.absolute_path()).into_owned();
        if let Some(mroot) = resolve_mount(&abs) { child_inode = mroot; }

        // Symlink handling (use the pre-mount-cross inode; a mount point
        // is a directory, never a symlink).
        if matches!(child.inode().map(|i| i.file_type()), Some(FileType::Symlink)) {
            if flags.no_symlinks { return Err(VfsError::Eloop); }
            if is_final && flags.no_follow_final {
                return Ok((child.inode().ok_or(VfsError::Enoent)?, child));
            }
            symlinks += 1;
            if symlinks > MAX_SYMLINK_DEPTH { return Err(VfsError::Eloop); }
            let target = child.inode().ok_or(VfsError::Enoent)?.readlink()?;
            let target = String::from_utf8_lossy(&target).into_owned();
            // Splice the symlink target's components ahead of whatever
            // remains, then restart the queue.
            let mut next: Vec<String> = components(&target);
            next.extend_from_slice(&queue[idx..]);
            queue = next;
            idx = 0;
            if target.starts_with('/') {
                // Absolute target: restart at root (BENEATH forbids the
                // escape — Linux returns EXDEV; we surface ELOOP).
                if flags.beneath { return Err(VfsError::Eloop); }
                cur_dentry = root.clone();
                cur_inode = cur_dentry.inode().ok_or(VfsError::Enoent)?;
            }
            // Relative target: keep walking from the symlink's directory
            // (cur_dentry / cur_inode unchanged).
            continue;
        }

        // Plain descent.
        cur_dentry = child;
        cur_inode = child_inode;
    }

    Ok((cur_inode, cur_dentry))
}
