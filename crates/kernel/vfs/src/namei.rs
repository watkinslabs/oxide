//! `path_lookup` per `docs/16§3` — the single component-walking name
//! resolver. Walks a path one component at a time via the dentry cache
//! (`Dentry::cached_child`) falling back to `Inode::lookup(name)`,
//! crosses mount points, follows symlinks with a depth limit, and
//! honors dirfd-relative bases + RESOLVE flags. Returns the final
//! `(InodeRef, Dentry)`.
//!
//! Mount crossing is keyed by dentry identity plus mount namespace. The
//! dentry records the covering mount id for each namespace, and the mount
//! table owns the mounted root inode. The walker itself is otherwise
//! filesystem-agnostic: it only needs `Inode::lookup`/`readlink`/
//! `file_type`, so it works over ext4, tmpfs, and any backend that
//! implements per-component lookup.

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

/// Linux-style resolved path: a dentry is only meaningful together with the
/// mount that owns it. `inode` is cached from `dentry`/mount crossing for the
/// current lookup result.
#[derive(Clone)]
pub struct VfsPath {
    pub mnt_id: u64,
    pub dentry: Arc<Dentry>,
    pub inode: InodeRef,
}

/// Whole-path delegate: resolves an absolute path within its owning
/// mount by that mount's own lookup (`vfs::mount::lookup`). Used when a
/// per-component `Inode::lookup` returns Enotdir/Eopnotsupp because the
/// filesystem at that point resolves whole-path, not per-component
/// (procfs synthesises `/proc/<pid>/<file>` from the full path). This is
/// the OWNING MOUNT resolving its own subtree — not a global legacy
/// fallback (which would bypass per-component symlink resolution).
type WholePath = fn(&str) -> Option<InodeRef>;
static MOUNT_WHOLE_PATH: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the whole-path in-mount delegate. Called once at boot.
/// # C: O(1)
pub fn set_mount_whole_path(f: WholePath) {
    MOUNT_WHOLE_PATH.store(f as *mut (), Ordering::Release);
}

fn whole_path(abs: &str) -> Option<InodeRef> {
    let p = MOUNT_WHOLE_PATH.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: only ever stores a `WholePath` fn pointer via the setter.
    let f: WholePath = unsafe { core::mem::transmute(p) };
    f(abs)
}

/// Global root-dentry provider — supplies the start of an absolute mount-
/// identification walk (`walk_to_mount`). Installed at boot from the syscall
/// layer (`pathresolve::root_dentry`), so the vfs crate can begin an
/// absolute walk without a caller-supplied root. # C: O(1)
type RootDentry = fn() -> Option<Arc<Dentry>>;
static ROOT_DENTRY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the global root-dentry provider. Called once at boot. # C: O(1)
pub fn set_root_dentry_provider(f: RootDentry) {
    ROOT_DENTRY.store(f as *mut (), Ordering::Release);
}

fn root_dentry() -> Option<Arc<Dentry>> {
    let p = ROOT_DENTRY.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: only ever stores a `RootDentry` fn pointer via the setter.
    let f: RootDentry = unsafe { core::mem::transmute(p) };
    f()
}

/// Identify the mount that OWNS absolute `path` — the `mnt_id` of the
/// deepest mount whose subtree contains `path` (Linux: the `path.mnt` a
/// `path_lookup` would leave you in). Walks components from the global root,
/// descending via `Inode::lookup` and crossing mounts via
/// `Dentry::mounted_mount`, tracking the last-crossed mount id. CRUCIAL: it
/// NEVER invokes the whole-path delegate, so `resolve_mount → lookup →
/// resolve_mount` cannot recurse through a whole-path filesystem (procfs).
/// On a missing/whole-path component it STOPS and returns the current
/// (owning) mount, so open-create/rename/link on a not-yet-existing leaf
/// still yield the parent's mount. `None` only before the root exists.
/// # C: O(components × dir-lookup)
pub fn walk_to_mount(path: &str) -> Option<u64> {
    let root = root_dentry()?;
    let ns = crate::mount::current_ns();
    let mut cur_dentry = root.clone();
    let mut cur_inode = root.inode()?;
    let mut cur_mnt = crate::mount::root_mount_id(ns).unwrap_or(0);
    // Root itself may be a mountpoint in this ns.
    if let Some(id) = cur_dentry.mounted_mount(ns) {
        if let Some(r) = crate::mount::root_for_mount_id(id) { cur_inode = r; cur_mnt = id; }
    }
    for comp in components(path) {
        if comp == "." { continue; }
        if comp == ".." {
            if let Some(p) = cur_dentry.parent() {
                let p = p.clone();
                if let Some(pi) = p.inode() { cur_inode = pi; cur_dentry = p; }
            }
            continue;
        }
        let child = match cur_dentry.cached_child(&comp) {
            Some(d) => d,
            None => match cur_inode.lookup(&comp) {
                Ok(ci) => {
                    let d = Dentry::new(Some(cur_dentry.clone()), comp.clone(), ci);
                    cur_dentry.cache_child(&comp, d)
                }
                // Missing leaf or whole-path fs: stop; current mount owns it.
                Err(_) => return Some(cur_mnt),
            },
        };
        let mut ci = match child.inode() { Some(i) => i, None => return Some(cur_mnt) };
        if let Some(id) = child.mounted_mount(ns) {
            if let Some(r) = crate::mount::root_for_mount_id(id) { ci = r; cur_mnt = id; }
        }
        cur_dentry = child;
        cur_inode = ci;
    }
    Some(cur_mnt)
}

/// Join `base` (an absolute dir path) + `comp` + `rest` into one
/// absolute path, for delegating the remaining walk to the owning
/// mount's whole-path lookup.
/// # C: O(total len)
fn join_abs(base: &[u8], comp: &str, rest: &[String]) -> String {
    let mut s = String::from_utf8_lossy(base).into_owned();
    if !s.ends_with('/') { s.push('/'); }
    s.push_str(comp);
    for c in rest { s.push('/'); s.push_str(c); }
    s
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
    let p = path_lookup_path(start, root, path, flags)?;
    Ok((p.inode, p.dentry))
}

/// Resolve `path` to a full VFS path object, preserving the mount identity
/// that owns the final dentry. This is the shape syscall/front-end code must
/// migrate to; `path_lookup` remains only as a compatibility wrapper while
/// callers are converted.
/// # C: O(components × dir-lookup) + O(symlinks)
pub fn path_lookup_path(
    start: Arc<Dentry>,
    root: Arc<Dentry>,
    path: &str,
    flags: LookupFlags,
) -> KResult<VfsPath> {
    let mut cur_dentry = if path.as_bytes().first() == Some(&b'/') { root.clone() } else { start };
    let mut cur_inode = cur_dentry.inode().ok_or(VfsError::Enoent)?;
    let mut cur_mnt_id = crate::mount::root_mount_id(crate::mount::current_ns()).unwrap_or(0);
    // Start-crossing: if the base dentry (a relative walk's cwd/dirfd base,
    // or a chroot resolution root) is ITSELF a mountpoint in this ns, begin
    // in the mounted root — Linux holds cwd/dirfd/root as `(vfsmount,
    // mnt_root)`, so resolution from a mounted directory runs inside that fs,
    // not the covered underlay. The stored base dentry is the UNDERLAY
    // mountpoint dentry (it carries the covering link), and `cur_dentry
    // .inode()` above gave the underlay inode (e.g. the empty ext4 `/dev`);
    // re-seat the start INODE on the mounted root so e.g. `chroot(/dev)` +
    // absolute lookups resolve in devfs. This keeps the same `(underlay
    // dentry, mounted inode)` pairing the mid-walk crossing below produces,
    // so the walk is self-consistent.
    //
    // The TRUE global namespace root (`Dentry::new_root`: no parent, empty
    // name) is never a mountpoint — `wire_crossing` skips "/" — but guard it
    // explicitly so a stray covering link can never re-seat the root inode of
    // a plain absolute walk. Only a covered NON-global base crosses, and only
    // when the mount table yields a real mounted root (else keep the underlay
    // inode rather than substitute a wrong/None one).
    let is_global_root = cur_dentry.parent().is_none() && cur_dentry.name().is_empty();
    if !is_global_root {
        if let Some(mnt_id) = cur_dentry.mounted_mount(crate::mount::current_ns()) {
            if let Some(r) = crate::mount::root_for_mount_id(mnt_id) {
                cur_inode = r;
                cur_mnt_id = mnt_id;
            }
        }
    }
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
            None => match cur_inode.lookup(&comp) {
                Ok(ci) => {
                    let d = Dentry::new(Some(cur_dentry.clone()), comp.clone(), ci);
                    cur_dentry.cache_child(&comp, d)
                }
                Err(e) => {
                    // Per-component lookup failed. If the current
                    // filesystem resolves whole-path (procfs synthesises
                    // from the full path; its dir inodes return Enotdir
                    // on Inode::lookup), delegate the remaining absolute
                    // path to the owning mount's lookup — the mount
                    // resolving its own subtree. A genuinely-missing name
                    // makes the delegate also miss, so the error stands.
                    let full = join_abs(&cur_dentry.absolute_path(), &comp, &queue[idx..]);
                    if let Some(i) = whole_path(&full) {
                        let d = Dentry::new(None, full, i.clone());
                        return Ok(VfsPath { mnt_id: cur_mnt_id, dentry: d, inode: i });
                    }
                    return Err(e);
                }
            },
        };
        let mut child_inode = child.inode().ok_or(VfsError::Enoent)?;

        // Mount crossing (`docs/16§3`): keyed by dentry identity and the
        // current mount namespace. The dentry only tells us which concrete
        // mount covers it; the mount table owns that mount's root.
        if let Some(mnt_id) = child.mounted_mount(crate::mount::current_ns()) {
            child_inode = crate::mount::root_for_mount_id(mnt_id).ok_or(VfsError::Enoent)?;
            cur_mnt_id = mnt_id;
        }

        // Symlink handling (use the pre-mount-cross inode; a mount point
        // is a directory, never a symlink).
        if matches!(child.inode().map(|i| i.file_type()), Some(FileType::Symlink)) {
            if flags.no_symlinks { return Err(VfsError::Eloop); }
            if is_final && flags.no_follow_final {
                let inode = child.inode().ok_or(VfsError::Enoent)?;
                return Ok(VfsPath { mnt_id: cur_mnt_id, dentry: child, inode });
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
            if target.as_bytes().first() == Some(&b'/') {
                // Absolute target: restart at root (BENEATH forbids the
                // escape — Linux returns EXDEV; we surface ELOOP).
                if flags.beneath { return Err(VfsError::Eloop); }
                cur_dentry = root.clone();
                cur_inode = cur_dentry.inode().ok_or(VfsError::Enoent)?;
                cur_mnt_id = crate::mount::root_mount_id(crate::mount::current_ns()).unwrap_or(0);
            }
            // Relative target: keep walking from the symlink's directory
            // (cur_dentry / cur_inode unchanged).
            continue;
        }

        // Plain descent.
        cur_dentry = child;
        cur_inode = child_inode;
    }

    Ok(VfsPath { mnt_id: cur_mnt_id, dentry: cur_dentry, inode: cur_inode })
}
