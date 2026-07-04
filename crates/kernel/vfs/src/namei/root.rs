extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::{KResult, VfsError};

use super::{components, dotdot_step, follow_mount_down, path_lookup_path, LookupFlags};

/// Resolve absolute `path` to its inode by the per-component walk from root.
/// # C: O(path components)
pub fn resolve_abs(path: &str) -> KResult<InodeRef> {
    let root = root_dentry().ok_or(VfsError::Enoent)?;
    let p = path_lookup_path(root.clone(), root, path, LookupFlags::default())?;
    Ok(p.inode)
}

/// Resolve absolute `path` to its canonical DENTRY (parent chain intact) by
/// the per-component walk from the global root. Used by `install_open` to
/// obtain the real parent dentry for an opened file. `None` if the root dentry
/// isn't built yet (early boot) or the path doesn't resolve. # C: O(components)
pub fn resolve_path_dentry(path: &str) -> Option<Arc<Dentry>> {
    let root = root_dentry()?;
    path_lookup_path(root.clone(), root, path, LookupFlags::default())
        .ok()
        .map(|p| p.dentry)
}

/// Global root-dentry provider — supplies the start of an absolute mount-
/// identification walk (`walk_to_mount`). Installed at boot from the syscall
/// layer (`pathresolve::root_dentry`). # C: O(1)
type RootDentry = fn() -> Option<Arc<Dentry>>;
static ROOT_DENTRY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the global root-dentry provider. Called once at boot. # C: O(1)
pub fn set_root_dentry_provider(f: RootDentry) {
    ROOT_DENTRY.store(f as *mut (), Ordering::Release);
}

/// The installed global root dentry (start of an absolute walk), or `None`
/// before the provider is installed. # C: O(1)
pub fn root_dentry() -> Option<Arc<Dentry>> {
    let p = ROOT_DENTRY.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: only ever stores a `RootDentry` fn pointer via the setter.
    let f: RootDentry = unsafe { core::mem::transmute(p) };
    f()
}

/// Identify the mount that OWNS absolute `path` — the `mnt_id` of the deepest
/// mount whose subtree contains `path`. Walks components from the global root,
/// crossing mounts to the mounted fs `s_root` (Linux `__follow_mount`) so the
/// dcache stays canonical with `path_lookup`, tracking the last-crossed mount
/// id. NEVER invokes a whole-path delegate (so `resolve_mount → lookup →
/// resolve_mount` cannot recurse). On a missing/whole-path component it STOPS
/// and returns the current (owning) mount, so open-create/rename/link on a
/// not-yet-existing leaf still yield the parent's mount. `None` only before the
/// root exists. # C: O(components × dir-lookup)
pub fn walk_to_mount(path: &str) -> Option<u64> {
    let root = root_dentry()?;
    let ns = crate::mount::current_ns();
    let root_mnt = crate::mount::root_mount_id(ns).unwrap_or(crate::mount::MNT_ID_NONE);
    let (mut cur_dentry, mut cur_inode, mut cur_mnt) =
        follow_mount_down(root.clone(), root_mnt).ok()?;
    for comp in components(path) {
        // `.`/empty already dropped by `components` (single splitter, path.rs).
        if comp == ".." {
            // Mount-identification walk: the root-clamp escape signal is
            // irrelevant here (no RESOLVE_BENEATH on this internal walk).
            let _ = dotdot_step(&mut cur_dentry, &mut cur_mnt, &mut cur_inode, &root, root_mnt);
            continue;
        }
        // dcache fast path (d_lookup) then slow path (i_op->lookup + d_add).
        let child = match crate::dcache::d_lookup(&cur_dentry, &comp) {
            Some(d) if !d.is_negative() => d,
            Some(_) => return Some(cur_mnt), // cached negative: current mount owns it
            None => match cur_inode.lookup(&comp) {
                Ok(ci) => {
                    // D3/D37: release the iget/build temporary; the dentry's
                    // `d_add` grab is the durable hold (see `walk`'s slow path).
                    let child = crate::dcache::d_add(&cur_dentry, &comp, ci.clone());
                    crate::file::iput(ci);
                    child
                }
                Err(_) => return Some(cur_mnt), // missing leaf / whole-path fs
            },
        };
        // Cross to the mounted fs `s_root` (keystone) for the next component.
        match follow_mount_down(child, cur_mnt) {
            Ok((nd, ni, nm)) => { cur_dentry = nd; cur_inode = ni; cur_mnt = nm; }
            Err(_) => return Some(cur_mnt),
        }
    }
    Some(cur_mnt)
}
