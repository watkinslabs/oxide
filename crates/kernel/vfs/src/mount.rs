//! Mount table per `docs/16` mount-point routing. Owns the
//! `(path, FileSystem)` registry that `vfs::lookup` walks by
//! longest-prefix match. Replaces the hardcoded `if devfs::lookup
//! else if tmpfs::lookup else if ext4::lookup_inode` chains
//! duplicated across syscall handlers (R67).

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{MountTable as MountClass, Spinlock};

use crate::fs::{FileSystem, KResult};
use crate::inode::InodeRef;
use crate::types::VfsError;

/// One mount instance. Holds the FS impl and the absolute path
/// it's rooted at. The root mount is `mount_point == "/"`.
pub struct Mount {
    pub fs: Arc<dyn FileSystem>,
    pub mount_point: String,
}

static TABLE: Spinlock<Vec<Arc<Mount>>, MountClass> = Spinlock::new(Vec::new());

/// Register a FileSystem at `mount_point`. Idempotent: if the
/// same mount_point already has a mount, returns Ebusy.
/// # C: O(N_mounts) — linear scan + push.
pub fn register(mount_point: &str, fs: Arc<dyn FileSystem>) -> KResult<()> {
    let mut t = TABLE.lock();
    if t.iter().any(|m| m.mount_point == mount_point) {
        return Err(VfsError::Eexist);
    }
    t.push(Arc::new(Mount {
        fs,
        mount_point: mount_point.to_string(),
    }));
    Ok(())
}

/// Find the mount whose mount_point is the longest prefix of
/// `path`. Returns `(mount, relative_path)` where relative_path
/// is `path` with the mount_point stripped.
/// # C: O(N_mounts × max_mount_point_len)
pub fn resolve_mount(path: &str) -> Option<(Arc<Mount>, String)> {
    let t = TABLE.lock();
    let mut best: Option<&Arc<Mount>> = None;
    for m in t.iter() {
        // Match if path == mount_point OR path starts with "<mount_point>/".
        let mp = m.mount_point.as_str();
        let match_full = path == mp;
        let match_pref = mp.len() == 1 && mp == "/" /* root: always */
                      || (path.starts_with(mp) && path.as_bytes().get(mp.len()) == Some(&b'/'));
        if !(match_full || match_pref) { continue; }
        match best {
            None => best = Some(m),
            Some(cur) if mp.len() > cur.mount_point.len() => best = Some(m),
            _ => {}
        }
    }
    best.map(|m| {
        let rel = if m.mount_point == "/" {
            path.to_string()
        } else if path == m.mount_point {
            "/".to_string()
        } else {
            path[m.mount_point.len()..].to_string()
        };
        (m.clone(), rel)
    })
}

/// Unified path lookup. Walks the mount table by longest-prefix
/// match, then calls the matching FS's `lookup`. Replaces the
/// per-syscall hardcoded chains.
/// # C: O(N_mounts) for mount routing + O(FS-impl).
pub fn lookup(path: &str) -> KResult<InodeRef> {
    let (mnt, rel) = resolve_mount(path).ok_or(VfsError::Enoent)?;
    mnt.fs.lookup(&rel).ok_or(VfsError::Enoent)
}

/// Snapshot the mount table for `/proc/mounts`.
/// # C: O(N_mounts)
pub fn snapshot() -> Vec<Arc<Mount>> {
    TABLE.lock().clone()
}
