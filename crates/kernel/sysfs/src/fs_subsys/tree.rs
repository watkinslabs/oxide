//! The `/sys/fs` directory, and the claim/publish/withdraw around it.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::{KResult, VfsError};

use super::attr::{self, ShowFn, StoreFn};

/// Filesystem names that have claimed a directory under `/sys/fs`.
static CLAIMED: Spinlock<Vec<String>, LockClass> = Spinlock::new(Vec::new());

/// One path component of a sysfs name. Upstream a kobject name is any string
/// without a separator; the three that would resolve somewhere other than
/// where they were written are refused rather than silently normalised.
/// # C: O(len)
fn valid_component(c: &str) -> bool {
    !c.is_empty() && c != "." && c != ".." && !c.contains('/') && !c.contains('\0')
}

/// Split a subsystem-relative path into its components, rejecting any that
/// could escape the subsystem's own directory. An empty path is the
/// subsystem root itself and yields no components. # C: O(len)
fn components(rel: &str) -> KResult<Vec<&str>> {
    let mut out = Vec::new();
    for c in rel.split('/') {
        if c.is_empty() { continue; }
        if !valid_component(c) { return Err(VfsError::Einval); }
        out.push(c);
    }
    Ok(out)
}

/// `/sys/fs`, created on first use.
///
/// Upstream creates this unconditionally as the mount machinery comes up, so
/// it exists whether or not a filesystem has anything to publish; [`init`] is
/// what reproduces that at boot. Building it here as well means a caller that
/// runs before boot registration — a test, or a filesystem registered late —
/// still gets the one directory rather than a second tree.
/// # C: O(1)
pub fn fs_root() -> Arc<PseudoDir> {
    let root = crate::root::sys_root();
    root.ensure_dir_path("fs");
    root.lookup_dir("fs").expect("just created")
}

/// Create `/sys/fs` at boot, before any filesystem registers. # C: O(1)
pub fn init() { let _ = fs_root(); }

/// Claim `/sys/fs/<name>` for one filesystem.
///
/// The name is the filesystem's, not a mount's: one claim serves every mount
/// of that type, exactly as one kset does upstream. A second claim of a name
/// already held reports `EEXIST` rather than letting two filesystems write
/// into one directory.
/// # C: O(N claimed)
pub fn claim(name: &str) -> KResult<()> {
    if !valid_component(name) { return Err(VfsError::Einval); }
    let mut held = CLAIMED.lock();
    if held.iter().any(|n| n == name) { return Err(VfsError::Eexist); }
    held.push(name.to_string());
    drop(held);
    fs_root().ensure_dir_path(name);
    Ok(())
}

/// Whether `name` currently holds a `/sys/fs` directory. # C: O(N claimed)
pub fn is_claimed(name: &str) -> bool {
    CLAIMED.lock().iter().any(|n| n == name)
}

/// Drop a filesystem's whole `/sys/fs` directory and its claim. # C: O(subtree)
pub fn release(name: &str) -> KResult<()> {
    let mut held = CLAIMED.lock();
    match held.iter().position(|n| n == name) {
        Some(i) => { held.remove(i); }
        None => return Err(VfsError::Enoent),
    }
    drop(held);
    let _ = fs_root().remove_subtree_inodes(name);
    crate::drop_cached(&alloc::format!("/sys/fs/{name}"));
    Ok(())
}

/// Resolve `subsys` + `rel` to a path under `/sys/fs`, refusing an unclaimed
/// subsystem. Publishing into a name nobody claimed would create a directory
/// with no owner and no way to remove it. # C: O(len)
fn path_in(subsys: &str, rel: &str) -> KResult<String> {
    if !is_claimed(subsys) { return Err(VfsError::Enoent); }
    let mut path = subsys.to_string();
    for c in components(rel)? {
        path.push('/');
        path.push_str(c);
    }
    Ok(path)
}

/// Create a directory under a claimed subsystem.
///
/// Needed on its own because a directory upstream declares can be empty: the
/// attributes it would hold belong to a facility this build does not have, and
/// an absent directory is a different statement from an empty one.
/// # C: O(components)
pub fn publish_dir(subsys: &str, rel: &str) -> KResult<()> {
    let path = path_in(subsys, rel)?;
    fs_root().ensure_dir_path(&path);
    Ok(())
}

/// Publish one live attribute file at `/sys/fs/<subsys>/<dir>/<name>`.
///
/// `dir` is empty for an attribute directly under the subsystem. `store` is
/// `None` for a read-only attribute, which then refuses writes with `EROFS`.
/// # C: O(components)
pub fn publish_attr(subsys: &str, dir: &str, name: &str, mode: u16,
                    show: ShowFn, store: Option<StoreFn>) -> KResult<()> {
    if !valid_component(name) { return Err(VfsError::Einval); }
    let parent = path_in(subsys, dir)?;
    let inode = attr::make(name.to_string(), mode, show, store);
    let mut path = parent;
    path.push('/');
    path.push_str(name);
    fs_root().insert_path(&path, inode);
    Ok(())
}

/// Remove one subtree under a claimed subsystem — the directory an unmount
/// published, with everything under it. # C: O(subtree)
pub fn withdraw(subsys: &str, rel: &str) -> KResult<()> {
    if rel.is_empty() { return Err(VfsError::Einval); }
    let path = path_in(subsys, rel)?;
    if fs_root().remove_subtree_inodes(&path).is_empty()
        && fs_root().lookup_dir(&path).is_none() {
        return Err(VfsError::Enoent);
    }
    crate::drop_cached(&alloc::format!("/sys/fs/{path}"));
    Ok(())
}

/// Every filesystem name holding a `/sys/fs` directory, sorted. # C: O(N log N)
pub fn subsys_names() -> Vec<String> {
    let mut v: Vec<String> = CLAIMED.lock().clone();
    v.sort();
    v
}

/// Entries a published directory holds, sorted — what a listing of it shows.
/// # C: O(N children)
pub fn names_in(subsys: &str, rel: &str) -> KResult<Vec<String>> {
    let path = path_in(subsys, rel)?;
    match fs_root().lookup_dir(&path) {
        Some(d) => Ok(d.child_names()),
        None => Err(VfsError::Enoent),
    }
}
