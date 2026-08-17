//! The `/proc/fs` directory, and the claim/publish/withdraw around it.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use kernfs::PseudoDir;
use sync::{Spinlock, TaskList as LockClass};
use vfs::{InodeRef, KResult, VfsError};

use super::file::{self, ShowFn, StoreFn};

/// Filesystem names holding a directory under `/proc/fs`.
static CLAIMED: Spinlock<Vec<String>, LockClass> = Spinlock::new(Vec::new());

/// One path component. # C: O(len)
fn valid_component(c: &str) -> bool {
    !c.is_empty() && c != "." && c != ".." && !c.contains('/') && !c.contains('\0')
}

/// Split a filesystem-relative path, refusing any component that could
/// resolve outside the filesystem's own directory. # C: O(len)
fn components(rel: &str) -> KResult<Vec<&str>> {
    let mut out = Vec::new();
    for c in rel.split('/') {
        if c.is_empty() { continue; }
        if !valid_component(c) { return Err(VfsError::Einval); }
        out.push(c);
    }
    Ok(out)
}

/// `/proc/fs`, created on first use, inside procfs's own registry tree.
/// # C: O(1)
pub fn proc_fs_root() -> Arc<PseudoDir> {
    let reg = crate::reg::proc_reg();
    reg.ensure_dir_path("fs");
    reg.lookup_dir("fs").expect("just created")
}

/// The `/proc/fs` directory inode, for the `/proc` root to hold as a child.
///
/// The `/proc` root lists the children it holds, so a directory reachable only
/// through the registry would resolve by name and be missing from `ls /proc` —
/// which is how `/proc/sys` and `/proc/net` are wired, and how this is too.
/// # C: O(1)
pub fn proc_fs_inode() -> InodeRef { proc_fs_root().as_inode() }

/// Claim `/proc/fs/<name>` for one filesystem. # C: O(N claimed)
pub fn claim(name: &str) -> KResult<()> {
    if !valid_component(name) { return Err(VfsError::Einval); }
    let mut held = CLAIMED.lock();
    if held.iter().any(|n| n == name) { return Err(VfsError::Eexist); }
    held.push(name.to_string());
    drop(held);
    proc_fs_root().ensure_dir_path(name);
    Ok(())
}

/// Whether `name` currently holds a `/proc/fs` directory. # C: O(N claimed)
pub fn is_claimed(name: &str) -> bool { CLAIMED.lock().iter().any(|n| n == name) }

/// Drop a filesystem's whole `/proc/fs` directory and its claim. # C: O(subtree)
pub fn release(name: &str) -> KResult<()> {
    let mut held = CLAIMED.lock();
    match held.iter().position(|n| n == name) {
        Some(i) => { held.remove(i); }
        None => return Err(VfsError::Enoent),
    }
    drop(held);
    let _ = proc_fs_root().remove_subtree_inodes(name);
    Ok(())
}

/// Resolve `fsname` + `rel` to a path under `/proc/fs`. # C: O(len)
fn path_in(fsname: &str, rel: &str) -> KResult<String> {
    if !is_claimed(fsname) { return Err(VfsError::Enoent); }
    let mut path = fsname.to_string();
    for c in components(rel)? {
        path.push('/');
        path.push_str(c);
    }
    Ok(path)
}

/// Create a directory under a claimed filesystem — the per-mount directory an
/// upstream `proc_mkdir(sb->s_id, root)` makes. # C: O(components)
pub fn publish_dir(fsname: &str, rel: &str) -> KResult<()> {
    let path = path_in(fsname, rel)?;
    proc_fs_root().ensure_dir_path(&path);
    Ok(())
}

/// Publish one seq file at `/proc/fs/<fsname>/<dir>/<name>`.
///
/// `store` is `None` for a report, which then refuses writes; a control
/// supplies one. # C: O(components)
pub fn publish_file(fsname: &str, dir: &str, name: &str, mode: u16, show: ShowFn,
                    store: Option<StoreFn>) -> KResult<()> {
    if !valid_component(name) { return Err(VfsError::Einval); }
    let parent = path_in(fsname, dir)?;
    let inode = file::make(mode, show, store, crate::ino::next_ino());
    let mut path = parent;
    path.push('/');
    path.push_str(name);
    proc_fs_root().insert_path(&path, inode);
    Ok(())
}

/// Remove one subtree under a claimed filesystem — the directory an unmount
/// published, with every file in it. # C: O(subtree)
pub fn withdraw(fsname: &str, rel: &str) -> KResult<()> {
    if rel.is_empty() { return Err(VfsError::Einval); }
    let path = path_in(fsname, rel)?;
    if proc_fs_root().remove_subtree_inodes(&path).is_empty()
        && proc_fs_root().lookup_dir(&path).is_none() {
        return Err(VfsError::Enoent);
    }
    Ok(())
}

/// Every filesystem name holding a `/proc/fs` directory, sorted. # C: O(N log N)
pub fn fs_names() -> Vec<String> {
    let mut v: Vec<String> = CLAIMED.lock().clone();
    v.sort();
    v
}

/// Entries a published directory holds, sorted. # C: O(N children)
pub fn names_in(fsname: &str, rel: &str) -> KResult<Vec<String>> {
    let path = path_in(fsname, rel)?;
    match proc_fs_root().lookup_dir(&path) {
        Some(d) => Ok(d.child_names()),
        None => Err(VfsError::Enoent),
    }
}
