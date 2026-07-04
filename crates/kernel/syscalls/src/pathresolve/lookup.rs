#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use vfs::fs::FileSystem;

use super::cred::current_cred;
use super::root::{resolution_root, root_dentry};

/// # C: O(components × dir-lookup)
pub fn resolve(abs: &str, no_follow_final: bool) -> Option<vfs::InodeRef> {
    resolve_path(abs, no_follow_final).map(|p| p.inode)
}

/// # C: O(components × dir-lookup)
pub fn resolve_path(abs: &str, no_follow_final: bool) -> Option<vfs::VfsPath> {
    resolve_path_result(abs, no_follow_final).ok()
}

/// # C: O(components × dir-lookup)
pub fn resolve_result(abs: &str, no_follow_final: bool) -> Result<vfs::InodeRef, vfs::VfsError> {
    resolve_path_result(abs, no_follow_final).map(|p| p.inode)
}

/// # C: O(components × dir-lookup)
pub fn resolve_path_result(abs: &str, no_follow_final: bool) -> Result<vfs::VfsPath, vfs::VfsError> {
    resolve_path_flags(abs, vfs::LookupFlags { no_follow_final, ..Default::default() })
}

/// # C: O(components × dir-lookup)
pub fn resolve_path_flags(abs: &str, mut flags: vfs::LookupFlags) -> Result<vfs::VfsPath, vfs::VfsError> {
    let (root, beneath) = resolution_root().ok_or(vfs::VfsError::Enoent)?;
    flags.beneath = flags.beneath || beneath;
    let Some(cur) = sched::live::current() else {
        return vfs::path_lookup_cred(root.clone(), root, abs, flags, vfs::Cred::root());
    };
    // SAFETY: cwd_vfs slot single-mutator per 13§5; current task is the sole writer.
    let start = unsafe { (*cur.cwd_vfs.get()).clone().map(|p| p.dentry) }.unwrap_or_else(|| root.clone());
    match vfs::path_lookup_cred(start, root, abs, flags, current_cred()) {
        Ok(p) => Ok(p),
        Err(vfs::VfsError::Enoent) if abs.starts_with("/proc/") => resolve_procfs_fallback(abs).ok_or(vfs::VfsError::Enoent),
        Err(e) => Err(e),
    }
}

/// # C: O(components)
pub fn resolve_parent_path(abs: &str) -> Result<vfs::VfsPath, vfs::VfsError> {
    resolve_path_flags(abs, vfs::LookupFlags { parent: true, ..Default::default() })
}

fn resolve_procfs_fallback(abs: &str) -> Option<vfs::VfsPath> {
    let rest = abs.strip_prefix("/proc/")?;
    if rest.is_empty() { return None; }
    let mut inode = procfs::static_files::proc_root() as vfs::InodeRef;
    let fs = Arc::new(procfs::fs_impl::ProcfsFs) as Arc<dyn FileSystem>;
    let sb = vfs::SuperBlock::for_backend(fs, fs, Some(inode.clone()), 0, String::from("procfs-fallback"));
    let mut dentry = vfs::d_make_root(inode.clone(), &sb);
    for comp in rest.split('/').filter(|c| !c.is_empty()) {
        let child = match vfs::d_lookup(&dentry, comp) {
            Some(d) if !d.is_negative() => d,
            _ => {
                let ci = inode.lookup(comp).ok()?;
                vfs::d_add(&dentry, comp, ci)
            }
        };
        inode = child.inode()?;
        dentry = child;
    }
    Some(vfs::VfsPath { mnt_id: 0, dentry, inode, last_component: None })
}

/// # C: O(components × dir-lookup)
pub fn mount_dentry(abs: &str) -> Option<Arc<vfs::Dentry>> {
    resolve_path(abs, false).map(|p| p.dentry)
}
