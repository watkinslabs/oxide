#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use vfs::fs::FileSystem;

use super::cred::current_cred;
use super::root::resolution_root_vfs;

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
    let (root, beneath) = resolution_root_vfs().ok_or(vfs::VfsError::Enoent)?;
    flags.beneath = flags.beneath || beneath;
    let Some(cur) = sched::live::current() else {
        return vfs::path_lookup_at_root_cred(
            root.dentry.clone(), root.mnt_id, root.dentry, root.mnt_id,
            abs, flags, vfs::Cred::root());
    };
    // SAFETY: cwd_vfs slot single-mutator per 13§5; current task is the sole writer.
    let start = unsafe { (*cur.cwd_vfs.get()).clone() }.unwrap_or_else(|| root.clone());
    let start_mnt = start.mnt_id;
    let root_mnt = root.mnt_id;
    match vfs::path_lookup_at_root_cred(
        start.dentry, start.mnt_id, root.dentry, root.mnt_id, abs, flags, current_cred()) {
        Ok(p) => Ok(p),
        Err(vfs::VfsError::Enoent) if abs.starts_with("/proc/") => resolve_procfs_fallback(abs).ok_or(vfs::VfsError::Enoent),
        Err(vfs::VfsError::Enotdir) => {
            trace_lookup_enotdir(abs, start_mnt, root_mnt);
            Err(vfs::VfsError::Enotdir)
        }
        Err(e) => Err(e),
    }
}

#[cfg(feature = "debug-boot")]
fn trace_lookup_enotdir(abs: &str, start_mnt: u64, root_mnt: u64) {
    klog::write_raw(b"[ENOTDIR] op=resolve_path_flags why=walk tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" start_mnt=");
    klog::write_dec_u64(start_mnt);
    klog::write_raw(b" root_mnt=");
    klog::write_dec_u64(root_mnt);
    klog::write_raw(b" path=");
    klog::write_raw(abs.as_bytes());
    if let Some(c) = sched::live::current() {
        // SAFETY: cwd slot single-mutator per 13§5; current task is sole reader here.
        let cwd = unsafe { (*c.cwd.get()).clone() };
        klog::write_raw(b" cwd=");
        klog::write_raw(cwd.as_bytes());
    }
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-boot"))]
fn trace_lookup_enotdir(_abs: &str, _start_mnt: u64, _root_mnt: u64) {}

/// # C: O(components)
pub fn resolve_parent_path(abs: &str) -> Result<vfs::VfsPath, vfs::VfsError> {
    resolve_path_flags(abs, vfs::LookupFlags { parent: true, ..Default::default() })
}

/// Resolve a mount syscall target as Linux `struct path`: final mountpoint
/// dentry plus the walked parent mount identity, without crossing the final
/// mountpoint. # C: O(components × dir-lookup)
pub fn resolve_mount_target(abs: &str) -> Result<vfs::MountTarget, vfs::VfsError> {
    let (root, _) = resolution_root_vfs().ok_or(vfs::VfsError::Enoent)?;
    let Some(cur) = sched::live::current() else {
        return vfs::mountpoint_lookup_at_root_cred(
            root.dentry.clone(), root.mnt_id, root.dentry, root.mnt_id, abs, vfs::Cred::root());
    };
    // SAFETY: cwd_vfs slot single-mutator per 13§5; current task is the sole writer.
    let start = unsafe { (*cur.cwd_vfs.get()).clone() }.unwrap_or_else(|| root.clone());
    let start_mnt = start.mnt_id;
    let root_mnt = root.mnt_id;
    let cred = current_cred();
    let res = vfs::mountpoint_lookup_at_root_cred(
        start.dentry, start_mnt, root.dentry, root_mnt, abs, cred);
    match res {
        Err(vfs::VfsError::Enotdir) => {
            trace_lookup_enotdir(abs, start_mnt, root_mnt);
            Err(vfs::VfsError::Enotdir)
        }
        other => other,
    }
}

/// Resolve `abs` to the dentry a mount operation targets, without crossing a
/// mount attached at the final component. Intermediate components still use the
/// normal mount-aware walk and the caller's current root.
/// # C: O(components × dir-lookup)
pub fn resolve_mountpoint_dentry(abs: &str) -> Result<Arc<vfs::Dentry>, vfs::VfsError> {
    if abs == "/" { return resolution_root_vfs().map(|(p, _)| p.dentry).ok_or(vfs::VfsError::Enoent); }
    let p = vfs::path::lexical_normalize(abs).ok_or(vfs::VfsError::Enoent)?;
    let mut parts = p.rsplitn(2, '/');
    let name = parts.next().ok_or(vfs::VfsError::Enoent)?;
    if name.is_empty() { return Err(vfs::VfsError::Enoent); }
    let parent_s = match parts.next() {
        Some("") | None => String::from("/"),
        Some(rest)      => {
            let mut s = String::from("/");
            s.push_str(rest.trim_start_matches('/'));
            s
        }
    };
    let parent = resolve_path_result(&parent_s, false)?;
    let pi = parent.dentry.inode().ok_or(vfs::VfsError::Enoent)?;
    match vfs::d_lookup(&parent.dentry, name) {
        Some(d) if !d.is_negative() => Ok(d),
        _ => {
            let ci = pi.lookup(name)?;
            Ok(vfs::d_add(&parent.dentry, name, ci))
        }
    }
}

fn resolve_procfs_fallback(abs: &str) -> Option<vfs::VfsPath> {
    let rest = abs.strip_prefix("/proc/")?;
    if rest.is_empty() { return None; }
    let mut inode = procfs::static_files::proc_root() as vfs::InodeRef;
    let fs = Arc::new(procfs::fs_impl::ProcfsFs) as Arc<dyn FileSystem>;
    let sb = vfs::SuperBlock::for_backend(fs, Some(inode.clone()), 0, String::from("procfs-fallback"));
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
