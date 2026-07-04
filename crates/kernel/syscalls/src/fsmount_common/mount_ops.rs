#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::Dentry;

use super::registry::ensure_filesystems_registered;

fn graft_mount(spec: vfs::fs::MountSpec, target_d: &Arc<Dentry>, parent_hint: Option<u64>) -> i64 {
    if spec.strict {
        let res = match spec.bind_root {
            Some(root) => vfs::mount::register_bind_at(Some(target_d.clone()), spec.fs, root, parent_hint),
            None => vfs::mount::register_at(Some(target_d.clone()), spec.fs, parent_hint),
        };
        match res {
            Ok(()) => { let _ = vfs::mount::propagate_mount(target_d); 0 }
            Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
            Err(e) => crate::namei_common::errno_from_vfs(e),
        }
    } else {
        match spec.bind_root {
            Some(root) => { let _ = vfs::mount::register_bind_at(Some(target_d.clone()), spec.fs, root, parent_hint); }
            None => { let _ = vfs::mount::register_at(Some(target_d.clone()), spec.fs, parent_hint); }
        }
        let _ = vfs::mount::propagate_mount(target_d);
        0
    }
}

/// # C: O(N_mounts + optional block-registry lookup)
pub(crate) fn mount_fstype(source: &str, fstype: &str, target: &str, target_d: &Arc<Dentry>) -> i64 {
    mount_fstype_with_data(source, fstype, target, target_d, "")
}

pub(crate) fn mount_fstype_with_data(source: &str, fstype: &str, target: &str, target_d: &Arc<Dentry>, data: &str) -> i64 {
    ensure_filesystems_registered();
    if let Some(ty) = vfs::fs::get_fs(fstype) {
        let spec = match ty.construct(source, target, data) {
            Ok(s) => s,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        let phint = crate::pathresolve::resolve_path(target, false).map(|p| p.mnt_id);
        return graft_mount(spec, target_d, phint);
    }
    match fstype {
        "devpts" | "cgroup" => 0,
        _ => -(Errno::Enodev.as_i32() as i64),
    }
}
