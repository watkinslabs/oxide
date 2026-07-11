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

pub(crate) fn mount_fstype_at(source: &str, fstype: &str, target: &str, target_d: &Arc<Dentry>, parent_hint: Option<u64>, data: &str) -> i64 {
    ensure_filesystems_registered();
    if let Some(ty) = vfs::fs::get_fs(fstype) {
        let spec = match ty.construct(source, target, data) {
            Ok(s) => s,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        return graft_mount(spec, target_d, parent_hint);
    }
    match fstype {
        "devpts" | "cgroup" => 0,
        _ => -(Errno::Enodev.as_i32() as i64),
    }
}
