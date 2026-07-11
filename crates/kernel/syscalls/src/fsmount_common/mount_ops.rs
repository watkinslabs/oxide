#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use vfs::Dentry;

use super::registry::ensure_filesystems_registered;

fn graft_mount(sb: Arc<vfs::SuperBlock>, target_d: &Arc<Dentry>, parent_hint: Option<u64>) -> i64 {
    match vfs::mount::attach_sb_with_flags_at(Some(target_d.clone()), sb, 0, parent_hint) {
        Ok(()) => { let _ = vfs::mount::propagate_mount(target_d); 0 }
        Err(vfs::VfsError::Eexist) => -(Errno::Ebusy.as_i32() as i64),
        Err(e) => crate::namei_common::errno_from_vfs(e),
    }
}

pub(crate) fn mount_fstype_at(source: Option<&str>, fstype: &str, target: &str, target_d: &Arc<Dentry>, parent_hint: Option<u64>, data: &str) -> i64 {
    ensure_filesystems_registered();
    if let Some(ty) = vfs::fs::get_fs(fstype) {
        let sb = match ty.construct(source, target, data) {
            Ok(s) => s,
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        return graft_mount(sb, target_d, parent_hint);
    }
    match fstype {
        "devpts" | "cgroup" => 0,
        _ => -(Errno::Enodev.as_i32() as i64),
    }
}
