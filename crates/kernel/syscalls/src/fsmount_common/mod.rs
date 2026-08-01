// Module manifest: `registry` owns fs-type admission/registration;
// `mount_ops` owns the kernel-only glue (registration + user-string reads);
// `mount_dispatch` owns the pure fstype→mount_capable→graft-or-honest-errno decision
// (ungated, hosted-testable); `objects` owns fs_context and detached-mount
// inode types; `fd` owns user-string/fd installation helpers.

#![cfg(target_os = "oxide-kernel")]

mod fd;
mod mount_dispatch;
mod mount_ops;
mod objects;
mod registry;

pub(crate) use mount_dispatch::{mount_capable, MountCaps};
pub(crate) use fd::{
    fd_file, fd_inode, install_fd, install_path_fd, read_cstr_req, read_cstr_strndup,
    read_path_allow_empty,
};
pub(crate) use mount_ops::mount_fstype_at;
pub use objects::{FsContextInode, MountObjectInode};
pub(crate) use crate::mount_perm::may_mount_or_eperm;
pub use registry::ensure_filesystems_registered;
