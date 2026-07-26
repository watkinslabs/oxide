// Module manifest: `registry` owns fs-type admission/registration;
// `mount_ops` owns the kernel-only glue (registration + user-string reads);
// `mount_dispatch` owns the pure fstype→graft-or-honest-errno decision
// (ungated, hosted-testable); `objects` owns fs_context and detached-mount
// inode types; `fd` owns user-string/fd installation helpers.

#![cfg(target_os = "oxide-kernel")]

mod fd;
mod mount_dispatch;
mod mount_ops;
mod objects;
mod registry;

pub(crate) use fd::{fd_inode, install_fd, read_cstr_req, read_path_allow_empty};
pub(crate) use mount_ops::mount_fstype_at;
pub use objects::{FsContextInode, MountObjectInode};
pub(crate) use registry::{fstype_ok, require_sys_admin};
pub use registry::ensure_filesystems_registered;
