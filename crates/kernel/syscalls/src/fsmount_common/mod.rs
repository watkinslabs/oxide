// Module manifest: `registry` owns fs-type admission/registration;
// `caps` owns the one capability sampler fsmount(2)/open_tree(2) share;
// `mount_ops` owns the kernel-only glue (registration + user-string reads);
// `objects` owns fs_context and detached-mount
// inode types; `fscontext_ops` owns `read(2)` on the context fd; `fd` owns
// user-string/fd installation helpers.

#![cfg(target_os = "oxide-kernel")]

mod caps;
mod fd;
mod fscontext_ops;
mod mount_ops;
mod objects;
mod registry;

pub(crate) use caps::sample_caps;
pub(crate) use crate::mount_capable::{mount_capable, MountCaps};
pub(crate) use fd::{
    fd_file, fd_inode, install_fd, install_mount_path_fd, install_path_fd, read_cstr_req,
    read_path_allow_empty,
};
pub(crate) use mount_ops::mount_fstype_at;
pub use objects::{FsContextInode, MountObjectInode};
pub(crate) use crate::mount_perm::may_mount_or_eperm;
pub use registry::ensure_filesystems_registered;
