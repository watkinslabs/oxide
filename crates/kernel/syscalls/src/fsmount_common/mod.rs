// Module manifest: `registry` owns fs-type admission/registration;
// `mount_ops` owns constructor dispatch + grafting; `objects` owns fs_context
// and detached-mount inode types; `fd` owns user-string/fd installation helpers.

#![cfg(target_os = "oxide-kernel")]

mod fd;
mod mount_ops;
mod objects;
mod registry;

pub(crate) use fd::{fd_inode, install_fd, read_cstr};
pub(crate) use mount_ops::{mount_fstype, mount_fstype_with_data};
pub use objects::{FsContextInode, MountObjectInode};
pub(crate) use registry::{fstype_converted, fstype_ok, require_sys_admin, NEXT_FSCTX_INO, ensure_filesystems_registered};
