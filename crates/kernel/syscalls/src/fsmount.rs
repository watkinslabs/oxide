// New mount API (`docs/16`, systemd 254+): fsopen/fsconfig/fsmount/
// move_mount/open_tree/fspick/mount_setattr. Each handler now lives in its
// own per-syscall file (docs/53 §0); shared types/helpers live in
// fsmount_common.rs. This module re-exports them so existing call sites
// (`crate::fsmount::sys_*`) keep resolving.

#![cfg(target_os = "oxide-kernel")]

pub use crate::fsmount_common::{FsContextInode, MountObjectInode};
pub use crate::s428_open_tree::sys_open_tree;
pub use crate::s429_move_mount::sys_move_mount;
pub use crate::s430_fsopen::sys_fsopen;
pub use crate::s431_fsconfig::sys_fsconfig;
pub use crate::s432_fsmount::sys_fsmount;
pub use crate::s433_fspick::sys_fspick;
pub use crate::s442_mount_setattr::sys_mount_setattr;
