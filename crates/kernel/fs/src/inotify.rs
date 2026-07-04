// Module manifest:
// - `types`: shared constants, watch/event records, global counters, and group state.
// - `group`: inotify/fanotify group inode/file ops, read/write paths, and perm-gate checks.
// - `dispatch`: global registry, event routing, VFS hook wiring, and fire_* helpers.
// - `syscalls`: watch-path resolution plus inotify/fanotify syscall entry points and mark editing.

mod dispatch;
mod group;
mod syscalls;
mod types;

#[cfg(test)]
#[path = "inotify_fan_tests.rs"]
mod fan_tests;

#[cfg(test)]
mod tests;

pub use dispatch::{fire_attrib, fire_delete_self, fire_modify_path, fire_move, fire_open_exec, install_write_hook};
pub use group::{check_access_perm, check_open_exec_perm, check_open_perm, make_inotify_inode, perm_marks_present};
pub use syscalls::{sys_fanotify_init, sys_fanotify_mark, sys_inotify_add_watch, sys_inotify_init1, sys_inotify_rm_watch};
pub use types::{
    InotifyData, IN_ACCESS, IN_ALL_EVENTS, IN_ATTRIB, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE,
    IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_OPEN,
};

#[cfg(test)]
pub(crate) use dispatch::fire_self;
#[cfg(test)]
pub(crate) use group::InotifyFileOps;
#[cfg(test)]
pub(crate) use syscalls::{apply_mark, validate_fanotify_init, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT, FAN_CLOEXEC,
    FAN_NONBLOCK, FAN_REPORT_DIR_FID, FAN_REPORT_NAME};
#[cfg(test)]
pub(crate) use types::{inode_key, Event, MarkScope, PermEvent, FAN_ACCESS, FAN_ALLOW, FAN_ATTRIB, FAN_CLOSE_WRITE,
    FAN_DENY, FAN_MODIFY, FAN_MOVE, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_MOVE_SELF, FAN_ONDIR, FAN_OPEN, FAN_OPEN_EXEC,
    FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM};
#[cfg(test)]
pub(crate) use core::sync::atomic::{AtomicU32, Ordering};
#[cfg(test)]
pub(crate) use vfs::InodeRef;
