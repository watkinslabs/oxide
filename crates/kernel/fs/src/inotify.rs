// Module manifest:
// - `types`: shared constants, watch/event records, global counters, and group state.
// - `group`: inotify/fanotify group inode/file ops, read/write paths, and perm-gate checks.
// - `dispatch`: global registry, event routing, VFS hook wiring, and fire_* helpers.
// - `marks`: mark teardown when the watched object dies (`__fsnotify_inode_delete`).
// - `queue`: notification-queue admission — overflow + each kind's merge rule.
// - `mask`: per-mark applicability (ONDIR / ON_CHILD) and ignore-mask rules.
// - `response`: `fanotify_response` admission and the verdict→errno mapping.
// - `fan_ids`: reported-pid selection and the event descriptor's open mode.
// - `fan_read`: fanotify read path — metadata, info records, minted fds.
// - `layout`: `struct inotify_event` wire encoding + name padding rules.
// - `fan_layout`: `fanotify_event_metadata` + `fanotify_event_info_fid` encoding.
// - `fan_mnt`: `FAN_MARK_MNTNS` marks, mount-tree dispatch, and the mount info record.
// - `fan_err`: `FAN_FS_ERROR` dispatch, the error info record, and its always-merge rule.
// - `fan_range`: `FAN_PRE_ACCESS` byte ranges and the range info record.
// - `fan_rename`: `FAN_RENAME` dispatch and the old/new parent+name info records.
// - `path`: watch-path resolution through task root/cwd plus credentials.
// - `perm`: `FAN_*_PERM` access gates and the park-until-verdict wait.
// - `validate`: inotify/fanotify UAPI flags and Linux argument validation.
// - `syscalls`: inotify/fanotify syscall entry points and mark editing.
// - `test_claim`: hosted-test claim on the one global group registry (test-only).

mod dispatch;
mod fan_err;
mod fan_ids;
mod fan_layout;
mod fan_mnt;
mod fan_range;
mod fan_rename;
mod fan_read;
mod group;
mod layout;
mod marks;
mod mask;
mod path;
mod perm;
mod queue;
mod response;
mod syscalls;
mod types;
mod validate;

#[cfg(test)]
#[path = "inotify_fan_tests.rs"]
mod fan_tests;

#[cfg(test)]
#[path = "inotify_fan_mnt_tests.rs"]
mod fan_mnt_tests;

#[cfg(test)]
#[path = "inotify_fan_err_tests.rs"]
mod fan_err_tests;

#[cfg(test)]
#[path = "inotify_fan_rename_tests.rs"]
mod fan_rename_tests;

#[cfg(test)]
#[path = "inotify_fan_range_tests.rs"]
mod fan_range_tests;

#[cfg(test)]
#[path = "inotify_deleteself_tests.rs"]
mod deleteself_tests;

#[cfg(test)]
#[path = "inotify_setattr_tests.rs"]
mod setattr_tests;

#[cfg(test)]
#[path = "inotify_mark_lifetime_tests.rs"]
mod mark_lifetime_tests;

#[cfg(test)]
#[path = "inotify_limits_tests.rs"]
mod limits_tests;

#[cfg(test)]
pub(crate) mod test_claim;

#[cfg(test)]
mod tests;

pub use dispatch::{fire_attrib, fire_delete_self, fire_link_count, fire_modify, fire_move, fire_open_exec, fire_unmount, install_write_hook};
pub use group::make_inotify_inode;
pub use perm::{check_file_area_perm, check_mmap_perm, check_open_exec_perm,
    check_open_perm, check_truncate_perm, perm_marks_present};
pub use syscalls::{sys_fanotify_init, sys_fanotify_mark, sys_inotify_add_watch, sys_inotify_init,
    sys_inotify_init1, sys_inotify_rm_watch};
pub use types::{
    InotifyData, IN_ACCESS, IN_ALL_EVENTS, IN_ATTRIB, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE,
    IN_ISDIR, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_OPEN,
};

#[cfg(test)]
pub(crate) use dispatch::{fire_child, fire_self, fire_self_path};
#[cfg(test)]
pub(crate) use group::InotifyFileOps;
#[cfg(test)]
pub(crate) use syscalls::{add_or_update_watch, apply_mark, remove_watch};
#[cfg(test)]
pub(crate) use validate::{validate_fanotify_init, validate_fanotify_mark_group,
    validate_fanotify_mark_prefd, validate_inotify_init_flags, validate_inotify_watch_mask_after_fd,
    validate_inotify_watch_mask_bits, FAN_CLASS_CONTENT, FAN_CLASS_PRE_CONTENT, FAN_CLOEXEC,
    FAN_ENABLE_AUDIT, FAN_MARK_ADD, FAN_MARK_EVICTABLE, FAN_MARK_FILESYSTEM, FAN_MARK_FLUSH,
    FAN_MARK_IGNORE, FAN_MARK_IGNORED_MASK, FAN_MARK_MOUNT, FAN_MARK_MNTNS, FAN_MARK_REMOVE,
    FAN_MARK_ONLYDIR, FAN_NONBLOCK, FAN_REPORT_DIR_FID, FAN_REPORT_FD_ERROR, FAN_REPORT_FID,
    FAN_REPORT_MNT, FAN_REPORT_NAME, FAN_REPORT_TARGET_FID};
#[cfg(test)]
pub(crate) use types::{inode_key, Event, MarkScope, FAN_ACCESS, FAN_ATTRIB, FAN_CLOSE_WRITE, FAN_CREATE,
    FAN_FS_ERROR, FAN_MNT_ATTACH, FAN_MODIFY, FAN_MOVE, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_MOVE_SELF,
    FAN_ONDIR, FAN_OPEN, FAN_OPEN_EXEC, FAN_OPEN_EXEC_PERM, FAN_OPEN_PERM, FAN_PRE_ACCESS, FAN_RENAME,
    IN_EXCL_UNLINK, IN_IGNORED, IN_ONESHOT, INOTIFY_DEFAULT_MAX_QUEUED_EVENTS, IN_Q_OVERFLOW, IN_UNMOUNT};
#[cfg(test)]
#[cfg(test)]
pub(crate) use vfs::InodeRef;
