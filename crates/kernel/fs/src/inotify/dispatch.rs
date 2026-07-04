use alloc::sync::{Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, InodeRef};

use crate::inotify::types::{
    inode_key, Event, InotifyData, FAN_ATTRIB, FAN_DELETE_SELF, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_MOVE_SELF,
    FAN_ONDIR, FAN_OPEN_EXEC, IN_ACCESS, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_MODIFY, IN_OPEN,
    MARK_COUNT, MOVE_COOKIE,
};

/// Global registry of weak refs to every live InotifyData. Walked
/// on each VFS write-hook call to find watches matching the modified
/// inode.
static INSTANCES: Spinlock<Vec<Weak<InotifyData>>, TaskListClass> =
    Spinlock::new(Vec::new());

pub(crate) fn instances() -> &'static Spinlock<Vec<Weak<InotifyData>>, TaskListClass> { &INSTANCES }

pub(crate) fn register_instance(w: Weak<InotifyData>) {
    let mut g = INSTANCES.lock();
    g.retain(|w| w.upgrade().is_some());
    g.push(w);
}

/// Core event dispatch. Walks the live group list and pushes one event per
/// matching mark (inode / mount / filesystem scope). `self_event` = the event
/// is on `inode` itself (open/read/write/close/attrib/*_self); `false` = a
/// dir-entry event reported on the watched directory `inode` (create/delete/
/// moved_*). `cookie` pairs the two halves of a rename. fanotify groups honor
/// FAN_ONDIR (directory self-events) and the per-mark ignore mask; inotify
/// groups keep verbatim inotify semantics. # C: O(N_groups * N_watches)
fn dispatch(inode: &InodeRef, mask_bit: u32, self_event: bool, cookie: u32) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let key = inode_key(inode);
    let fsid = inode.fsid();
    let is_dir = inode.file_type() == FileType::Directory;
    #[cfg(target_os = "oxide-kernel")]
    let pid = sched::current().map(|t| t.tgid.load(Ordering::Relaxed)).unwrap_or(0);
    #[cfg(not(target_os = "oxide-kernel"))]
    let pid = 0u32;
    let g = INSTANCES.lock();
    for w in g.iter() {
        let arc = match w.upgrade() { Some(a) => a, None => continue };
        let watches = arc.watches.lock();
        for wi in watches.iter() {
            if !wi.applies(key, fsid) { continue; }
            if (wi.ignored & mask_bit) != 0 { continue; }
            if (wi.mask & mask_bit) == 0 { continue; }
            let mut report = mask_bit;
            if arc.fanotify {
                if self_event && is_dir && (wi.mask & FAN_ONDIR) == 0 { continue; }
                if is_dir { report |= FAN_ONDIR; }
            }
            let obj = if arc.fanotify { Some(inode.clone()) } else { None };
            arc.events.lock().push_back(Event { wd: wi.wd, mask: report, cookie, len: 0, obj, pid });
        }
    }
}

/// An event on `inode` itself. # C: O(N_groups * N_watches)
pub(crate) fn fire_self(inode: &InodeRef, mask_bit: u32) { dispatch(inode, mask_bit, true, 0); }

/// A dir-entry event reported on watched directory `parent`. # C: as dispatch
fn fire_child(parent: &InodeRef, mask_bit: u32, cookie: u32) { dispatch(parent, mask_bit, false, cookie); }

/// Fire `IN_MODIFY` on the inode currently registered at `path`.
/// Leaf crates (cgroup) that mutate a synthetic file's content without
/// going through the VFS write path use this to emit the
/// change-notification Linux's `cgroup_file_notify` provides.
/// # C: O(N_inotify * N_watches) + O(path components)
pub fn fire_modify_path(path: &str) {
    if let Ok(inode) = vfs::resolve_abs(path) {
        fire_self(&inode, IN_MODIFY);
    }
}

/// FAN_ATTRIB / IN_ATTRIB — metadata change (chmod/chown/utimes/link-count).
/// Wired from the chmod/chown syscall handlers (Linux `fsnotify_change`).
/// # C: O(N_groups * N_watches)
pub fn fire_attrib(inode: &InodeRef) {
    fire_self(inode, FAN_ATTRIB);
    vfs::file::dnotify_emit(inode, vfs::file::DN_ATTRIB);
}

/// FAN_OPEN_EXEC — a file opened for program execution (Linux
/// `fsnotify_open` with `FMODE_EXEC`). Wired from the execve path.
/// # C: O(N_groups * N_watches)
pub fn fire_open_exec(inode: &InodeRef) { fire_self(inode, FAN_OPEN_EXEC); }

/// FAN_DELETE_SELF / IN_DELETE_SELF — the watched object itself was unlinked.
/// # C: O(N_groups * N_watches)
pub fn fire_delete_self(inode: &InodeRef) { fire_self(inode, FAN_DELETE_SELF); }

/// Rename notification triple (Linux `fsnotify_move`): FAN_MOVED_FROM on the
/// source directory + FAN_MOVED_TO on the destination directory share one
/// cookie, and FAN_MOVE_SELF fires on the moved object.
/// # C: O(N_groups * N_watches)
pub fn fire_move(old_parent: &InodeRef, new_parent: &InodeRef, moved: Option<&InodeRef>) {
    let c = MOVE_COOKIE.fetch_add(1, Ordering::Relaxed);
    fire_child(old_parent, FAN_MOVED_FROM, c);
    fire_child(new_parent, FAN_MOVED_TO, c);
    if let Some(m) = moved { fire_self(m, FAN_MOVE_SELF); }
    vfs::file::dnotify_emit(old_parent, vfs::file::DN_RENAME);
    vfs::file::dnotify_emit(new_parent, vfs::file::DN_RENAME);
}

fn vfs_write_notify(inode: &InodeRef) { fire_self(inode, IN_MODIFY); }
fn vfs_open_notify(inode: &InodeRef)  { fire_self(inode, IN_OPEN); }
fn vfs_read_notify(inode: &InodeRef)  { fire_self(inode, IN_ACCESS); }
fn vfs_close_notify(inode: &InodeRef, was_writable: bool) {
    fire_self(inode, if was_writable { IN_CLOSE_WRITE } else { IN_CLOSE_NOWRITE });
}

/// Install all inotify event hooks into vfs. Called once at kernel_main.
/// # C: O(1)
pub fn install_write_hook() {
    vfs::set_write_hook(vfs_write_notify);
    vfs::set_open_hook(vfs_open_notify);
    vfs::set_read_hook(vfs_read_notify);
    vfs::set_close_hook(vfs_close_notify);
    vfs::set_dirent_create_hook(vfs_dirent_create);
    vfs::set_dirent_delete_hook(vfs_dirent_delete);
}

fn vfs_dirent_create(parent: &str, _leaf: &str) {
    if let Ok(parent_inode) = vfs::mount::lookup(parent) {
        fire_child(&parent_inode, IN_CREATE, 0);
        vfs::file::dnotify_emit(&parent_inode, vfs::file::DN_CREATE);
    }
}

fn vfs_dirent_delete(parent: &str, _leaf: &str) {
    if let Ok(parent_inode) = vfs::mount::lookup(parent) {
        fire_child(&parent_inode, IN_DELETE, 0);
        vfs::file::dnotify_emit(&parent_inode, vfs::file::DN_DELETE);
    }
}
