use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, InodeRef};

use crate::inotify::layout::encode_name;
use crate::inotify::types::{
    inode_key, Event, InotifyData, FAN_ATTRIB, FAN_DELETE_SELF, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_MOVE_SELF,
    FAN_ONDIR, FAN_OPEN_EXEC, IN_ACCESS, IN_CLOSE_NOWRITE, IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_IGNORED,
    IN_EXCL_UNLINK, IN_ISDIR, IN_MODIFY, IN_ONESHOT, IN_OPEN, IN_SELF_NO_ISDIR, MARK_COUNT, MOVE_COOKIE,
};

/// One notification's identifying facts, shared by every group the fire path
/// visits — the same set Linux threads through `fsnotify()`: the event bit, the
/// rename cookie, the affected entry's name (`struct qstr`, `NULL` for an event
/// on the watched object itself), and whether the AFFECTED object is a
/// directory (`FS_ISDIR` — the CHILD for a dirent/child event, the watched
/// object otherwise).
struct Fire<'a> {
    mask_bit:   u32,
    cookie:     u32,
    /// `None` for an event on the watched object itself.
    name:       Option<&'a str>,
    target_dir: bool,
    /// The event carries a PATH (`fsnotify_data_path`) whose dentry is already
    /// unlinked — the only situation `IN_EXCL_UNLINK` suppresses. An event with
    /// no path (a dirent notification, a delete/move-self, an attribute change)
    /// leaves this `false`, because Linux's guard short-circuits on `path` being
    /// NULL and such events reach an `IN_EXCL_UNLINK` mark regardless.
    unlinked:   bool,
}

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
/// matching mark (inode / mount / filesystem scope).
///
/// The reported mask carries `IN_ISDIR` for inotify groups when the affected
/// object is a directory (Linux `FS_ISDIR`), except on `IN_DELETE_SELF` /
/// `IN_MOVE_SELF`. Legacy (fd-reporting) fanotify groups instead FILTER on it —
/// `fsnotify_mask_applicable` drops a directory event for a mark without
/// `FAN_ONDIR` — and never report the bit back to userspace.
/// # C: O(N_groups * N_watches)
fn dispatch(inode: &InodeRef, f: &Fire<'_>) {
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let key = inode_key(inode);
    let fsid = inode.fsid();
    #[cfg(target_os = "oxide-kernel")]
    // `fanotify_event_metadata.pid` is a pid userspace can act on, so it is
    // the process's VISIBLE number — never the opaque internal tgid.
    let pid = sched::current().map(|t| t.visible_pid()).unwrap_or(0);
    #[cfg(not(target_os = "oxide-kernel"))]
    let pid = 0u32;
    let g = INSTANCES.lock();
    for w in g.iter() {
        let arc = match w.upgrade() { Some(a) => a, None => continue };
        let mut watches = arc.watches.lock();
        let mut i = 0usize;
        while i < watches.len() {
            let wi = &watches[i];
            if !wi.applies(key, fsid) { i += 1; continue; }
            // `fsnotify_handle_inode_event`: an `IN_EXCL_UNLINK` mark drops
            // every path-carrying event about a file that has already been
            // unlinked, which is how a watcher avoids the endless
            // ACCESS/MODIFY/CLOSE stream from a still-open deleted file.
            if (wi.flags & IN_EXCL_UNLINK) != 0 && f.unlinked { i += 1; continue; }
            if (wi.ignored & f.mask_bit) != 0 { i += 1; continue; }
            if (wi.mask & f.mask_bit) == 0 { i += 1; continue; }
            let mut report = f.mask_bit;
            if arc.fanotify {
                if f.target_dir && (wi.mask & FAN_ONDIR) == 0 { i += 1; continue; }
            } else if f.target_dir && (f.mask_bit & IN_SELF_NO_ISDIR) == 0 {
                report |= IN_ISDIR;
            }
            let obj = if arc.fanotify { Some(inode.clone()) } else { None };
            // fanotify's LEGACY record is a fixed 24-byte metadata blob with no
            // name field, so the leaf is dropped there. A group that asked for
            // directory fids can report the entry name in a `DFID_NAME` info
            // record, so it keeps the leaf.
            let name = if arc.fanotify && !arc.reports_dir_fid() { Vec::new() }
                       else { encode_name(f.name) };
            arc.enqueue_event(Event { wd: wi.wd, mask: report, cookie: f.cookie, name, obj, pid });
            if !arc.fanotify && (wi.flags & IN_ONESHOT) != 0 {
                let wd = wi.wd;
                watches.remove(i);
                MARK_COUNT.fetch_sub(1, Ordering::AcqRel);
                arc.release_marks(1);
                arc.enqueue_event(Event { wd, mask: IN_IGNORED, cookie: 0, name: Vec::new(), obj: None, pid });
                continue;
            }
            i += 1;
        }
    }
}

/// An event on `inode` itself (no name; `FS_ISDIR` from `inode`).
/// # C: O(N_groups * N_watches)
pub(crate) fn fire_self(inode: &InodeRef, mask_bit: u32) {
    let target_dir = inode.file_type() == FileType::Directory;
    dispatch(inode, &Fire { mask_bit, cookie: 0, name: None, target_dir, unlinked: false });
}

/// `fire_self` for an event that carries an open file's PATH — the arm the
/// `IN_EXCL_UNLINK` guard applies to. # C: as dispatch
pub(crate) fn fire_self_path(inode: &InodeRef, mask_bit: u32, unlinked: bool) {
    let target_dir = inode.file_type() == FileType::Directory;
    dispatch(inode, &Fire { mask_bit, cookie: 0, name: None, target_dir, unlinked });
}

/// A dir-entry event reported on watched directory `parent`, naming the entry
/// (`leaf`) it happened to. `child_dir` is whether THAT entry is a directory.
/// # C: as dispatch
pub(crate) fn fire_child(parent: &InodeRef, mask_bit: u32, cookie: u32, leaf: &str, child_dir: bool) {
    dispatch(parent, &Fire { mask_bit, cookie, name: Some(leaf), target_dir: child_dir, unlinked: false });
}

/// `fire_child` for the parent leg of a path-carrying event. # C: as dispatch
fn fire_child_path(parent: &InodeRef, mask_bit: u32, leaf: &str, child_dir: bool, unlinked: bool) {
    dispatch(parent, &Fire { mask_bit, cookie: 0, name: Some(leaf), target_dir: child_dir, unlinked });
}

/// Fire `IN_MODIFY` on an already-identified inode. Leaf crates (cgroup) that
/// mutate synthetic file content without going through the VFS write path use
/// this to emit Linux's `cgroup_file_notify` without re-walking a path string.
/// # C: O(N_groups * N_watches)
pub fn fire_modify(inode: &InodeRef) { fire_self(inode, IN_MODIFY); }

/// FAN_ATTRIB / IN_ATTRIB — metadata change (chmod/chown/utimes/link-count).
/// Wired from the chmod/chown syscall handlers (Linux `fsnotify_change`).
/// # C: O(N_groups * N_watches)
pub fn fire_attrib(inode: &InodeRef) {
    fire_self(inode, FAN_ATTRIB);
    vfs::file::dnotify_emit(inode, vfs::file::DN_ATTRIB);
}

/// Linux `fsnotify_link_count` — the inode's link count changed, reported as
/// FS_ATTRIB on the inode itself (`include/linux/fsnotify.h`). Fired by
/// `fsnotify_link` on every new hardlink and by `fsnotify_move` on a rename
/// that overwrote an existing target. Distinct from the dirent CREATE/DELETE
/// on the parent: a watch on the FILE learns its link count moved.
/// # C: O(N_groups * N_watches)
pub fn fire_link_count(inode: &InodeRef) { fire_self(inode, FAN_ATTRIB); }

/// FAN_OPEN_EXEC — a file opened for program execution (Linux
/// `fsnotify_open` with `FMODE_EXEC`). Wired from the execve path.
/// # C: O(N_groups * N_watches)
pub fn fire_open_exec(inode: &InodeRef) { fire_self(inode, FAN_OPEN_EXEC); }

/// The filesystem identified by `fsid` is going away: report `IN_UNMOUNT` on
/// every mark it carries and retire them (each inotify wd also gets its
/// `IN_IGNORED`). Called from the unmount path once the last mount of a
/// superblock is detached. # C: O(N_groups * N_watches)
pub fn fire_unmount(fsid: u64) { crate::inotify::marks::unmount_fs_marks(fsid); }

/// Linux `fsnotify_inoderemove` (`include/linux/fsnotify.h`) in full: report
/// FS_DELETE_SELF on the dying inode, THEN retire every mark attached to it
/// (`__fsnotify_inode_delete`), which queues each freed wd's `IN_IGNORED`.
/// The order matters — a reader must see DELETE_SELF before IGNORED.
/// # C: O(N_groups * N_watches)
pub fn fire_delete_self(inode: &InodeRef) {
    fire_self(inode, FAN_DELETE_SELF);
    crate::inotify::marks::destroy_inode_marks(inode);
}

/// Rename notification triple (Linux `fsnotify_move`): FAN_MOVED_FROM on the
/// source directory (naming the OLD entry) + FAN_MOVED_TO on the destination
/// directory (naming the NEW entry) share one cookie, and FAN_MOVE_SELF fires
/// on the moved object. The two names are what lets a watcher pair the halves
/// with the entries they refer to — the cookie alone only says "same rename".
/// # C: O(N_groups * N_watches)
pub fn fire_move(old_parent: &InodeRef, new_parent: &InodeRef, moved: Option<&InodeRef>,
                 old_name: &str, new_name: &str) {
    let c = MOVE_COOKIE.fetch_add(1, Ordering::Relaxed);
    let is_dir = moved.map(|m| m.file_type() == FileType::Directory).unwrap_or(false);
    fire_child(old_parent, FAN_MOVED_FROM, c, old_name, is_dir);
    fire_child(new_parent, FAN_MOVED_TO, c, new_name, is_dir);
    if let Some(m) = moved { fire_self(m, FAN_MOVE_SELF); }
    vfs::file::dnotify_emit(old_parent, vfs::file::DN_RENAME);
    vfs::file::dnotify_emit(new_parent, vfs::file::DN_RENAME);
}

/// Linux `fsnotify_parent`: an event on a file is reported on the file's OWN
/// marks and, named, on its PARENT directory's marks. Watching a directory is
/// the normal way inotify is used (`GFileMonitor`, systemd `.path` units), and
/// without the parent leg such a watch never learns that a file inside it was
/// opened / read / written / closed at all. # C: 2x dispatch
fn fire_with_parent(inode: &InodeRef, mask_bit: u32, dentry: &Arc<vfs::Dentry>) {
    // Same zero-watch fast path `dispatch` takes, hoisted so a system with no
    // marks pays neither the parent walk nor its dentry-inode lock on every
    // read/write/open/close.
    if MARK_COUNT.load(Ordering::Acquire) == 0 { return; }
    let unlinked = d_unlinked(dentry);
    fire_self_path(inode, mask_bit, unlinked);
    let Some(parent) = dentry.parent() else { return };
    let Some(pino) = parent.inode() else { return };
    let child_dir = inode.file_type() == FileType::Directory;
    fire_child_path(&pino, mask_bit, dentry.name(), child_dir, unlinked);
}

/// `d_unlinked(dentry)` — `d_unhashed(dentry) && !IS_ROOT(dentry)`. A name that
/// has left the dcache but is not a filesystem root: exactly what `unlink` on a
/// still-open file leaves behind. # C: O(1)
fn d_unlinked(d: &Arc<vfs::Dentry>) -> bool { d.is_unhashed() && d.parent().is_some() }

fn vfs_write_notify(inode: &InodeRef, d: &Arc<vfs::Dentry>) { fire_with_parent(inode, IN_MODIFY, d); }
fn vfs_open_notify(inode: &InodeRef, d: &Arc<vfs::Dentry>)  { fire_with_parent(inode, IN_OPEN, d); }
fn vfs_read_notify(inode: &InodeRef, d: &Arc<vfs::Dentry>)  { fire_with_parent(inode, IN_ACCESS, d); }
fn vfs_close_notify(inode: &InodeRef, was_writable: bool, d: &Arc<vfs::Dentry>) {
    fire_with_parent(inode, if was_writable { IN_CLOSE_WRITE } else { IN_CLOSE_NOWRITE }, d);
}

/// Linux `fsnotify_change` (`include/linux/fsnotify.h`): map the applied
/// `ATTR_*` set onto event bits. Not every attribute change is `FS_ATTRIB` — a
/// size change is a MODIFY, and a lone atime/mtime update is ACCESS/MODIFY
/// respectively, while BOTH together mean a `utimes()` call and are ATTRIB.
/// # C: O(1)
pub(crate) fn setattr_event_mask(ia_valid: u32) -> u32 {
    let mut mask = 0;
    if ia_valid & (vfs::ATTR_UID | vfs::ATTR_GID | vfs::ATTR_MODE) != 0 { mask |= FAN_ATTRIB; }
    if ia_valid & vfs::ATTR_SIZE != 0 { mask |= IN_MODIFY; }
    let times = ia_valid & (vfs::ATTR_ATIME | vfs::ATTR_MTIME);
    if times == vfs::ATTR_ATIME | vfs::ATTR_MTIME { mask |= FAN_ATTRIB; }
    else if times == vfs::ATTR_ATIME { mask |= IN_ACCESS; }
    else if times == vfs::ATTR_MTIME { mask |= IN_MODIFY; }
    mask
}

/// The `fsnotify_change` subscriber. One event per set bit, since `fire_self`
/// dispatches a single bit at a time. # C: O(bits × dispatch)
pub(crate) fn vfs_setattr_notify(inode: &InodeRef, ia_valid: u32) {
    let mask = setattr_event_mask(ia_valid);
    if mask == 0 { return; }
    for bit in [FAN_ATTRIB, IN_MODIFY, IN_ACCESS] {
        if mask & bit != 0 { fire_self(inode, bit); }
    }
    // dnotify's equivalent split (Linux `fsnotify_dentry` feeds both).
    let mut dn = 0;
    if mask & FAN_ATTRIB != 0 { dn |= vfs::file::DN_ATTRIB; }
    if mask & IN_MODIFY  != 0 { dn |= vfs::file::DN_MODIFY; }
    if mask & IN_ACCESS  != 0 { dn |= vfs::file::DN_ACCESS; }
    vfs::file::dnotify_emit(inode, dn);
}

/// Install all inotify event hooks into vfs. Called once at kernel_main.
/// # C: O(1)
pub fn install_write_hook() {
    vfs::set_delete_self_hook(fire_delete_self);
    vfs::set_setattr_hook(vfs_setattr_notify);
    vfs::set_write_hook(vfs_write_notify);
    vfs::set_open_hook(vfs_open_notify);
    vfs::set_read_hook(vfs_read_notify);
    vfs::set_close_hook(vfs_close_notify);
    vfs::set_dirent_create_hook(vfs_dirent_create);
    vfs::set_dirent_delete_hook(vfs_dirent_delete);
}

fn vfs_dirent_create(parent: &InodeRef, leaf: &str, leaf_is_dir: bool) {
    fire_child(parent, IN_CREATE, 0, leaf, leaf_is_dir);
    vfs::file::dnotify_emit(parent, vfs::file::DN_CREATE);
}

fn vfs_dirent_delete(parent: &InodeRef, leaf: &str, leaf_is_dir: bool) {
    fire_child(parent, IN_DELETE, 0, leaf, leaf_is_dir);
    vfs::file::dnotify_emit(parent, vfs::file::DN_DELETE);
}
