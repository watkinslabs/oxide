// Devfs registry surface per `52§3` domain layer.
//
// Owns the namespace-aware (`ns`, `path`) → `InodeRef` table that
// `register*` writes and `lookup` reads. The boot-time bootstrap
// (`devfs::init`) that POPULATES this table with /dev/console,
// /dev/tty*, /dev/null, /dev/zero, /dev/random, etc. lives in
// `kernel/src/devfs.rs` because it pulls together the kernel-side
// device implementations (ConsoleInode, NullInode, ZeroInode, …).
// `PrefixDirInode` (synthetic directory walker) likewise stays in
// `kernel/src/devfs.rs` because its `readdir` overlays ext4 entries
// via `crate::dev_ext4::read_dir` — moving that into a hook in this
// crate is future cleanup.
//
// `read_user_cstr` rides here because every kernel module that
// resolves a user path through `crate::devfs::read_user_cstr` would
// otherwise have to duplicate the bounded-strlen + USER_VA_END
// check — keeping the helper colocated with the registry it serves
// avoids that.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::InodeRef;

/// `(ns, path, inode)` — devfs registry row. `ns == 0` is the init
/// (host) namespace; all `register*` calls into the boot bootstrap
/// land here. Forks/clone-NS install rows under their own `ns`.
type Row = (u64, String, InodeRef);

static REGISTRY: Spinlock<Vec<Row>, TaskListClass> = Spinlock::new(Vec::new());

/// Register `path` → `inode` in the init namespace (`ns == 0`).
/// Used by the boot bootstrap; takes a `'static` path so we don't
/// clone for the common case.
/// # C: O(1) push
pub fn register(path: &'static str, inode: InodeRef) {
    REGISTRY.lock().push((0, String::from(path), inode));
}

/// Same as `register` but accepts an owned `String`. Used by
/// runtime mounts and overlay creation.
/// # C: O(1) push
pub fn register_owned(path: String, inode: InodeRef) {
    REGISTRY.lock().push((0, path, inode));
}

/// Register `path` in a specific namespace `ns`. Mount-namespace
/// fork support per `27`.
/// # C: O(1) push
pub fn register_in_ns(ns: u64, path: String, inode: InodeRef) {
    REGISTRY.lock().push((ns, path, inode));
}

/// Look up a path. Tries caller's mount_ns first, then init NS.
/// Applies the chroot prefix (F95) before matching.
/// # C: O(N)
pub fn lookup(path: &str) -> Option<InodeRef> {
    let resolved = chroot_resolve(path);
    let cur_ns = sched::current()
        .map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    let g = REGISTRY.lock();
    if cur_ns != 0 {
        if let Some((_, _, i)) = g.iter().find(|(n, p, _)| *n == cur_ns && p.as_str() == resolved.as_str()) {
            return Some(Arc::clone(i));
        }
    }
    g.iter().find(|(n, p, _)| *n == 0 && p.as_str() == resolved.as_str()).map(|(_, _, i)| Arc::clone(i))
}

/// Detach every entry whose path is under `mount_point` from
/// `mount_ns`. Linux umount2(2) equivalent. Returns the row count
/// removed.
/// # C: O(N)
pub fn unregister_subtree(ns: u64, mount_point: &str) -> usize {
    let mut g = REGISTRY.lock();
    let before = g.len();
    g.retain(|(n, p, _)| {
        if *n != ns { return true; }
        if p.as_str() == mount_point { return false; }
        let mut prefix = String::from(mount_point);
        prefix.push('/');
        !p.starts_with(prefix.as_str())
    });
    before - g.len()
}

/// Clone every init-NS row into `dst_ns`. Used when a process
/// transitions to a new mount namespace via clone(CLONE_NEWNS) or
/// unshare.
/// # C: O(N)
pub fn snapshot_ns(src_ns: u64, dst_ns: u64) {
    let mut g = REGISTRY.lock();
    let snapshot: Vec<Row> = g.iter()
        .filter(|(n, _, _)| *n == src_ns)
        .map(|(_, p, i)| (dst_ns, p.clone(), Arc::clone(i)))
        .collect();
    g.extend(snapshot);
}

/// Snapshot every row whose ns matches the caller's mount_ns or
/// init NS. Used by `PrefixDirInode::readdir` (kernel-side) to
/// walk the registry without holding the spinlock during the
/// callback. Caller filters by prefix.
/// # C: O(N)
pub fn snapshot_visible_to_current() -> Vec<(String, InodeRef)> {
    let cur_ns = sched::current()
        .map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    let g = REGISTRY.lock();
    g.iter()
        .filter(|(n, _, _)| *n == cur_ns || *n == 0)
        .map(|(_, p, i)| (p.clone(), Arc::clone(i)))
        .collect()
}

/// Apply the calling task's chroot root to an absolute path.
/// Relative paths and boot-context calls (no current task) pass
/// through unchanged.
/// # C: O(len)
fn chroot_resolve(path: &str) -> String {
    if !path.starts_with('/') { return String::from(path); }
    let cur = match sched::current() { Some(c) => c, None => return String::from(path) };
    // SAFETY: task.root single-mutator per `13§5`; running task on this CPU is the sole writer (sys_chroot updates only on the calling task).
    let root = unsafe { (*cur.root.get()).clone() };
    if root == "/" { return String::from(path); }
    let mut out = root;
    if out.ends_with('/') { out.pop(); }
    out.push_str(path);
    out
}

/// Read a NUL-terminated string from user memory at `ptr`, bounded
/// at `max` bytes. Returns the slice (trimmed of NUL) borrowed
/// against the user page.
/// # SAFETY: ptr in user range; user page mapped; CPL=0 reads pass
/// through user mappings.
/// # C: O(strlen)
pub unsafe fn read_user_cstr<'a>(ptr: u64, max: usize) -> Option<&'a [u8]> {
    if ptr == 0 || ptr >= hal::USER_VA_END { return None; }
    let mut len = 0;
    while len < max {
        // SAFETY: ptr+len < ptr+max ≤ USER_VA_END (caller's responsibility for mapped page); 1-byte read.
        let b = unsafe { core::ptr::read_volatile((ptr + len as u64) as *const u8) };
        if b == 0 { break; }
        len += 1;
    }
    if len == 0 { return Some(&[]); }
    // SAFETY: same range; we've just probed every byte.
    Some(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) })
}


pub mod misc;
