use core::sync::atomic::{AtomicU64, Ordering};

use sync::Spinlock;

use alloc::sync::Arc;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::types::OpenFlags;

use super::File;

/// Kernel-side hook installed at boot. Called from `File::drop` for
/// the last-Arc-reference release (close+last-dup gone). The kernel
/// flock module installs a release fn that walks the per-inode
/// registry. `0` = no hook installed (host tests, early boot).
static FLOCK_RELEASE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the per-File drop hook used by `flock(2)` to release any
/// held lock. Called once at kernel init. The `usize` argument the
/// hook receives is the dropped File's `&self` raw pointer cast.
/// # C: O(1)
pub fn set_drop_hook(f: fn(usize, &InodeRef)) {
    FLOCK_RELEASE_HOOK.store(f as u64, Ordering::Release);
}

/// Close-hook slot count per `16§R02`. Multiple subsystems register a
/// close hook (inotify IN_CLOSE_*, pipe writer/reader-count tracking,
/// posix-lock cleanup, ext4 orphan reap); every occupied slot fires in
/// `File::Drop`. Fixed N=4 covers the in-kernel consumers; extend if a new
/// one arrives.
const CLOSE_HOOK_SLOTS: usize = 4;

/// D30: typed inotify/fsnotify + pipe-accounting hook registry. Replaces the
/// old per-slot transmuted `AtomicU64` storage (every load reinterpreted a
/// `u64` as a `fn` of an assumed signature via `core::mem::transmute`). Each
/// entry is now a typed `Option<fn(..)>` carrying its exact signature, so
/// installing AND firing a hook needs NO transmute — the compiler checks the
/// call. Hooks are installed once at boot (inotify / pipe / posix-lock / ext4
/// rootfs modules); the data path copies the relevant `Option<fn>` out under
/// the registry lock, RELEASES it, then calls, so no foreign hook ever runs
/// while the lock is held. # C: O(1) per fire (+ short critical section)
#[derive(Copy, Clone)]
struct InodeHooks {
    /// IN_OPEN — fired at `File::new_at` (Linux `fsnotify_open`).
    open:  Option<fn(&InodeRef, &Arc<Dentry>)>,
    /// IN_ACCESS — fired after a `read` returns >0 (Linux `fsnotify_access`).
    read:  Option<fn(&InodeRef, &Arc<Dentry>)>,
    /// IN_MODIFY — fired after a `write` returns >0 (Linux `fsnotify_modify`).
    write: Option<fn(&InodeRef, &Arc<Dentry>)>,
    /// Per-reference clone (fork_clone / dup / dup2): pipe writer-count++.
    /// `bool` = opened-writable.
    clone: Option<fn(&InodeRef, bool)>,
    /// IN_CLOSE_* + pipe close accounting, fired in `File::Drop`. Multiple
    /// subsystems register; every occupied slot fires. `bool` = was-writable.
    close: [Option<fn(&InodeRef, bool, &Arc<Dentry>)>; CLOSE_HOOK_SLOTS],
    /// IN_CREATE — dirent created in a watched parent inode.
    /// Args: (parent, leaf, leaf-is-a-directory).
    dirent_create: Option<fn(&InodeRef, &str, bool)>,
    /// IN_DELETE — dirent removed from a watched parent inode. Same args.
    dirent_delete: Option<fn(&InodeRef, &str, bool)>,
    /// `fsnotify_inoderemove` — the inode's LAST link is gone. Args: (inode).
    delete_self: Option<fn(&InodeRef)>,
    inode_evict: Option<fn(&InodeRef)>,
    /// `fsnotify_change` — a successful `notify_change`. Args: (inode, ia_valid).
    /// The subscriber owns the `ATTR_*` → event-mask mapping, exactly as
    /// Linux's `fsnotify_change` inline does (`include/linux/fsnotify.h`).
    setattr: Option<fn(&InodeRef, u32)>,
    /// A filesystem reported an on-disk inconsistency or an I/O failure of its
    /// own structures. Args: (`st_dev` of the filesystem, the inode the failure
    /// was discovered on when there is one, positive errno). Unlike every other
    /// hook here the object is the FILESYSTEM, which is why the inode is
    /// optional: a filesystem too damaged to name an inode still has to be able
    /// to say so.
    fs_error: Option<fn(u64, Option<&InodeRef>, i32)>,
}

impl InodeHooks {
    /// # C: O(1)
    const fn new() -> Self {
        Self { open: None, read: None, write: None, clone: None,
               close: [None; CLOSE_HOOK_SLOTS], dirent_create: None, dirent_delete: None,
               delete_self: None, inode_evict: None, setattr: None, fs_error: None }
    }
}

/// Lock class for the typed hook registry. Taken standalone — the fire path
/// copies the `Option<fn>` out and releases the lock BEFORE calling, so it
/// never nests under the inode / pos / ra locks. # C: O(1)
struct HookReg;
impl sync::LockClass for HookReg { fn rank() -> u16 { 33 } fn name() -> &'static str { "HookReg" } }

static HOOKS: Spinlock<InodeHooks, HookReg> = Spinlock::new(InodeHooks::new());

/// Snapshot installed close hooks before running foreign callbacks. # C: O(1)
pub(super) fn close_hooks() -> [Option<fn(&InodeRef, bool, &Arc<Dentry>)>; CLOSE_HOOK_SLOTS] {
    HOOKS.lock().close
}

/// Snapshot the flock release hook pointer for `File::Drop`. # C: O(1)
pub(super) fn flock_release_hook() -> u64 {
    FLOCK_RELEASE_HOOK.load(Ordering::Acquire)
}

/// Install the open hook (fires IN_OPEN at `File::new_at`). # C: O(1)
pub fn set_open_hook(f: fn(&InodeRef, &Arc<Dentry>))  { HOOKS.lock().open = Some(f); }

/// Install the read hook (fires IN_ACCESS after `File::read` returns >0). # C: O(1)
pub fn set_read_hook(f: fn(&InodeRef, &Arc<Dentry>))  { HOOKS.lock().read = Some(f); }

/// Install the post-write hook used by inotify(7) to fire IN_MODIFY. # C: O(1)
pub fn set_write_hook(f: fn(&InodeRef, &Arc<Dentry>)) { HOOKS.lock().write = Some(f); }

/// Install a close hook (fires at `File::Drop`; `bool` = opened-writable).
/// Takes the next free slot; panics if the table is full so a misconfiguration
/// is loud rather than silent. # C: O(N) slot scan, N=4 fixed.
pub fn set_close_hook(f: fn(&InodeRef, bool, &Arc<Dentry>)) {
    let mut h = HOOKS.lock();
    for slot in h.close.iter_mut() {
        if slot.is_none() { *slot = Some(f); return; }
    }
    hal::kassert!(false, "CLOSE_HOOKS table full");
}

/// Install the clone hook (fires when an fd-table reference to a `File` is
/// duplicated: fork_clone / dup / dup2). Every "open count++" event thus has a
/// matching close-hook "open count--". Without it, fork_clone bumps the
/// `Arc<File>` refcount but the pipe writer/reader counts stay at 1; closing
/// the original drops the Arc to 1 (File alive), no close hook fires, pipe
/// POLL_HUP never propagates. F205. `bool` = opened-writable. # C: O(1)
pub fn set_clone_hook(f: fn(&InodeRef, bool)) { HOOKS.lock().clone = Some(f); }

/// Fire the clone hook for a `File` reference being duplicated. The caller
/// (fork_clone / dup / dup2) has already produced the new `Arc<File>`
/// reference; this announces it to any subscriber tracking per-reference state
/// (e.g. the pipe writer count). # C: O(1)
pub fn fire_clone_hook(file: &File) {
    let h = HOOKS.lock().clone;
    if let Some(f) = h {
        let was_writable = {
            let bits = file.flags.load(Ordering::Acquire);
            let fl = OpenFlags::from_bits_retain(bits);
            fl.contains(OpenFlags::O_WRONLY) || fl.contains(OpenFlags::O_RDWR)
        };
        f(&file.inode, was_writable);
    }
}

/// Install the dirent-create hook (fires IN_CREATE; args (parent inode, leaf)).
/// Fired after namespace mutations so inotify watches on the resolved parent
/// directory can dispatch IN_CREATE without re-resolving a rendered path. # C: O(1)
pub fn set_dirent_create_hook(f: fn(&InodeRef, &str, bool)) { HOOKS.lock().dirent_create = Some(f); }
/// Install the dirent-delete hook (fires IN_DELETE; args (parent inode, leaf)). # C: O(1)
pub fn set_dirent_delete_hook(f: fn(&InodeRef, &str, bool)) { HOOKS.lock().dirent_delete = Some(f); }

/// Install the delete-self hook. Fired from the dcache, where Linux fires it:
/// `dentry_unlink_inode` runs `if (!inode->i_nlink) fsnotify_inoderemove(inode)`
/// (`fs/dcache.c`). Firing from `unlink(2)` instead both over-reported (a file
/// with remaining hardlinks got IN_DELETE_SELF on the first name removed) and
/// under-reported (`rmdir` never sent it at all, so a watch on a removed
/// directory never learned it was gone). # C: O(1)
pub fn set_delete_self_hook(f: fn(&InodeRef)) { HOOKS.lock().delete_self = Some(f); }

/// Fire the delete-self hook (no-op when not installed). # C: O(1)
pub fn fire_delete_self_hook(inode: &InodeRef) {
    let h = HOOKS.lock().delete_self;
    if let Some(f) = h { f(inode); }
}

/// Install the inode-EVICTION hook. Distinct from the delete-self hook: that
/// one announces an inode that has ceased to exist, this one an inode merely
/// leaving the cache, which may still exist on disk and be read back later.
/// The distinction is user-visible — a notification mark that asked not to pin
/// its object goes away with the cached inode, while an ordinary mark does not.
/// # C: O(1)
pub fn set_inode_evict_hook(f: fn(&InodeRef)) { HOOKS.lock().inode_evict = Some(f); }

/// Fire the inode-eviction hook (no-op when not installed). # C: O(1)
pub fn fire_inode_evict_hook(inode: &InodeRef) {
    let h = HOOKS.lock().inode_evict;
    if let Some(f) = h { f(inode); }
}

/// Install the setattr hook. Fired from the ONE point Linux fires it: after
/// `i_op->setattr` succeeds inside `notify_change` (`fs/attr.c` `notify_change`
/// → `fsnotify_change`). Per-syscall firing cannot work — it misses every
/// caller that does not go through that syscall (`fchmod`, `fchmodat`,
/// `fchown`, `fchownat`, `truncate`, `ftruncate`, `utimensat`), and aarch64
/// has no legacy `chmod`/`chown` slots at all. # C: O(1)
pub fn set_setattr_hook(f: fn(&InodeRef, u32)) { HOOKS.lock().setattr = Some(f); }

/// Fire the setattr hook with the applied `ATTR_*` set (no-op when not
/// installed). # C: O(1)
pub fn fire_setattr_hook(inode: &InodeRef, ia_valid: u32) {
    let h = HOOKS.lock().setattr;
    if let Some(f) = h { f(inode, ia_valid); }
}

/// Install the filesystem-error hook. Fired by a filesystem that has detected
/// an on-disk inconsistency or an I/O failure of its own metadata, which is a
/// fact about the whole filesystem rather than about whichever caller happened
/// to trip over it. # C: O(1)
pub fn set_fs_error_hook(f: fn(u64, Option<&InodeRef>, i32)) { HOOKS.lock().fs_error = Some(f); }

/// Report a filesystem error: `fsid` is the filesystem's `st_dev`, `inode` the
/// object the failure was found on when one can be named, and `error` the
/// POSITIVE errno the failure surfaces as. No-op when no hook is installed.
/// # C: O(1) + subscriber
pub fn fire_fs_error(fsid: u64, inode: Option<&InodeRef>, error: i32) {
    let h = HOOKS.lock().fs_error;
    if let Some(f) = h { f(fsid, inode, error); }
}

/// Fire the dirent-create hook (no-op when not installed). # C: O(1)
pub fn fire_dirent_create(parent: &InodeRef, leaf: &str, leaf_is_dir: bool) {
    let h = HOOKS.lock().dirent_create;
    if let Some(f) = h { f(parent, leaf, leaf_is_dir); }
}

/// Fire the dirent-delete hook (no-op when not installed). # C: O(1)
pub fn fire_dirent_delete(parent: &InodeRef, leaf: &str, leaf_is_dir: bool) {
    let h = HOOKS.lock().dirent_delete;
    if let Some(f) = h { f(parent, leaf, leaf_is_dir); }
}

/// Fire the IN_OPEN hook (no-op when not installed). # C: O(1)
pub(crate) fn fire_open_hook(inode: &InodeRef, dentry: &Arc<Dentry>) {
    let h = HOOKS.lock().open;
    if let Some(f) = h { f(inode, dentry); }
}

/// Fire the IN_ACCESS hook (no-op when not installed). # C: O(1)
pub(crate) fn fire_read_hook(inode: &InodeRef, dentry: &Arc<Dentry>) {
    let h = HOOKS.lock().read;
    if let Some(f) = h { f(inode, dentry); }
}

/// Fire the IN_MODIFY hook (no-op when not installed). # C: O(1)
pub(crate) fn fire_write_hook(inode: &InodeRef, dentry: &Arc<Dentry>) {
    let h = HOOKS.lock().write;
    if let Some(f) = h { f(inode, dentry); }
}
