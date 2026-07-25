use core::sync::atomic::{AtomicU64, Ordering};

use sync::Spinlock;

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
    open:  Option<fn(&InodeRef)>,
    /// IN_ACCESS — fired after a `read` returns >0 (Linux `fsnotify_access`).
    read:  Option<fn(&InodeRef)>,
    /// IN_MODIFY — fired after a `write` returns >0 (Linux `fsnotify_modify`).
    write: Option<fn(&InodeRef)>,
    /// Per-reference clone (fork_clone / dup / dup2): pipe writer-count++.
    /// `bool` = opened-writable.
    clone: Option<fn(&InodeRef, bool)>,
    /// IN_CLOSE_* + pipe close accounting, fired in `File::Drop`. Multiple
    /// subsystems register; every occupied slot fires. `bool` = was-writable.
    close: [Option<fn(&InodeRef, bool)>; CLOSE_HOOK_SLOTS],
    /// IN_CREATE — dirent created in a watched parent inode. Args: (parent, leaf).
    dirent_create: Option<fn(&InodeRef, &str)>,
    /// IN_DELETE — dirent removed from a watched parent inode. Args: (parent, leaf).
    dirent_delete: Option<fn(&InodeRef, &str)>,
}

impl InodeHooks {
    /// # C: O(1)
    const fn new() -> Self {
        Self { open: None, read: None, write: None, clone: None,
               close: [None; CLOSE_HOOK_SLOTS], dirent_create: None, dirent_delete: None }
    }
}

/// Lock class for the typed hook registry. Taken standalone — the fire path
/// copies the `Option<fn>` out and releases the lock BEFORE calling, so it
/// never nests under the inode / pos / ra locks. # C: O(1)
struct HookReg;
impl sync::LockClass for HookReg { fn rank() -> u16 { 33 } fn name() -> &'static str { "HookReg" } }

static HOOKS: Spinlock<InodeHooks, HookReg> = Spinlock::new(InodeHooks::new());

/// Snapshot installed close hooks before running foreign callbacks. # C: O(1)
pub(super) fn close_hooks() -> [Option<fn(&InodeRef, bool)>; CLOSE_HOOK_SLOTS] {
    HOOKS.lock().close
}

/// Snapshot the flock release hook pointer for `File::Drop`. # C: O(1)
pub(super) fn flock_release_hook() -> u64 {
    FLOCK_RELEASE_HOOK.load(Ordering::Acquire)
}

/// Install the open hook (fires IN_OPEN at `File::new_at`). # C: O(1)
pub fn set_open_hook(f: fn(&InodeRef))  { HOOKS.lock().open = Some(f); }

/// Install the read hook (fires IN_ACCESS after `File::read` returns >0). # C: O(1)
pub fn set_read_hook(f: fn(&InodeRef))  { HOOKS.lock().read = Some(f); }

/// Install the post-write hook used by inotify(7) to fire IN_MODIFY. # C: O(1)
pub fn set_write_hook(f: fn(&InodeRef)) { HOOKS.lock().write = Some(f); }

/// Install a close hook (fires at `File::Drop`; `bool` = opened-writable).
/// Takes the next free slot; panics if the table is full so a misconfiguration
/// is loud rather than silent. # C: O(N) slot scan, N=4 fixed.
pub fn set_close_hook(f: fn(&InodeRef, bool)) {
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
pub fn set_dirent_create_hook(f: fn(&InodeRef, &str)) { HOOKS.lock().dirent_create = Some(f); }
/// Install the dirent-delete hook (fires IN_DELETE; args (parent inode, leaf)). # C: O(1)
pub fn set_dirent_delete_hook(f: fn(&InodeRef, &str)) { HOOKS.lock().dirent_delete = Some(f); }

/// Fire the dirent-create hook (no-op when not installed). # C: O(1)
pub fn fire_dirent_create(parent: &InodeRef, leaf: &str) {
    let h = HOOKS.lock().dirent_create;
    if let Some(f) = h { f(parent, leaf); }
}

/// Fire the dirent-delete hook (no-op when not installed). # C: O(1)
pub fn fire_dirent_delete(parent: &InodeRef, leaf: &str) {
    let h = HOOKS.lock().dirent_delete;
    if let Some(f) = h { f(parent, leaf); }
}

/// Fire the IN_OPEN hook (no-op when not installed). # C: O(1)
pub(crate) fn fire_open_hook(inode: &InodeRef) {
    let h = HOOKS.lock().open;
    if let Some(f) = h { f(inode); }
}

/// Fire the IN_ACCESS hook (no-op when not installed). # C: O(1)
pub(crate) fn fire_read_hook(inode: &InodeRef) {
    let h = HOOKS.lock().read;
    if let Some(f) = h { f(inode); }
}

/// Fire the IN_MODIFY hook (no-op when not installed). # C: O(1)
pub(crate) fn fire_write_hook(inode: &InodeRef) {
    let h = HOOKS.lock().write;
    if let Some(f) = h { f(inode); }
}
