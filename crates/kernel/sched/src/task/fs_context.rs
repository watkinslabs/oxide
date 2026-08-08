//! Task filesystem-context ownership (`fs_struct` analogue).
//!
//! One `FsContext` owns the rendered diagnostic paths and the canonical VFS
//! root/pwd paths.  Callers receive cloned snapshots only; no raw task path
//! storage escapes this module.

use alloc::string::String;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{Dentry, VfsPath};

/// `S_IRWXUGO` — the only bits `umask(2)` retains (Linux: `mask & S_IRWXUGO`).
/// # C: O(1)
pub const UMASK_MASK: u32 = 0o777;

/// Boot/init `fs_struct.umask` before any `umask(2)` call.
const UMASK_DEFAULT: u32 = 0o022;

/// Owned snapshot of one filesystem context.  The VFS paths retain their
/// dentry/inode references, so a lookup may use the snapshot after its lock is
/// released.  Mount lifetime ownership is supplied by the VFS path contract.
#[derive(Clone)]
pub struct FsContextSnapshot {
    cwd:     String,
    cwd_vfs: Option<VfsPath>,
    root:    String,
    root_vfs: Option<VfsPath>,
    umask:   u32,
}

impl FsContextSnapshot {
    /// Rendered current directory retained for getcwd/proc rendering. # C: O(len)
    pub fn cwd(&self) -> String { self.cwd.clone() }

    /// Current directory path retained for name resolution. # C: O(1)
    pub fn cwd_vfs(&self) -> Option<VfsPath> { self.cwd_vfs.clone() }

    /// Rendered chroot path retained for diagnostics/proc rendering. # C: O(len)
    pub fn root(&self) -> String { self.root.clone() }

    /// Chroot path retained for absolute name resolution. # C: O(1)
    pub fn root_vfs(&self) -> Option<VfsPath> { self.root_vfs.clone() }

    /// `fs_struct.umask` at snapshot time. # C: O(1)
    pub fn umask(&self) -> u32 { self.umask }
}

struct FsContextState {
    cwd:     String,
    cwd_vfs: Option<VfsPath>,
    root:    String,
    root_vfs: Option<VfsPath>,
}

impl FsContextState {
    fn snapshot(&self, umask: u32) -> FsContextSnapshot {
        FsContextSnapshot {
            cwd: self.cwd.clone(), cwd_vfs: self.cwd_vfs.clone(),
            root: self.root.clone(), root_vfs: self.root_vfs.clone(),
            umask,
        }
    }
}

/// Linux-shaped shared filesystem owner (`struct fs_struct`).  Task cloning
/// either shares this `Arc` for `CLONE_FS` or constructs a new owner from a
/// snapshot.  The state lock serializes root/pwd replacement with remote
/// pivot-root repointing and snapshot acquisition.
pub struct FsContext {
    state: Spinlock<FsContextState, TaskListClass>,
    /// Linux `fs_struct.umask`. It lives HERE, not on the task, because
    /// `umask(2)` mutates the shared filesystem owner: every `CLONE_FS`
    /// sibling (which is every thread of a process) observes one mask, and
    /// `unshare(CLONE_FS)` is what splits it.
    umask: AtomicU32,
}

impl FsContext {
    /// Construct the initial `/` filesystem context — Linux `init_fs` after
    /// `init_mount_tree()` ran `set_fs_pwd`/`set_fs_root` on it:
    /// root AND pwd are the mount-namespace root `struct path`, not "unset".
    /// A live task's `fs->root` is what `/proc/<pid>/root` resolves to
    /// (`proc_root_link` → `get_task_root`), so leaving it unset
    /// makes that magic link ENOENT — which systemd reads as "I am in a
    /// chroot" and then skips `udevadm trigger`, leaving the udev database
    /// empty for the whole boot. `None` only before the root filesystem is
    /// mounted (Linux's pre-`init_mount_tree` window). # C: O(log N)
    pub fn new() -> Self {
        let root = vfs::mount::root_path_for_ns(vfs::mount::current_ns());
        Self { state: Spinlock::new(FsContextState {
            cwd: String::from("/"), cwd_vfs: root.clone(),
            root: String::from("/"), root_vfs: root,
        }), umask: AtomicU32::new(UMASK_DEFAULT) }
    }

    /// Construct an independent filesystem owner from an owned snapshot. # C: O(1)
    pub fn from_snapshot(snapshot: FsContextSnapshot) -> Self {
        Self { state: Spinlock::new(FsContextState {
            cwd: snapshot.cwd, cwd_vfs: snapshot.cwd_vfs,
            root: snapshot.root, root_vfs: snapshot.root_vfs,
        }), umask: AtomicU32::new(snapshot.umask) }
    }

    /// Clone one coherent root/pwd snapshot while holding the owner lock. # C: O(1)
    pub fn snapshot(&self) -> FsContextSnapshot {
        let umask = self.umask.load(Ordering::Acquire);
        self.state.lock().snapshot(umask)
    }

    /// `umask(2)`: install `mask & S_IRWXUGO` and return
    /// the PREVIOUS mask. # C: O(1)
    pub fn swap_umask(&self, mask: u32) -> u32 {
        self.umask.swap(mask & UMASK_MASK, Ordering::AcqRel)
    }

    /// Current `fs_struct.umask`. # C: O(1)
    pub fn umask(&self) -> u32 { self.umask.load(Ordering::Acquire) }

    /// Replace the current working directory after lookup completed. # C: O(1)
    pub fn set_cwd(&self, cwd: String, cwd_vfs: VfsPath) {
        let mut state = self.state.lock();
        state.cwd = cwd;
        state.cwd_vfs = Some(cwd_vfs);
    }

    /// Replace the chroot root after lookup and permission checks completed. # C: O(1)
    pub fn set_root(&self, root: String, root_vfs: VfsPath) {
        let mut state = self.state.lock();
        state.root = root;
        state.root_vfs = Some(root_vfs);
    }

    /// Repoint root and pwd that refer exactly to a pivoted mount root. # C: O(1)
    pub fn repoint_old_root(&self, old_mnt: u64, old_dentry: Option<&Arc<Dentry>>, replacement: &VfsPath) {
        let mut state = self.state.lock();
        if at_old_root(&state.root_vfs, old_mnt, old_dentry) { state.root_vfs = Some(replacement.clone()); }
        if at_old_root(&state.cwd_vfs, old_mnt, old_dentry) { state.cwd_vfs = Some(replacement.clone()); }
    }

    /// Rewrite this owner's VFS mount identities after mount-namespace copy. # C: O(paths × map)
    pub fn remap_mount_ids(&self, mount_map: &[(u64, u64)]) {
        let mut state = self.state.lock();
        remap_one(&mut state.cwd_vfs, mount_map);
        remap_one(&mut state.root_vfs, mount_map);
    }
}

impl super::Task {
    /// Obtain the shared Linux-style filesystem owner. # C: O(1)
    pub fn fs_context(&self) -> Arc<FsContext> { self.fs_context.lock().clone() }

    /// Clone a coherent root/pwd state without exposing task storage. # C: O(1)
    pub fn fs_context_snapshot(&self) -> FsContextSnapshot { self.fs_context().snapshot() }

    /// Inherit a parent's filesystem context for clone/fork.  `share` is true
    /// only for `CLONE_FS`; ordinary fork receives an independent owner. # C: O(1)
    pub fn inherit_fs_context_from(&self, parent: &super::Task, share: bool) {
        let inherited = parent.fs_context();
        let context = if share { inherited } else { Arc::new(FsContext::from_snapshot(inherited.snapshot())) };
        *self.fs_context.lock() = context;
    }

    /// Copy-on-write this task's filesystem owner for `unshare(CLONE_FS)` and
    /// mount-namespace changes that must not alter CLONE_FS siblings. # C: O(1)
    pub fn unshare_fs_context(&self) {
        let current = self.fs_context();
        *self.fs_context.lock() = Arc::new(FsContext::from_snapshot(current.snapshot()));
    }

    /// Linux `fs->users`: how many tasks share this `fs_struct`.
    ///
    /// `mntns_install` refuses `setns(CLONE_NEWNS)` unless this is exactly 1
    /// — stricter than `fs_context_shared_outside_thread_group`'s
    /// `LSM_UNSAFE_SHARE` rule, because re-rooting moves cwd and root for
    /// EVERY sharer, including a `CLONE_FS` thread in the caller's own group.
    /// # C: O(1)
    pub fn fs_context_users(&self) -> usize {
        // One strong ref is the clone `fs_context()` just handed back.
        Arc::strong_count(&self.fs_context()) - 1
    }

    /// Whether two tasks reference the same `CLONE_FS` owner. # C: O(1)
    pub fn shares_fs_context_with(&self, other: &super::Task) -> bool {
        Arc::ptr_eq(&self.fs_context(), &other.fs_context())
    }

    /// Linux `check_unsafe_exec`'s `LSM_UNSAFE_SHARE`:
    /// `p->fs->users > n_fs`, where `n_fs` counts this task plus the threads of
    /// its own group that share the owner. A task OUTSIDE the thread group
    /// holding the same `fs_struct` can rewrite cwd/root while the exec is in
    /// flight, so `cap_bprm_creds_from_file` refuses the setuid transition.
    /// # C: O(threads in group)
    pub fn fs_context_shared_outside_thread_group(&self) -> bool {
        let mine = self.fs_context();
        // One of the strong refs is the clone just taken; the rest are tasks.
        let users = Arc::strong_count(&mine) - 1;
        let mut n_fs = 1usize;
        for (_vtid, tid) in crate::registry::thread_entries(self.tgid.load(Ordering::Acquire)) {
            if tid == self.tid { continue; }
            if let Some(t) = crate::registry::lookup(tid) {
                if Arc::ptr_eq(&t.fs_context(), &mine) { n_fs += 1; }
            }
        }
        users > n_fs
    }

    /// Replace the current working directory after successful lookup. # C: O(1)
    pub fn set_fs_cwd(&self, cwd: String, cwd_vfs: VfsPath) { self.fs_context().set_cwd(cwd, cwd_vfs); }

    /// Replace the chroot resolution root after successful lookup. # C: O(1)
    pub fn set_fs_root(&self, root: String, root_vfs: VfsPath) { self.fs_context().set_root(root, root_vfs); }

    /// `umask(2)`: swap the shared filesystem owner's mask, returning the
    /// previous one. # C: O(1)
    pub fn swap_umask(&self, mask: u32) -> u32 { self.fs_context().swap_umask(mask) }

    /// Creation mask applied by open/mkdir/mknod (Linux `current_umask()`).
    /// # C: O(1)
    pub fn umask(&self) -> u32 { self.fs_context().umask() }

    /// Repoint this task's context during pivot_root's `chroot_fs_refs`. # C: O(1)
    pub fn repoint_fs_old_root(&self, old_mnt: u64, old_dentry: Option<&Arc<Dentry>>, replacement: &VfsPath) {
        self.fs_context().repoint_old_root(old_mnt, old_dentry, replacement);
    }

    /// Rewrite this task's path mount ids after its filesystem owner was made
    /// private for a mount namespace transition. # C: O(paths × map)
    pub fn remap_fs_mount_ids(&self, mount_map: &[(u64, u64)]) { self.fs_context().remap_mount_ids(mount_map); }
}

fn at_old_root(path: &Option<VfsPath>, old_mnt: u64, old_dentry: Option<&Arc<Dentry>>) -> bool {
    match path {
        Some(path) if path.mnt_id == old_mnt => match old_dentry {
            Some(dentry) => Arc::ptr_eq(&path.dentry, dentry),
            None => true,
        },
        _ => false,
    }
}

fn remap_one(path: &mut Option<VfsPath>, mount_map: &[(u64, u64)]) {
    let Some(path) = path.as_mut() else { return };
    if let Some((_, new_mnt)) = mount_map.iter().find(|(old_mnt, _)| *old_mnt == path.mnt_id) {
        path.mnt_id = *new_mnt;
    }
}
