extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::Ordering;

use crate::inode::InodeRef;
use crate::types::OpenFlags;

use super::{dnotify_unregister, fasync_unregister, lease_unregister, File, F_UNLCK, O_ASYNC};
use super::hooks::{close_hooks, flock_release_hook};

impl Drop for File {
    fn drop(&mut self) {
        self.release_epoll_links();
        // Drop any lease / dnotify registration (Linux `__fput` → `locks_remove_file`
        // / `dnotify_flush`). Weaks self-expire, but prune eagerly + fix the counters.
        if self.lease.load(Ordering::Acquire) != F_UNLCK { lease_unregister(self); }
        if self.dnotify_mask.load(Ordering::Acquire) != 0 { dnotify_unregister(self); }
        // Drop the fasync registration weak (Linux `__fput` -> `f_op->fasync(.,
        // 0)` for an `O_ASYNC` file). Weaks self-expire, but prune eagerly.
        if (self.flags.load(Ordering::Acquire) & O_ASYNC) != 0 {
            fasync_unregister(self);
        }
        // `locks_remove_file`: inode-owned state is the canonical final-close
        // release point for BSD flock (and, once installed, OFD records).
        // The legacy hook below remains temporarily for callers not migrated
        // to `inode->i_flctx` yet.
        self.inode.file_lock_context().release_file(self as *const Self as usize);
        if self.flock_op.load(Ordering::Acquire) != 0 {
            let h = flock_release_hook();
            if h != 0 {
                // SAFETY: h was installed by `set_drop_hook` with a real fn(usize, &InodeRef) pointer.
                let f: fn(usize, &InodeRef) = unsafe { core::mem::transmute(h) };
                f(self as *const Self as usize, &self.inode);
            }
        }
        // Close-hook chain: inotify IN_CLOSE_*, pipe writer/reader
        // tracking, etc. Every installed slot fires.
        let was_writable = {
            let bits = self.flags.load(Ordering::Acquire);
            let f = OpenFlags::from_bits_retain(bits);
            f.contains(OpenFlags::O_WRONLY) || f.contains(OpenFlags::O_RDWR)
        };
        let close = close_hooks();
        for slot in close.iter() {
            if let Some(f) = slot { f(&self.inode, was_writable); }
        }
        // Last-close release per Linux `file_operations->release`: a
        // File == one open file description; dup'd fds share this Arc,
        // so Drop fires on the LAST close (incl. process exit). No lock
        // is held here (only atomics read above); on_release must not
        // block or panic. pty MASTER uses this to hang up the slave.
        self.f_op.on_release_file(self);
        // D11: release the `d_count` ref taken in `new_at` (Linux `dput` in
        // `__fput`). At zero the dentry is unused — `d_op->d_delete` may evict
        // it (pseudo-fs), otherwise it joins the dcache LRU for the shrinker.
        crate::dcache::dput(self.dentry.clone());
        // D3: release the `i_count` reference this open file description took on
        // its inode at construction (Linux `iput` reached via `__fput`→`dput`).
        // Routed through the owning superblock so a 1→0 drop runs the
        // `drop_inode`/`evict_inode` lifecycle; an anon inode (no superblock /
        // icache: pipe/eventfd/socket/…) just balances the count in place. The
        // matching `igrab` is in `new_at`, so this is always balanced and never
        // underflows regardless of how the inode was obtained.
        match self.inode.i_sb() {
            Some(sb) => sb.iput(self.inode.clone()),
            None     => { self.inode.i_count_dec(); }
        }
    }
}

/// Linux `get_file()` — take an additional reference to an open file
/// description, bumping `f_count` (here the `Arc<File>` strong count), and
/// return the new owning handle. A caller handing the SAME open file
/// description to a second owner (installing it at a second fd, stashing it
/// in a deferred-I/O request, …) uses this so the description stays alive
/// until BOTH owners `fput`; the last drop still runs `->release` once. This
/// is the open-file-description refcount only — it does NOT fire the
/// per-reference clone hook (`fire_clone_hook`), which the fd-table dup paths
/// invoke separately for pipe writer/reader accounting.
/// # C: O(1)
pub fn get_file(file: &Arc<File>) -> Arc<File> { Arc::clone(file) }

/// Linux `fput()` — drop one reference to an open file description,
/// decrementing `f_count`. Taking the handle BY MOVE makes the decrement
/// explicit at the call site (mirrors `void fput(struct file *)`); the
/// reference cannot be used afterward. When this was the last reference the
/// `File` `Drop` runs the backend release hook chain (flock release, close
/// hooks, `inode->on_release`, dentry `dput`) — Linux `__fput` /
/// `file_operations->release` — exactly once. Per-`close(2)` flush is NOT
/// done here; that is `filp_close`'s job (`FdTable::close` calls `flush`
/// before the final `fput`).
/// # C: O(1) amortized; last-ref also runs the release hook chain
pub fn fput(file: Arc<File>) { drop(file); }

/// Release ONE `i_count` reference on `inode` (Linux `iput`). A superblock-backed
/// inode routes through [`SuperBlock::iput`] so a 1→0 drop runs the
/// `drop_inode`/`evict_inode` lifecycle; an anon inode (no SB / icache) just
/// balances the count in place. The PUBLIC form of the dcache's private
/// `dentry_iput`, mirrored from `File::drop` — for callers (D3/D37) that obtained
/// an inode via `iget`/`build`/`i_op->create` and must release that
/// temporary/born reference once a DURABLE counted holder (a dentry alias from
/// `d_add`/`d_instantiate`, or an open `File`'s `igrab`) is already in place. This
/// is Linux's `d_instantiate` consuming the iget reference, expressed at the
/// caller side so the dcache primitive's own `grab_inode_hold` contract is
/// unchanged. MUST be called only AFTER such a holder exists, so `i_count` never
/// reaches 0 on a still-live inode. # C: O(log N_ino) for an SB inode, else O(1)
pub fn iput(inode: InodeRef) {
    match inode.i_sb() {
        Some(sb) => sb.iput(inode),
        None     => { inode.i_count_dec(); }
    }
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("File")
            .field("ino", &self.inode.ino())
            .field("pos", &self.pos())
            .field("flags", &self.flags())
            .finish()
    }
}
