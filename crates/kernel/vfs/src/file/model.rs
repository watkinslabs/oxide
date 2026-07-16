extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::Spinlock;

use crate::dentry::Dentry;
use crate::file_ops::FileOps;
use crate::inode::InodeRef;
use crate::namei::Cred;
use crate::types::{FileType, OpenFlags};

use super::{fire_open_hook, fasync_register, fasync_unregister, fmode_from_flags, File, FileCred, FileRaState, Fmode, DEFAULT_RA_PAGES, O_ASYNC, SETFL_MASK};

impl File {
    /// Anonymous-inode / early-boot constructor: no vfsmount (`mnt_id=0`)
    /// and root credentials. Used by every anon fd (pipe/eventfd/socket/
    /// memfd/timerfd/…) where there is no mount the file was opened
    /// through — exactly Linux's `anon_inode` files.
    /// # C: O(1)
    pub fn new(inode: InodeRef, dentry: Arc<Dentry>, flags: OpenFlags) -> Arc<Self> {
        Self::new_at(inode, dentry, flags, 0, FileCred::root())
    }

    /// Full `f_path`-carrying constructor (Linux `struct file` with
    /// `f_path = {mnt, dentry}`): records the `mnt_id` the file was
    /// opened through plus the opener's credentials. The real-FS open
    /// paths (`openat`/`open`/`install_open_at`) call this with the
    /// resolved `VfsPath.mnt_id`.
    /// # C: O(1)
    pub fn new_at(
        inode: InodeRef,
        dentry: Arc<Dentry>,
        flags: OpenFlags,
        mnt_id: u64,
        cred: FileCred,
    ) -> Arc<Self> {
        // D2: default binding snapshots `inode->i_fop` into `file->f_op`.
        let f_op = inode.i_fop().clone();
        Self::new_at_fop(inode, dentry, flags, mnt_id, cred, f_op)
    }

    /// `f_op`-OVERRIDE constructor — Linux `fifo_open` (and any `f_op->open`
    /// that swaps the vtable) sets `filp->f_op` to something OTHER than the
    /// inode's `i_fop` for the life of this open description. The FIFO open path
    /// resolves a named-pipe inode (whose on-disk `i_fop` is a metadata-only /
    /// EIO stub) and installs the pipe read/write/poll vtable ON THIS FILE ONLY
    /// via `pipefifo_fops`, so the returned fd's data path goes through the pipe
    /// ring while the inode's other opens/aliases are untouched. `f_op` is the
    /// already-resolved vtable to snapshot into `file->f_op` (Linux `f->f_op =
    /// fops`); everything else matches [`Self::new_at`]. # C: O(1)
    pub fn new_at_fop(
        inode: InodeRef,
        dentry: Arc<Dentry>,
        flags: OpenFlags,
        mnt_id: u64,
        cred: FileCred,
        f_op: Arc<dyn FileOps>,
    ) -> Arc<Self> {
        fire_open_hook(&inode);
        let mut f_mode = fmode_from_flags(flags);
        // FMODE_LSEEK/PREAD/PWRITE (Linux `do_dentry_open`): a seekable backing
        // (anything but a streaming pipe/socket/fifo) carries a real cursor +
        // positional I/O → all three bits; an O_PATH (`empty_fops`) / streaming
        // file gets none. Computed once so `seek`/`pread`/`pwrite` read `f_mode`.
        if !f_mode.contains(Fmode::PATH)
            && !matches!(inode.file_type(), FileType::Fifo | FileType::Socket)
        {
            f_mode |= Fmode::LSEEK | Fmode::PREAD | Fmode::PWRITE;
        }
        // D11 (`16§97` lockref): the open file description pins its dentry with a
        // `d_count` ref (Linux `struct file` holds a `dget`'d `f_path.dentry`);
        // the matching `dput` is in `File::drop`.
        let dentry = crate::dcache::dget(&dentry);
        // D3: the open file description takes an `i_count` reference on its inode
        // (Linux `struct file` pins the inode; iget/igrab supplies the ref). The
        // matching `iput`/dec is in `File::drop`.
        inode.igrab();
        Arc::new(Self {
            inode,
            f_op,
            dentry,
            mnt_id,
            f_mode,
            f_cred: cred,
            private_data: AtomicU64::new(0),
            pos:   AtomicU64::new(0),
            f_pos_lock: Spinlock::new(()),
            f_ra: Spinlock::new(FileRaState { ra_pages: DEFAULT_RA_PAGES, ..FileRaState::default() }),
            flags: AtomicU32::new(flags.bits()),
            flock_op: AtomicU32::new(0),
            owner: ::core::sync::atomic::AtomicI32::new(0),
            owner_creds: AtomicU64::new(0),
            f_sig: ::core::sync::atomic::AtomicI32::new(0),
            // F_UNLCK (2) = no lease held (Linux `F_GETLEASE` default).
            lease: core::sync::atomic::AtomicI32::new(2),
            dnotify_mask: AtomicU32::new(0),
            f_version: AtomicU64::new(0),
            // RWH_WRITE_LIFE_NOT_SET (Linux `F_GET_RW_HINT` default).
            rw_hint: AtomicU64::new(0),
            epoll_links: Spinlock::new(alloc::vec::Vec::new()),
        })
    }

    /// `f_count` snapshot (Linux `atomic_long_read(&file->f_count)`): the
    /// number of open-file-description references currently alive — fd-table
    /// slots, dups, and in-flight `get_file` takers all count. The reference
    /// count IS the backing `Arc<File>` strong count; the LAST one to drop
    /// (its `fput`) runs the backend release hook chain exactly once. `1`
    /// means this is the sole owner. Advisory under concurrent get_file/fput.
    /// # C: O(1)
    pub fn f_count(self: &Arc<Self>) -> usize { Arc::strong_count(self) }

    /// `f_inode` cache (Linux `file->f_inode`). # C: O(1)
    pub fn inode(&self) -> &InodeRef { &self.inode }

    /// Alias for `inode()` matching Linux `file_inode()` naming. # C: O(1)
    pub fn f_inode(&self) -> &InodeRef { &self.inode }

    /// # C: O(1)
    pub fn dentry(&self) -> &Arc<Dentry> { &self.dentry }

    /// `f_path` = (vfsmount id, dentry) per Linux `struct path`. # C: O(1)
    pub fn f_path(&self) -> (u64, &Arc<Dentry>) { (self.mnt_id, &self.dentry) }

    /// The id of the vfsmount this file was opened through; 0 = anon. # C: O(1)
    pub fn mnt_id(&self) -> u64 { self.mnt_id }

    /// Resolve `f_path.mnt` to its `Mount`, if still mounted. # C: O(log N)
    pub fn vfsmount(&self) -> Option<Arc<crate::mount::Mount>> {
        if self.mnt_id == 0 { return None; }
        crate::mount::mount_by_id(self.mnt_id)
    }

    /// True iff a write through this open file description must be refused
    /// `EROFS` because its mount or backing superblock is read-only (Linux
    /// `mnt_want_write` → `__mnt_want_write` + `sb_rdonly`). Reads the mount
    /// the file was opened THROUGH (the captured `f_path.vfsmount`, recovered
    /// by `mnt_id`) — O(1) by mount-id lookup — instead of re-deriving the
    /// absolute pathname and re-walking it on every write, which could resolve
    /// a DIFFERENT mount than the one the file was opened through if the tree
    /// changed since open. An anon file (`mnt_id == 0`: pipe/socket/eventfd/…)
    /// has no vfsmount and is never mount-RO-blocked; its backend governs
    /// writability directly.
    /// # C: O(log N)
    pub(super) fn mnt_readonly(&self) -> bool {
        // Linux `mnt_want_write` protects filesystem data. Character and block
        // device writes are driver operations and remain valid on a read-only
        // filesystem mount; their f_op owns device-specific admission.
        if !matches!(self.inode.file_type(), crate::FileType::Regular) { return false; }
        match self.vfsmount() {
            Some(m) => (m.flags() & crate::mount::MNT_RDONLY) != 0 || m.sb().is_readonly(),
            None    => false,
        }
    }

    /// `f_mode` (FMODE_* capability bits). # C: O(1)
    pub fn f_mode(&self) -> Fmode { self.f_mode }

    /// `f_cred` — opener's credential snapshot. # C: O(1)
    pub fn f_cred(&self) -> &crate::namei::Cred { self.f_cred.dac() }

    /// Full retained opener credential snapshot. # C: O(1)
    pub fn file_cred(&self) -> &FileCred { &self.f_cred }

    /// `file->private_data` slot read. # C: O(1)
    pub fn private_data(&self) -> u64 { self.private_data.load(Ordering::Acquire) }

    /// `file->private_data` slot write. # C: O(1)
    pub fn set_private_data(&self, v: u64) { self.private_data.store(v, Ordering::Release); }

    /// `f_op->poll` for this open file description. This is the Linux
    /// `struct file *` poll shape; inode-only polling remains the default for
    /// backends that do not need per-open state.
    /// # C: O(1)
    pub fn poll(&self) -> u32 {
        self.f_op.poll_open_file(self)
    }

    /// Wait source selected by `f_op->poll` registration for this caller.
    /// # C: O(1)
    pub fn poll_subscribers(&self) -> Option<Arc<crate::PollSubscribers>> {
        self.f_op.poll_subscribers(self)
    }

    /// Earliest monotonic deadline for an unnotified readiness transition.
    /// # C: O(1)
    pub fn poll_deadline_ns(&self) -> Option<u64> {
        self.f_op.poll_deadline_ns(self)
    }

    /// `file_operations->fasync` dispatch for this open file description.
    /// Backends that support async notification adjust `FASYNC` themselves,
    /// matching Linux's `f_op->fasync` ownership of the flag transition.
    /// # C: backend-dependent
    pub fn fasync(self: &Arc<Self>, fd: i32, on: bool) -> crate::KResult<()> {
        self.f_op.fasync_file(fd, self, on)
    }

    /// Int-valued `file_operations->unlocked_ioctl` dispatch for queue queries.
    /// # C: backend-dependent
    pub fn ioctl_int(&self, cmd: crate::IoctlIntCmd) -> crate::KResult<u32> {
        self.f_op.ioctl_int(self, cmd)
    }

    /// `file_operations->unlocked_ioctl` dispatch for file-specific ioctls.
    /// # C: backend-dependent
    pub fn unlocked_ioctl(
        &self,
        idmap: &crate::idmap::Idmap,
        cred: &Cred,
        cmd: crate::FileIoctlCmd,
    ) -> crate::KResult<crate::FileIoctlReply> {
        self.f_op.unlocked_ioctl(self, idmap, cred, cmd)
    }

    /// Generic `fasync_helper` state transition for async-capable backends.
    /// Unsupported files never reach this; their `f_op->fasync` default returns
    /// `ENOTTY`, so no registry entry is published by accident. # C: O(1)
    pub fn set_fasync_state(self: &Arc<Self>, on: bool) {
        let mut fl = self.flags();
        let async_flag = OpenFlags::from_bits_retain(O_ASYNC);
        if on {
            fl |= async_flag;
            self.set_flags(fl);
            fasync_register(self);
        } else {
            fl &= !async_flag;
            self.set_flags(fl);
            fasync_unregister(self);
        }
    }

    /// Run `file_operations->open` after this open file description exists.
    /// # C: backend-dependent
    pub fn open_hook(&self) -> crate::KResult<()> { self.f_op.on_open_file(self) }

    /// `F_SET_RW_HINT` (Linux `fcntl_rw_hint`): store the `RWH_WRITE_LIFE_*`
    /// write-life hint. Advisory; forwarded to a hinting block backend. # C: O(1)
    pub fn set_rw_hint(&self, hint: u64) { self.rw_hint.store(hint, Ordering::Release); }

    /// `F_GET_RW_HINT`: the stored write-life hint (`0` = `NOT_SET`). # C: O(1)
    pub fn rw_hint(&self) -> u64 { self.rw_hint.load(Ordering::Acquire) }

    /// `file->f_version` read — the change-version a `readdir` cursor was built against. # C: O(1)
    pub fn f_version(&self) -> u64 { self.f_version.load(Ordering::Acquire) }
    /// `file->f_version` stamp (Linux: from `inode_query_iversion` at cursor setup). # C: O(1)
    pub fn set_f_version(&self, v: u64) { self.f_version.store(v, Ordering::Release); }
    /// True when the inode's change-version advanced past the last `f_version`
    /// stamp — the cached `readdir` position is stale (Linux `file->f_version !=
    /// inode->i_version`). # C: O(1)
    pub fn dir_version_changed(&self) -> bool {
        crate::inode::inode_query_iversion(&*self.inode) != self.f_version.load(Ordering::Acquire)
    }

    /// Snapshot of the `f_ra` readahead window state. # C: O(1)
    pub fn ra_state(&self) -> FileRaState { *self.f_ra.lock() }

    /// Set the readahead window ceiling in pages (Linux `POSIX_FADV_SEQUENTIAL`
    /// doubles the default, `POSIX_FADV_RANDOM` zeroes it to disable RA). # C: O(1)
    pub fn set_ra_pages(&self, pages: u32) { self.f_ra.lock().ra_pages = pages; }

    /// On-demand readahead advance (Linux `ondemand_readahead` core): from the
    /// read's first page `index`, page count `req`, and whether the PG_readahead
    /// marker was hit, update `f_ra` and return the `(start, size, async_size)`
    /// window to submit (page-cache fill is the block lane). `ra_pages == 0`
    /// (FADV_RANDOM) disables RA; a sequential continuation (`index==start+size`)
    /// or marker hit grows via `next_ra_size`; SOF / a jump re-seeds via
    /// `init_ra_size`. # C: O(1)
    pub fn ra_ondemand(&self, index: u64, req: u32, hit_marker: bool) -> (u64, u32, u32) {
        let mut ra = self.f_ra.lock();
        let max = ra.ra_pages;
        if max == 0 { *ra = FileRaState { start: index, ..*ra }; return (index, 0, 0); }
        let sequential = index == ra.start + ra.size as u64;
        if index != 0 && (sequential || hit_marker) {
            ra.start = if sequential { ra.start + ra.size as u64 } else { index + 1 };
            ra.size = ra.next_ra_size(max);
            ra.async_size = ra.size;
        } else {
            ra.start = index;
            ra.size = FileRaState::init_ra_size(req, max);
            ra.async_size = if ra.size > req { ra.size - req } else { ra.size };
        }
        (ra.start, ra.size, ra.async_size)
    }

    /// Per-close flush (Linux `file_operations->flush`, fired by
    /// `filp_close` on every `close(2)`/`dup2`-replace/cloexec drop —
    /// NOT only the last). Dispatches through this open file description's
    /// snapshotted `f_op`, not the inode's current `i_fop`. # C: depends on f_op
    pub fn flush(&self) -> crate::KResult<()> { self.f_op.on_flush_file(self) }

    /// FMODE_ATOMIC_POS predicate (Linux `do_dentry_open`: set only for
    /// `S_ISREG`/`S_ISDIR`). Seekable files carry a real cursor whose
    /// pos-read -> I/O -> pos-update must be serialized against a shared
    /// fd; non-seekable files (pipe/socket/fifo) ignore `pos` and their
    /// I/O may park, so they skip the (non-sleeping) pos lock entirely.
    /// # C: O(1)
    pub(super) fn atomic_pos(&self) -> bool {
        matches!(self.inode.file_type(), FileType::Regular | FileType::Directory)
    }

    /// Snapshot of the file position.
    /// # C: O(1)
    pub fn pos(&self) -> u64 { self.pos.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn set_pos(&self, p: u64) { self.pos.store(p, Ordering::Release); }

    /// Snapshot of open flags.
    /// # C: O(1)
    pub fn flags(&self) -> OpenFlags {
        OpenFlags::from_bits_retain(self.flags.load(Ordering::Acquire))
    }

    /// # C: O(1)
    pub fn set_flags(&self, f: OpenFlags) {
        self.flags.store(f.bits(), Ordering::Release);
    }

    /// `fcntl(F_SETFL, arg)` (Linux `setfl`): update ONLY the `SETFL_MASK`
    /// bits (`O_APPEND`/`O_NONBLOCK`/`O_DIRECT`/`O_NOATIME`) of `f_flags`
    /// from `arg`, preserving the access mode and the creation-time flags
    /// which are fixed for the life of the open file description. The caller
    /// passes the full requested flag word (as glibc/musl forward the user's
    /// `arg` verbatim); the masking is done here so the syscall shim carries
    /// no flag logic (`53§3`). Returns the resulting `f_flags`. Concurrent
    /// `F_SETFL` on a shared description is last-writer-wins on the atomic,
    /// matching Linux's `f_lock`-guarded single store.
    /// # C: O(1)
    pub fn set_fl(&self, arg: OpenFlags) -> OpenFlags {
        let old = self.flags.load(Ordering::Acquire);
        let new = (arg.bits() & SETFL_MASK) | (old & !SETFL_MASK);
        self.flags.store(new, Ordering::Release);
        OpenFlags::from_bits_retain(new)
    }
}
