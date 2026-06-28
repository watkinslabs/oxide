// `File` per `16§5`. The kernel-side handle that an FD entry points
// to: cached inode / dentry, current position, open flags. Per-process
// FD table lives in `fdtable.rs`.

extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::Spinlock;

use crate::dentry::Dentry;
use crate::inode::InodeRef;
use crate::namei::Cred;
use crate::types::{FileType, KResult, OpenFlags, VfsError};

/// Lock class for `File::f_pos_lock` (`06§3.6`). Ranked below `Inode`
/// (40): the pos lock is acquired in `read`/`write` BEFORE the inode I/O
/// that takes the inode lock, mirroring Linux `__fdget_pos` preceding
/// `vfs_read`/`vfs_write`. Defined locally (not in the shared `sync`
/// taxonomy) so this change stays self-contained.
struct FilePos;
impl sync::LockClass for FilePos {
    /// # C: O(1)
    fn rank() -> u16 { 35 }
}

bitflags::bitflags! {
    /// `file->f_mode` access bits (Linux `include/linux/fs.h` `FMODE_*`).
    /// Derived once from the open access mode at `File` construction so
    /// permission checks read the canonical capability rather than
    /// re-deriving from `O_*` flags at each call. Numeric values match
    /// Linux exactly.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct Fmode: u32 {
        /// FMODE_READ — file is readable.
        const READ   = 0x0000_0001;
        /// FMODE_WRITE — file is writable.
        const WRITE  = 0x0000_0002;
        /// FMODE_LSEEK — file is seekable (`do_dentry_open`: `f_op->llseek`
        /// present and not `no_llseek`). Gates `lseek(2)`.
        const LSEEK  = 0x0000_0004;
        /// FMODE_PREAD — positional read supported (`f_op->read_iter`). Gates
        /// `pread(2)`.
        const PREAD  = 0x0000_0008;
        /// FMODE_PWRITE — positional write supported (`f_op->write_iter`).
        /// Gates `pwrite(2)`.
        const PWRITE = 0x0000_0010;
        /// FMODE_EXEC — opened for execution (`do_open_execat`).
        const EXEC   = 0x0000_0020;
        /// FMODE_PATH — O_PATH descriptor (no read/write, fd-ref only).
        const PATH   = 0x0000_4000;
    }
}

/// `O_PATH` bit (asm-generic, both arches — Linux `fcntl.h` `010000000`). Not
/// declared in `OpenFlags` (which only carries bits with an in-`vfs` consumer),
/// so it's matched here by raw value. An `O_PATH` fd is an fd-reference with
/// NEITHER `FMODE_READ` nor `FMODE_WRITE`; read/write on it are `EBADF`.
/// Caller (`openat`) must preserve this bit into the `File` flags (e.g.
/// `from_bits_retain`) for the gate to see it.
const O_PATH: u32 = 0o10000000;

/// `O_DIRECT` (asm-generic, 0o40000) and `O_NOATIME` (0o1000000) — settable
/// via `F_SETFL` but not declared in `OpenFlags` (no in-`vfs` consumer yet),
/// so they're matched here by raw value so the mask can preserve/update them
/// exactly like Linux. `O_NDELAY` aliases `O_NONBLOCK` on both arches.
const O_DIRECT:  u32 = 0o40000;
const O_NOATIME: u32 = 0o1000000;

/// Linux `SETFL_MASK` (`fs/fcntl.c`): the only `f_flags` bits `fcntl(F_SETFL)`
/// may change on an already-open file description. The access mode
/// (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) and the creation-time flags
/// (`O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_CLOEXEC`/`O_DIRECTORY`/…) are fixed at open
/// and silently ignored by `F_SETFL`, so they are excluded here.
const SETFL_MASK: u32 =
    OpenFlags::O_APPEND.bits() | OpenFlags::O_NONBLOCK.bits() | O_DIRECT | O_NOATIME;

/// Map an open's access mode (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) to the
/// canonical `Fmode` capability bits. Mirrors Linux `OPEN_FMODE`. An `O_PATH`
/// open yields `FMODE_PATH` only (no read/write) regardless of the access-mode
/// bits, matching Linux `do_dentry_open`.
/// # C: O(1)
fn fmode_from_flags(f: OpenFlags) -> Fmode {
    if (f.bits() & O_PATH) != 0 {
        return Fmode::PATH; // fd-reference only: no READ, no WRITE
    }
    let mut m = Fmode::empty();
    if f.contains(OpenFlags::O_RDWR) {
        m |= Fmode::READ | Fmode::WRITE;
    } else if f.contains(OpenFlags::O_WRONLY) {
        m |= Fmode::WRITE;
    } else {
        m |= Fmode::READ; // O_RDONLY (access mode 0)
    }
    m
}

/// Backing handle for an open file. Stored as `Arc<File>` so dup / fork
/// share the position cursor per POSIX (`15§2`).
pub struct File {
    inode:  InodeRef,
    dentry: Arc<Dentry>,
    /// `f_path.vfsmount` resolved by id (Linux `struct path.mnt`). The
    /// mount the file was opened through, recovered from the lookup's
    /// `VfsPath.mnt_id`. `0` = anonymous inode (pipe/eventfd/socket/…)
    /// with no vfsmount, matching Linux `anon_inode` files.
    mnt_id: u64,
    /// `f_mode` (FMODE_*), derived from the open access mode once at
    /// construction. Immutable for the life of the open description.
    f_mode: Fmode,
    /// `f_cred` — opener's credentials snapshot (Linux `file->f_cred`).
    /// Lets a deferred read/write enforce without re-reading task creds.
    f_cred: Cred,
    /// `file->private_data` — per-fd driver/anon-inode state slot.
    /// Default 0; opaque to the VFS core.
    private_data: AtomicU64,
    pos:    AtomicU64,
    /// `f_pos_lock` (Linux `struct file.f_pos_lock`, set for FMODE_ATOMIC_POS
    /// files). Serializes the pos-read -> I/O -> pos-update region in
    /// `read`/`write` so concurrent ops on a shared (dup / CLONE_FILES) open
    /// file description cannot interleave the cursor. Guards the separate
    /// `pos` atomic — payload is `()`. Only taken for seekable files
    /// (regular/directory); non-seekable I/O may park and ignores `pos`.
    f_pos_lock: Spinlock<(), FilePos>,
    flags:  AtomicU32,
    /// Currently-held flock kind: 0=none, 1=LOCK_SH, 2=LOCK_EX. Used
    /// by the kernel-side flock registry to find which lock to drop
    /// when the last reference to this open-file-description goes
    /// away (Drop impl below).
    pub flock_op: AtomicU32,
    /// F_GETOWN/F_SETOWN target: positive = tid, negative = -pgid, 0 = none.
    /// SIGIO/SIGURG delivery routes to this id when fasync fires. The bare id
    /// slot of Linux `f_owner.pid`; the credential snapshot lives in
    /// `owner_creds`, the delivery signal in `f_sig`.
    pub owner: core::sync::atomic::AtomicI32,
    /// `f_owner` credential snapshot (Linux `struct fown_struct.uid/.euid`)
    /// captured at `F_SETOWN`, so a deferred SIGIO permission-checks against
    /// the credentials that requested ownership, not those current when the
    /// signal fires. Packed `uid << 32 | euid`. The `Cred` subset carries one
    /// id, so uid==euid here until a separate euid lands.
    owner_creds: AtomicU64,
    /// `F_SETSIG`/`F_GETSIG` (Linux `f_owner.signum`): the signal delivered on
    /// async-I/O readiness; `0` = the default `SIGIO` (data) / `SIGURG` (OOB).
    f_sig: core::sync::atomic::AtomicI32,
}

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

/// Kernel-side write hook called from `File::write` after a successful
/// inode write. Used by the inotify subsystem to fire IN_MODIFY events.
/// `0` = no hook installed.
static WRITE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the post-write hook used by inotify(7) to fire IN_MODIFY.
/// # C: O(1)
pub fn set_write_hook(f: fn(&InodeRef)) {
    WRITE_HOOK.store(f as u64, Ordering::Release);
}

static OPEN_HOOK:  AtomicU64 = AtomicU64::new(0);
static READ_HOOK:  AtomicU64 = AtomicU64::new(0);

/// Close-hook slot table per `16§R02`. Multiple subsystems register
/// here (inotify IN_CLOSE_*, pipe writer/reader-count tracking, …);
/// every slot fires in `File::Drop`. Fixed N=4 covers the in-kernel
/// subsystems we have; extend if a new consumer arrives.
const CLOSE_HOOK_SLOTS: usize = 4;
static CLOSE_HOOKS: [AtomicU64; CLOSE_HOOK_SLOTS] =
    [const { AtomicU64::new(0) }; CLOSE_HOOK_SLOTS];

/// Install the open hook (fires IN_OPEN at File::new).
/// # C: O(1)
pub fn set_open_hook(f: fn(&InodeRef))  { OPEN_HOOK.store(f as u64, Ordering::Release); }

/// Install the read hook (fires IN_ACCESS after File::read returns >0).
/// # C: O(1)
pub fn set_read_hook(f: fn(&InodeRef))  { READ_HOOK.store(f as u64, Ordering::Release); }

/// Install a close hook (fires at `File::Drop`). Bool argument is
/// true when the closed File was opened writable. Picks the next
/// free slot in the registry; panics if full so misconfiguration
/// is loud rather than silent.
/// # C: O(N) slot scan; N=4 fixed.
pub fn set_close_hook(f: fn(&InodeRef, bool)) {
    for slot in CLOSE_HOOKS.iter() {
        if slot.compare_exchange(0, f as u64, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            return;
        }
    }
    hal::kassert!(false, "CLOSE_HOOKS table full");
}

/// Clone-hook slot: fires when a Fd-table reference to an existing
/// File is duplicated (fork_clone, dup, dup2). Conceptually mirrors
/// CLOSE_HOOKS — every "open count++" event has a matching "open
/// count--" on close. Without this, fork_clone bumps the Arc<File>
/// refcount but the pipe writer/reader counts stay at 1; closing
/// the original drops the Arc to 1 (File alive), no close hook fires,
/// pipe POLL_HUP never propagates. F205. Bool: writable flag, same
/// convention as the close hook.
static CLONE_HOOK: AtomicU64 = AtomicU64::new(0);
/// # C: O(1)
pub fn set_clone_hook(f: fn(&InodeRef, bool)) {
    CLONE_HOOK.store(f as u64, Ordering::Release);
}
/// Fire the clone hook for a File reference being duplicated. Caller
/// is fork_clone / dup / dup2 right after the Arc::clone — they have
/// already produced the new reference; we just announce it to any
/// subscriber that tracks per-reference state (e.g. pipe writer count).
/// # C: O(1)
pub fn fire_clone_hook(file: &File) {
    let h = CLONE_HOOK.load(Ordering::Acquire);
    if h == 0 { return; }
    let was_writable = {
        let bits = file.flags.load(Ordering::Acquire);
        let f = OpenFlags::from_bits_retain(bits);
        f.contains(OpenFlags::O_WRONLY) || f.contains(OpenFlags::O_RDWR)
    };
    // SAFETY: h was installed by `set_clone_hook` with the documented signature.
    let f: fn(&InodeRef, bool) = unsafe { core::mem::transmute(h) };
    f(&file.inode, was_writable);
}

/// Dirent-mutation hooks per `16§R02`. Fired by devfs / tmpfs path-
/// registry mutations so inotify watches on the parent directory
/// can dispatch IN_CREATE / IN_DELETE / IN_MOVED with the new dirent
/// name. Args: (parent_path, leaf_name).
static DIRENT_CREATE_HOOK: AtomicU64 = AtomicU64::new(0);
static DIRENT_DELETE_HOOK: AtomicU64 = AtomicU64::new(0);

/// # C: O(1)
pub fn set_dirent_create_hook(f: fn(&str, &str)) {
    DIRENT_CREATE_HOOK.store(f as u64, Ordering::Release);
}
/// # C: O(1)
pub fn set_dirent_delete_hook(f: fn(&str, &str)) {
    DIRENT_DELETE_HOOK.store(f as u64, Ordering::Release);
}

/// Fire the dirent-create hook (no-op when not installed).
/// # C: O(1)
pub fn fire_dirent_create(parent: &str, leaf: &str) {
    let h = DIRENT_CREATE_HOOK.load(Ordering::Acquire);
    if h == 0 { return; }
    // SAFETY: h was installed by `set_dirent_create_hook` with the
    // documented signature.
    let f: fn(&str, &str) = unsafe { core::mem::transmute(h) };
    f(parent, leaf);
}

/// Fire the dirent-delete hook (no-op when not installed).
/// # C: O(1)
pub fn fire_dirent_delete(parent: &str, leaf: &str) {
    let h = DIRENT_DELETE_HOOK.load(Ordering::Acquire);
    if h == 0 { return; }
    // SAFETY: h was installed by `set_dirent_delete_hook` with the
    // documented signature.
    let f: fn(&str, &str) = unsafe { core::mem::transmute(h) };
    f(parent, leaf);
}

impl Drop for File {
    fn drop(&mut self) {
        if self.flock_op.load(Ordering::Acquire) != 0 {
            let h = FLOCK_RELEASE_HOOK.load(Ordering::Acquire);
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
        for slot in CLOSE_HOOKS.iter() {
            let h = slot.load(Ordering::Acquire);
            if h == 0 { continue; }
            // SAFETY: slot value installed via set_close_hook with the documented fn(&InodeRef, bool) signature; reinterpret round-trips that exact type.
            let f: fn(&InodeRef, bool) = unsafe { core::mem::transmute(h) };
            f(&self.inode, was_writable);
        }
        // Last-close release per Linux `file_operations->release`: a
        // File == one open file description; dup'd fds share this Arc,
        // so Drop fires on the LAST close (incl. process exit). No lock
        // is held here (only atomics read above); on_release must not
        // block or panic. pty MASTER uses this to hang up the slave.
        self.inode.on_release();
        // D11: release the `d_count` ref taken in `new_at` (Linux `dput` in
        // `__fput`). At zero the dentry is unused — `d_op->d_delete` may evict
        // it (pseudo-fs), otherwise it joins the dcache LRU for the shrinker.
        crate::dcache::dput(self.dentry.clone());
    }
}

impl File {
    /// Anonymous-inode / early-boot constructor: no vfsmount (`mnt_id=0`)
    /// and root credentials. Used by every anon fd (pipe/eventfd/socket/
    /// memfd/timerfd/…) where there is no mount the file was opened
    /// through — exactly Linux's `anon_inode` files.
    /// # C: O(1)
    pub fn new(inode: InodeRef, dentry: Arc<Dentry>, flags: OpenFlags) -> Arc<Self> {
        Self::new_at(inode, dentry, flags, 0, Cred::root())
    }

    /// Full `f_path`-carrying constructor (Linux `struct file` with
    /// `f_path = {mnt, dentry}`): records the `mnt_id` the file was
    /// opened through plus the opener's credentials. The real-FS open
    /// paths (`openat`/`open`/`install_open`) call this with the
    /// resolved `VfsPath.mnt_id`.
    /// # C: O(1)
    pub fn new_at(
        inode: InodeRef,
        dentry: Arc<Dentry>,
        flags: OpenFlags,
        mnt_id: u64,
        cred: Cred,
    ) -> Arc<Self> {
        let h = OPEN_HOOK.load(Ordering::Acquire);
        if h != 0 {
            // SAFETY: h was installed by `set_open_hook` with a real fn(&InodeRef) pointer.
            let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
            f(&inode);
        }
        let mut f_mode = fmode_from_flags(flags);
        // FMODE_LSEEK/PREAD/PWRITE (Linux `do_dentry_open`): a seekable backing
        // (anything but an inherently streaming pipe/socket/fifo) carries a real
        // cursor and positional I/O, so it gets all three capability bits; an
        // O_PATH fd (`empty_fops`) and a streaming file get none. Computed once
        // here so `seek`/`pread`/`pwrite` read the canonical `f_mode` bit rather
        // than re-deriving the file type at every call.
        if !f_mode.contains(Fmode::PATH)
            && !matches!(inode.file_type(), FileType::Fifo | FileType::Socket)
        {
            f_mode |= Fmode::LSEEK | Fmode::PREAD | Fmode::PWRITE;
        }
        // D11 (`16§97` lockref): the open file description pins its dentry with
        // a `d_count` ref (Linux `struct file` holds a `dget`'d `f_path.dentry`).
        // The matching `dput` is in `File::drop`. Until this, `d_count` was
        // permanently 0 in production — no dentry ever entered the LRU.
        let dentry = crate::dcache::dget(&dentry);
        Arc::new(Self {
            inode,
            dentry,
            mnt_id,
            f_mode,
            f_cred: cred,
            private_data: AtomicU64::new(0),
            pos:   AtomicU64::new(0),
            f_pos_lock: Spinlock::new(()),
            flags: AtomicU32::new(flags.bits()),
            flock_op: AtomicU32::new(0),
            owner: core::sync::atomic::AtomicI32::new(0),
            owner_creds: AtomicU64::new(0),
            f_sig: core::sync::atomic::AtomicI32::new(0),
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
    /// absolute pathname and re-walking it on every write (the old
    /// `is_readonly_path(absolute_path())` round-trip, which could also resolve
    /// a DIFFERENT mount than the one the file was opened through if the tree
    /// changed since open). An anon file (`mnt_id == 0`: pipe/socket/eventfd/…)
    /// has no vfsmount and is never mount-RO-blocked; its backend governs
    /// writability directly.
    /// # C: O(log N)
    fn mnt_readonly(&self) -> bool {
        match self.vfsmount() {
            Some(m) => (m.flags() & crate::mount::MNT_RDONLY) != 0 || m.sb().is_readonly(),
            None    => false,
        }
    }

    /// `f_mode` (FMODE_* capability bits). # C: O(1)
    pub fn f_mode(&self) -> Fmode { self.f_mode }

    /// `f_cred` — opener's credential snapshot. # C: O(1)
    pub fn f_cred(&self) -> &Cred { &self.f_cred }

    /// `file->private_data` slot read. # C: O(1)
    pub fn private_data(&self) -> u64 { self.private_data.load(Ordering::Acquire) }

    /// `file->private_data` slot write. # C: O(1)
    pub fn set_private_data(&self, v: u64) { self.private_data.store(v, Ordering::Release); }

    /// `F_SETOWN` (Linux `f_setown`): set the SIGIO/SIGURG delivery target
    /// (`>0` a task, `<0` a `-pgrp`, `0` clears) AND snapshot the requesting
    /// credentials for the later delivery permission check. Stores the bare id
    /// in `owner` (what `F_GETOWN` returns) and the packed uid/euid in
    /// `owner_creds`. # C: O(1)
    pub fn f_setown(&self, id: i32, cred: &Cred) {
        self.owner.store(id, Ordering::Release);
        self.owner_creds.store(((cred.uid as u64) << 32) | cred.uid as u64, Ordering::Release);
    }

    /// `F_GETOWN` (Linux `f_getown`): the delivery target id. # C: O(1)
    pub fn f_getown(&self) -> i32 { self.owner.load(Ordering::Acquire) }

    /// `f_owner` credential snapshot `(uid, euid)` from the last `F_SETOWN`
    /// (Linux `struct fown_struct.uid/.euid`). # C: O(1)
    pub fn f_owner_creds(&self) -> (u32, u32) {
        let v = self.owner_creds.load(Ordering::Acquire);
        ((v >> 32) as u32, v as u32)
    }

    /// `F_SETSIG` (Linux): choose the signal delivered on async-I/O readiness;
    /// `0` restores the default (SIGIO for data, SIGURG for OOB). # C: O(1)
    pub fn set_sig(&self, sig: i32) { self.f_sig.store(sig, Ordering::Release); }

    /// `F_GETSIG` (Linux). # C: O(1)
    pub fn sig(&self) -> i32 { self.f_sig.load(Ordering::Acquire) }

    /// Resolve the signal to actually deliver for an async-I/O event: the
    /// `F_SETSIG` value if set, else `dfl` (the default `SIGIO`/`SIGURG`).
    /// Linux `send_sigio_to_task`: `signum ? signum : SIGIO`. # C: O(1)
    pub fn fasync_signal(&self, dfl: i32) -> i32 {
        let s = self.f_sig.load(Ordering::Acquire);
        if s != 0 { s } else { dfl }
    }

    /// Per-close flush (Linux `file_operations->flush`, fired by
    /// `filp_close` on every `close(2)`/`dup2`-replace/cloexec drop —
    /// NOT only the last). Distinct from `on_release` (last-ref). Default
    /// inode impl is a no-op. # C: depends on inode impl
    pub fn flush(&self) { self.inode.on_flush(); }

    /// FMODE_ATOMIC_POS predicate (Linux `do_dentry_open`: set only for
    /// `S_ISREG`/`S_ISDIR`). Seekable files carry a real cursor whose
    /// pos-read -> I/O -> pos-update must be serialized against a shared
    /// fd; non-seekable files (pipe/socket/fifo) ignore `pos` and their
    /// I/O may park, so they skip the (non-sleeping) pos lock entirely.
    /// # C: O(1)
    fn atomic_pos(&self) -> bool {
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

    /// `read(2)` — advances the cursor by the byte count returned by
    /// the inode's `read`. Rejects writes-only opens with `Ebadf`.
    /// O_NONBLOCK routes through `Inode::read_nonblock`, which the
    /// blocking inodes (pipe/pty/tty/socket) override to return
    /// `EAGAIN` instead of parking.
    /// # C: depends on inode impl
    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let f = self.flags();
        // Gate on the canonical `f_mode` capability (Linux `rw_verify_area` /
        // `FMODE_READ`): O_WRONLY and O_PATH both lack FMODE_READ → EBADF.
        if !self.f_mode.contains(Fmode::READ) {
            return Err(VfsError::Ebadf);
        }
        // FMODE_ATOMIC_POS: hold `f_pos_lock` across pos-read -> I/O ->
        // pos-update so a dup'd / CLONE_FILES-shared fd can't interleave the
        // cursor (Linux `__fdget_pos`). `None` for non-seekable files.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        let pos = self.pos.load(Ordering::Acquire);
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.inode.read_nonblock(pos, buf)?
        } else {
            self.inode.read(pos, buf)?
        };
        self.pos.store(pos + n as u64, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if n > 0 {
            let h = READ_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_read_hook` with a real fn(&InodeRef) pointer.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(n)
    }

    /// `write(2)` — advances the cursor by the byte count returned by
    /// the inode's `write`. Rejects read-only opens with `Ebadf`.
    /// `O_APPEND` snaps the offset to the current size before writing.
    /// # C: depends on inode impl
    pub fn write(&self, buf: &[u8]) -> KResult<usize> {
        let f = self.flags();
        // Gate on the canonical `f_mode` capability (Linux `FMODE_WRITE`):
        // O_RDONLY and O_PATH both lack FMODE_WRITE → EBADF.
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            return Err(VfsError::Erofs);
        }
        // FMODE_ATOMIC_POS: hold `f_pos_lock` across the offset pick (incl.
        // the O_APPEND size read) -> I/O -> pos-update so a shared fd can't
        // interleave the cursor (Linux `__fdget_pos`). `None` for
        // non-seekable files. O_APPEND atomicity vs other writers is the
        // inode lock's job; this serializes only this description's `pos`.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        let off = if f.contains(OpenFlags::O_APPEND) {
            self.inode.size()
        } else {
            self.pos.load(Ordering::Acquire)
        };
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.inode.write_nonblock(off, buf)?
        } else {
            self.inode.write(off, buf)?
        };
        self.pos.store(off + n as u64, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        // inotify IN_MODIFY hook (no-op when nothing installed).
        if n > 0 {
            let h = WRITE_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_write_hook` with a real fn(&InodeRef) pointer; the cast back to that signature is the documented-shape contract.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(n)
    }

    /// `lseek(2)` SEEK_SET / CUR / END. Returns the new position.
    /// A resulting offset < 0 is rejected with `EINVAL`, matching Linux
    /// `vfs_setpos` / `default_llseek`: SEEK_SET with a negative `off`, or
    /// SEEK_CUR/END whose base+`off` is negative. The base+offset is computed
    /// in `i64` so a negative result can be detected before the unsigned store
    /// (the old `off as u64` cast turned a negative offset into a huge value).
    ///
    /// FMODE_LSEEK gate (Linux `vfs_llseek`): a file without FMODE_LSEEK is
    /// `ESPIPE` ("illegal seek") before any offset math. The bit is computed
    /// once at open (`new_at`): an `O_PATH` fd (FMODE_PATH only, `empty_fops`,
    /// no `llseek`) and an inherently non-seekable `pipe`/`socket`/`fifo` lack
    /// it — exactly the files Linux `do_dentry_open` leaves without
    /// FMODE_LSEEK. Regular/dir/char/block keep a real cursor and seek.
    /// # C: O(1)
    pub fn seek(&self, whence: SeekFrom, off: i64) -> KResult<u64> {
        if !self.f_mode.contains(Fmode::LSEEK) {
            return Err(VfsError::Espipe);
        }
        let base = match whence {
            SeekFrom::Start   => 0i64,
            SeekFrom::Current => self.pos.load(Ordering::Acquire) as i64,
            SeekFrom::End     => self.inode.size() as i64,
        };
        let new = base.checked_add(off).ok_or(VfsError::Einval)?;
        if new < 0 { return Err(VfsError::Einval); }
        let new_pos = new as u64;
        self.pos.store(new_pos, Ordering::Release);
        Ok(new_pos)
    }

    /// `pread(2)` / `pread64` — positional read at the explicit `off` that
    /// does NOT touch `f_pos` (Linux `ksys_pread64` → `vfs_read(file, buf,
    /// count, &pos)` over a LOCAL `pos`, bypassing `__fdget_pos`). Because no
    /// shared cursor is consulted or mutated, `f_pos_lock` is NOT taken —
    /// concurrent `pread`s on a dup'd / CLONE_FILES-shared fd are independent.
    /// Gate order mirrors Linux: a negative `off` is `EINVAL` before `fdget`;
    /// a file lacking FMODE_PREAD (a non-seekable pipe/socket/fifo, or an
    /// `O_PATH` fd with `empty_fops`) is `ESPIPE`; only then does the read
    /// capability (`FMODE_READ`) gate apply (`EBADF` for an `O_WRONLY` open).
    /// O_NONBLOCK routes through `read_nonblock` exactly as `read` does.
    /// # C: depends on inode impl
    pub fn pread(&self, buf: &mut [u8], off: i64) -> KResult<usize> {
        if off < 0 { return Err(VfsError::Einval); }
        // FMODE_PREAD gate (Linux `do_dentry_open`): only seekable files carry
        // it; pipe/socket/fifo and O_PATH fds do not → ESPIPE. The bit is set
        // once at open, so no per-call file-type re-derivation.
        if !self.f_mode.contains(Fmode::PREAD) {
            return Err(VfsError::Espipe);
        }
        if !self.f_mode.contains(Fmode::READ) {
            return Err(VfsError::Ebadf);
        }
        let f = self.flags();
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.inode.read_nonblock(off as u64, buf)?
        } else {
            self.inode.read(off as u64, buf)?
        };
        if n > 0 {
            let h = READ_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_read_hook` with a real fn(&InodeRef) pointer.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(n)
    }

    /// `pwrite(2)` / `pwrite64` — positional write at the explicit `off` that
    /// does NOT touch `f_pos` (Linux `ksys_pwrite64` → `vfs_write` over a
    /// LOCAL `pos`, bypassing `__fdget_pos`), so `f_pos_lock` is NOT taken.
    /// Gate order mirrors Linux: negative `off` → `EINVAL`; a file lacking
    /// FMODE_PWRITE (pipe/socket/fifo or `O_PATH`) → `ESPIPE`; an unwritable
    /// open (`O_RDONLY`) → `EBADF`; a read-only mount → `EROFS`. The
    /// documented Linux O_APPEND quirk is preserved: with `O_APPEND` the
    /// effective offset is forced to the current size and `off` is IGNORED
    /// (`generic_write_checks` `IOCB_APPEND` overrides `ki_pos`) — see
    /// `pwrite(2)` BUGS. O_NONBLOCK routes through `write_nonblock`.
    /// # C: depends on inode impl
    pub fn pwrite(&self, buf: &[u8], off: i64) -> KResult<usize> {
        if off < 0 { return Err(VfsError::Einval); }
        // FMODE_PWRITE gate (Linux `do_dentry_open`): set once at open for
        // seekable files only; pipe/socket/fifo and O_PATH lack it → ESPIPE.
        if !self.f_mode.contains(Fmode::PWRITE) {
            return Err(VfsError::Espipe);
        }
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            return Err(VfsError::Erofs);
        }
        let f = self.flags();
        // Linux pwrite + O_APPEND: IOCB_APPEND forces ki_pos = i_size,
        // ignoring the caller's offset (documented quirk, pwrite(2) BUGS).
        let pos = if f.contains(OpenFlags::O_APPEND) { self.inode.size() } else { off as u64 };
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.inode.write_nonblock(pos, buf)?
        } else {
            self.inode.write(pos, buf)?
        };
        if n > 0 {
            let h = WRITE_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_write_hook` with a real fn(&InodeRef) pointer.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(n)
    }

    /// `readv(2)` core (Linux `vfs_readv` -> `do_iter_read`): aggregate a slice
    /// of destination buffers into ONE cursor-advancing read against the file,
    /// holding `f_pos_lock` for the WHOLE walk so a dup'd / CLONE_FILES-shared
    /// fd cannot interleave the cursor between buffers, and advancing `f_pos`
    /// ONCE by the grand total — matching Linux taking `f_pos_lock` once in
    /// `__fdget_pos` and writing `file->f_pos` back a single time. The buffers
    /// form one logical region: buffer `i` is filled at the running offset
    /// `pos + total`. A short fill (inode `read` returns fewer bytes than the
    /// buffer length, `0` = EOF) terminates the walk per `iov_iter` semantics.
    /// An inode error propagates only when NO bytes have been read yet; once
    /// progress is made the partial count is returned (Linux generic-read
    /// `written ? written : error`). Empty buffers are skipped. O_NONBLOCK
    /// routes through `read_nonblock`, exactly as scalar `read`.
    /// # C: O(sum of buf lens)
    pub fn read_iter(&self, bufs: &mut [&mut [u8]]) -> KResult<usize> {
        if !self.f_mode.contains(Fmode::READ) {
            return Err(VfsError::Ebadf);
        }
        let f = self.flags();
        let nonblock = f.contains(OpenFlags::O_NONBLOCK);
        // FMODE_ATOMIC_POS: one lock across the whole vectored op (Linux
        // `__fdget_pos`), so the cursor advances atomically over all buffers.
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        let pos = self.pos.load(Ordering::Acquire);
        let mut total: u64 = 0;
        for buf in bufs.iter_mut() {
            if buf.is_empty() { continue; }
            let want = buf.len();
            let off = pos + total;
            let r = if nonblock { self.inode.read_nonblock(off, buf) } else { self.inode.read(off, buf) };
            match r {
                Ok(0)                => break,                   // EOF
                Ok(n)                => { total += n as u64; if n < want { break; } }
                Err(e) if total == 0 => return Err(e),
                Err(_)               => break,                   // partial progress: keep it
            }
        }
        self.pos.store(pos + total, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if total > 0 {
            let h = READ_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_read_hook` with a real fn(&InodeRef) pointer.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(total as usize)
    }

    /// `writev(2)` core (Linux `vfs_writev` -> `do_iter_write`): aggregate a
    /// slice of source buffers into ONE cursor-advancing write, holding
    /// `f_pos_lock` for the whole walk and advancing `f_pos` ONCE by the total
    /// (Linux `__fdget_pos`). With `O_APPEND` the base offset is forced to the
    /// current size ONCE (Linux `IOCB_APPEND` overriding `ki_pos` for the whole
    /// iocb), then buffers are written sequentially at `base + total`; the
    /// inter-writer append atomicity is the inode lock's job — this serializes
    /// only this description's cursor. A short write terminates the walk per
    /// `iov_iter` semantics. An inode error propagates only when NO bytes have
    /// been written yet; otherwise the partial count is returned. Empty buffers
    /// are skipped. O_NONBLOCK routes through `write_nonblock`.
    /// # C: O(sum of buf lens)
    pub fn write_iter(&self, bufs: &[&[u8]]) -> KResult<usize> {
        if !self.f_mode.contains(Fmode::WRITE) {
            return Err(VfsError::Ebadf);
        }
        if self.mnt_readonly() {
            return Err(VfsError::Erofs);
        }
        let f = self.flags();
        let nonblock = f.contains(OpenFlags::O_NONBLOCK);
        let pos_guard = if self.atomic_pos() { Some(self.f_pos_lock.lock()) } else { None };
        // O_APPEND forces the base to i_size ONCE for the whole vectored write.
        let base = if f.contains(OpenFlags::O_APPEND) { self.inode.size() } else { self.pos.load(Ordering::Acquire) };
        let mut total: u64 = 0;
        for buf in bufs.iter() {
            if buf.is_empty() { continue; }
            let want = buf.len();
            let off = base + total;
            let r = if nonblock { self.inode.write_nonblock(off, buf) } else { self.inode.write(off, buf) };
            match r {
                Ok(0)                => break,
                Ok(n)                => { total += n as u64; if n < want { break; } }
                Err(e) if total == 0 => return Err(e),
                Err(_)               => break,
            }
        }
        self.pos.store(base + total, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if total > 0 {
            let h = WRITE_HOOK.load(Ordering::Acquire);
            if h != 0 {
                // SAFETY: h was installed by `set_write_hook` with a real fn(&InodeRef) pointer.
                let f: fn(&InodeRef) = unsafe { core::mem::transmute(h) };
                f(&self.inode);
            }
        }
        Ok(total as usize)
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

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("File")
            .field("ino", &self.inode.ino())
            .field("pos", &self.pos())
            .field("flags", &self.flags())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SeekFrom {
    Start,
    Current,
    End,
}


/// Create a `File` from an inode + path, install into the supplied
/// `FdTable`. Per `docs/53§3` work fn. Handles the common
/// post-lookup sequence: O_DIRECTORY check, O_TRUNC, Dentry wrap,
/// File construction, fd allocation.
/// # C: O(1) + fd_table alloc
pub fn install_open(
    fdt: &crate::fdtable::FdTable,
    inode: InodeRef,
    path: &str,
    flags: OpenFlags,
    mnt_id: u64,
    cred: Cred,
) -> Result<i32, VfsError> {
    if flags.contains(OpenFlags::O_DIRECTORY)
        && !matches!(inode.file_type(), crate::types::FileType::Directory)
    {
        return Err(VfsError::Enotdir);
    }
    inode.on_open()?;
    if flags.contains(OpenFlags::O_TRUNC) {
        if crate::mount::is_readonly_path(path) {
            return Err(VfsError::Erofs);
        }
        let _ = inode.truncate(0);
    }
    let cloexec = flags.contains(OpenFlags::O_CLOEXEC);
    let file_flags = flags - OpenFlags::O_CLOEXEC;
    let dentry = open_dentry(path, &inode);
    let file = File::new_at(inode, dentry, file_flags, mnt_id, cred);
    let fd = fdt.alloc(file).map_err(|_| VfsError::Emfile)?;
    if cloexec {
        fdt.set_cloexec(fd, true)?;
    }
    Ok(fd)
}

/// Build the `Dentry` for an opened file as a properly-PARENTED node (Linux
/// `f->f_path.dentry`): resolve the parent directory's dentry via the
/// per-component walk and hang the basename child off it, carrying the
/// opened inode. `Dentry::absolute_path` then reconstructs the pathname by
/// walking the parent chain — there is no whole-path-in-one-dentry shape.
/// Falls back to a basename-only dentry only when the root dentry isn't
/// built yet (very early boot) or the parent doesn't resolve.
/// # C: O(path components)
pub fn open_dentry(path: &str, inode: &InodeRef) -> alloc::sync::Arc<crate::dentry::Dentry> {
    use alloc::sync::Arc;
    use alloc::string::String;
    use crate::dentry::Dentry;
    // Root itself: reuse the canonical root dentry when available.
    if path == "/" {
        if let Some(r) = crate::namei::resolve_path_dentry("/") { return r; }
        return Dentry::new(None, String::new(), Arc::clone(inode));
    }
    let trimmed = path.trim_end_matches('/');
    let (parent, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None    => ("", trimmed),
    };
    if let Some(pd) = crate::namei::resolve_path_dentry(parent) {
        // D3: hand the fd the CANONICAL hashed dentry the walk produced, not a
        // fresh unhashed Arc. `d_lookup` returns the object already in the
        // global table (so a wired `d_move`/`d_drop` reaches the fd's dentry);
        // a miss `d_add`s the canonical positive.
        return match crate::dcache::d_lookup(&pd, name) {
            // Defensive: if a negative dentry is ever cached for this name
            // (e.g. once D5/D6 negative-caching lands), splice the real inode
            // onto it (Linux `d_splice_alias` / `d_instantiate`) → positive
            // rather than handing the fd a negative dentry.
            Some(d) if d.is_negative() => crate::dcache::d_splice_alias(Arc::clone(inode), &d),
            Some(d) => d,
            None    => crate::dcache::d_add(&pd, name, Arc::clone(inode)),
        };
    }
    Dentry::new(None, String::from(name), Arc::clone(inode))
}
