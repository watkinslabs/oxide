// `File` per `16§5`. The kernel-side handle that an FD entry points
// to: cached inode / dentry, current position, open flags. Per-process
// FD table lives in `fdtable.rs`.

extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::Spinlock;

use crate::dentry::Dentry;
use crate::file_ops::FileOps;
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
        /// FMODE_OPENED — `do_dentry_open` reached the point past `f_op->open`
        /// (the description is fully opened). Linux `(1 << 19)`.
        const OPENED  = 0x0008_0000;
        /// FMODE_CREATED — this open CREATED the file (`O_CREAT` hit the
        /// negative-dentry path), distinguishing create-vs-existing for events
        /// / audit after the open returns. Linux `(1 << 20)`.
        const CREATED = 0x0010_0000;
        /// FMODE_NONOTIFY — suppress fsnotify events on this description
        /// (fanotify's own fds avoid self-notification loops). Linux `(1 << 26)`.
        const NONOTIFY = 0x0400_0000;
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

/// `O_ASYNC`/`FASYNC` (asm-generic, both arches — Linux `fcntl.h` `0o20000`).
/// Settable via `F_SETFL`; toggling it (de)registers the open file description
/// for fasync SIGIO/SIGURG delivery to its `f_owner` (Linux `setfl`'s
/// `FASYNC` branch calling `f_op->fasync`). Not declared in `OpenFlags` (no
/// other in-`vfs` consumer), so matched here by raw value, and the stored bit
/// is read by `File::is_async`.
const O_ASYNC: u32 = 0o20000;

/// Linux `SETFL_MASK` (`fs/fcntl.c`): the only `f_flags` bits `fcntl(F_SETFL)`
/// may change on an already-open file description. The access mode
/// (`O_RDONLY`/`O_WRONLY`/`O_RDWR`) and the creation-time flags
/// (`O_CREAT`/`O_EXCL`/`O_TRUNC`/`O_CLOEXEC`/`O_DIRECTORY`/…) are fixed at open
/// and silently ignored by `F_SETFL`, so they are excluded here.
const SETFL_MASK: u32 =
    OpenFlags::O_APPEND.bits() | OpenFlags::O_NONBLOCK.bits() | O_DIRECT | O_NOATIME | O_ASYNC;

/// Default readahead window (Linux `VM_READAHEAD_PAGES`, 128 KiB = 32 pages at
/// 4 KiB) — the per-open `f_ra.ra_pages` ceiling.
const DEFAULT_RA_PAGES: u32 = 32;

/// Page size used to convert a byte offset/length into the PAGE-unit index +
/// request count [`File::ra_ondemand`] works in (Linux readahead is page-
/// granular). 4 KiB on both arches' base page. # C: O(1)
const PAGE_SIZE: u64 = 4096;

/// Lock class for `File::f_ra` (never nested with the inode lock). # C: O(1)
struct FileRa;
impl sync::LockClass for FileRa { fn rank() -> u16 { 36 } }

/// `struct file_ra_state` (Linux): per-open sequential readahead window —
/// `start`/`size` in PAGE units, `async_size` the async-trigger margin,
/// `ra_pages` the ceiling. State + Linux window arithmetic; the page-cache fill
/// is the block lane, the mmap `prev_pos`/`mmap_miss` heuristics the mmap lane.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FileRaState { pub start: u64, pub size: u32, pub async_size: u32, pub ra_pages: u32 }

impl FileRaState {
    /// Initial window for a `req`-page read, ≤ `max` (Linux `get_init_ra_size`:
    /// roundup pow2 → 4x small / 2x medium / clamp). # C: O(1)
    pub fn init_ra_size(req: u32, max: u32) -> u32 {
        let mut n = req.max(1).next_power_of_two();
        if n <= max / 32 { n = n.saturating_mul(4); } else if n <= max / 4 { n = n.saturating_mul(2); } else { n = max; }
        n.clamp(1, max.max(1))
    }
    /// Grown window from the current, ≤ `max` (Linux `get_next_ra_size`). # C: O(1)
    pub fn next_ra_size(&self, max: u32) -> u32 {
        let cur = self.size.max(1);
        let n = if cur < max / 16 { cur.saturating_mul(4) } else if cur <= max / 2 { cur.saturating_mul(2) } else { max };
        n.clamp(1, max.max(1))
    }
}

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
    /// `file->f_op` (Linux `struct file.f_op`) — the `file_operations` vtable
    /// SNAPSHOTTED from `inode->i_fop` at open. The data path
    /// (read/write/read_iter/…) dispatches through this cached `Arc` rather than
    /// re-reading `inode.i_fop()` each call, matching Linux's per-`struct file`
    /// `f_op` (a device open may even install a different `f_op` than the
    /// inode's; the snapshot is the open-time binding). # C: O(1)
    f_op: Arc<dyn FileOps>,
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
    /// `f_ra` readahead window (Linux `struct file.f_ra`). Spinlock-guarded so
    /// the on-demand advance is atomic against a dup'd / shared description.
    f_ra: Spinlock<FileRaState, FileRa>,
    flags:  AtomicU32,
    /// Currently-held flock kind: 0=none, 1=LOCK_SH, 2=LOCK_EX. Used
    /// by the kernel-side flock registry to find which lock to drop
    /// when the last reference to this open-file-description goes
    /// away (Drop impl below).
    pub flock_op: AtomicU32,
    /// F_GETOWN/F_SETOWN target: positive = tid, negative = -pgid, 0 = none
    /// (Linux `f_owner.pid`). SIGIO/SIGURG routes here on fasync; the credential
    /// snapshot lives in `owner_creds`, the delivery signal in `f_sig`.
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
    /// `F_SETLEASE`/`F_GETLEASE` lease type held on this open file description
    /// (Linux `fl->fl_type` of the `FL_LEASE` lock): `F_RDLCK`(0) read lease,
    /// `F_WRLCK`(1) write lease, `F_UNLCK`(2) = no lease. Default `F_UNLCK`.
    /// Storage + validation only; the lease-break delivery (a conflicting
    /// open signalling the lease holder) is the lease-manager follow-up.
    lease: core::sync::atomic::AtomicI32,
    /// `F_NOTIFY` (dnotify) directory-change watch mask (Linux `dnotify_struct
    /// .dn_mask`): the `DN_*` events this directory fd wants `F_SETSIG`/`SIGIO`
    /// for. `0` = no watch. `F_NOTIFY` is additive unless the caller passes a
    /// zero arg (clear). Storage + validation only; the event delivery rides
    /// the dnotify follow-up (needs dir-mutation hooks, cross-lane).
    dnotify_mask: AtomicU32,
    /// `file->f_version` (Linux): inode change-version this open last observed;
    /// directory readers compare it vs `inode->i_version` to drop a stale cursor.
    f_version: AtomicU64,
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
    /// IN_CREATE — dirent created in a watched parent. Args: (parent, leaf).
    dirent_create: Option<fn(&str, &str)>,
    /// IN_DELETE — dirent removed from a watched parent. Args: (parent, leaf).
    dirent_delete: Option<fn(&str, &str)>,
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
impl sync::LockClass for HookReg { fn rank() -> u16 { 33 } }

static HOOKS: Spinlock<InodeHooks, HookReg> = Spinlock::new(InodeHooks::new());

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

/// Install the dirent-create hook (fires IN_CREATE; args (parent, leaf)).
/// Fired by devfs / tmpfs path-registry mutations so inotify watches on the
/// parent directory can dispatch IN_CREATE. # C: O(1)
pub fn set_dirent_create_hook(f: fn(&str, &str)) { HOOKS.lock().dirent_create = Some(f); }
/// Install the dirent-delete hook (fires IN_DELETE; args (parent, leaf)). # C: O(1)
pub fn set_dirent_delete_hook(f: fn(&str, &str)) { HOOKS.lock().dirent_delete = Some(f); }

/// Fire the dirent-create hook (no-op when not installed). # C: O(1)
pub fn fire_dirent_create(parent: &str, leaf: &str) {
    let h = HOOKS.lock().dirent_create;
    if let Some(f) = h { f(parent, leaf); }
}

/// Fire the dirent-delete hook (no-op when not installed). # C: O(1)
pub fn fire_dirent_delete(parent: &str, leaf: &str) {
    let h = HOOKS.lock().dirent_delete;
    if let Some(f) = h { f(parent, leaf); }
}

/// Fire the IN_OPEN hook (no-op when not installed). # C: O(1)
fn fire_open_hook(inode: &InodeRef) {
    let h = HOOKS.lock().open;
    if let Some(f) = h { f(inode); }
}

/// Fire the IN_ACCESS hook (no-op when not installed). # C: O(1)
fn fire_read_hook(inode: &InodeRef) {
    let h = HOOKS.lock().read;
    if let Some(f) = h { f(inode); }
}

/// Fire the IN_MODIFY hook (no-op when not installed). # C: O(1)
fn fire_write_hook(inode: &InodeRef) {
    let h = HOOKS.lock().write;
    if let Some(f) = h { f(inode); }
}

/// SIGIO delivery hook (Linux `send_sigio`/`kill_pid_info`): installed at boot
/// by the sched signal module so the VFS fasync path can post a signal to a
/// pid/pgrp without `vfs` depending on `sched`. Args: `(owner, sig, uid,
/// euid)` — `owner` is the `F_SETOWN` target (`>0` task, `<0` `-pgrp`), `sig`
/// the resolved signal (`F_SETSIG` value or default SIGIO/SIGURG), `uid`/`euid`
/// the `F_SETOWN`-time credential snapshot for the delivery permission check.
/// `0` = not installed (host tests, early boot). # C: O(1)
static SIGIO_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the SIGIO delivery hook used by fasync (`O_ASYNC`). Called once at
/// kernel init by the sched signal module. # C: O(1)
pub fn set_sigio_hook(f: fn(i32, i32, u32, u32)) {
    SIGIO_HOOK.store(f as u64, Ordering::Release);
}

/// Lock class for the global fasync registry. Taken standalone (the held set
/// is snapshotted then released before any delivery hook runs), so it never
/// nests under the inode / pos / ra locks. # C: O(1)
struct FasyncLock;
impl sync::LockClass for FasyncLock { fn rank() -> u16 { 34 } }

/// `inode->i_fasync` analogue (Linux per-object `fasync_struct` list): the set
/// of open file descriptions with `O_ASYNC` enabled, awaiting SIGIO on an
/// async-ready event. Held as `Weak<File>` so a closed description drops out
/// without an explicit unregister; dead entries are pruned on every touch.
/// # C: O(N) registered fds
static FASYNC: Spinlock<Vec<Weak<File>>, FasyncLock> = Spinlock::new(Vec::new());

/// Register an open file description for fasync SIGIO delivery (Linux
/// `fasync_helper(.., on=1)` linking a `fasync_struct` onto the backend list).
/// Idempotent; prunes dead weak entries. Called when `O_ASYNC` is turned on via
/// `F_SETFL`. # C: O(N) registered fds
pub fn fasync_register(file: &Arc<File>) {
    let mut l = FASYNC.lock();
    let p = Arc::as_ptr(file);
    l.retain(|w| w.upgrade().is_some());
    if !l.iter().any(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) == p)) {
        l.push(Arc::downgrade(file));
    }
}

/// Unregister an open file description from fasync delivery (Linux
/// `fasync_helper(.., on=0)`). Also prunes dead entries. Called when `O_ASYNC`
/// is turned off via `F_SETFL` and from `File::drop`. # C: O(N) registered fds
pub fn fasync_unregister(file: &File) {
    let mut l = FASYNC.lock();
    let p = file as *const File;
    l.retain(|w| w.upgrade().is_some_and(|f| Arc::as_ptr(&f) != p));
}

/// Count of live fasync-registered descriptions (prunes dead entries).
/// Test/observability accessor. # C: O(N) registered fds
pub fn fasync_registered() -> usize {
    let mut l = FASYNC.lock();
    l.retain(|w| w.upgrade().is_some());
    l.len()
}

/// `kill_fasync(&inode->i_fasync, sig, band)` (Linux `fs/fcntl.c`): deliver the
/// async-ready signal to every `O_ASYNC` fd open on `inode`. A backend
/// (pipe/socket/tty) calls this when its buffer becomes readable/writable or an
/// OOB byte arrives. `dfl` is the default signal — `SIGIO` for data-ready,
/// `SIGURG` for out-of-band — overridden per-fd by `F_SETSIG`. Snapshots the
/// matching set under the registry lock, then delivers with the lock dropped so
/// the signal hook may take sched locks. # C: O(N) registered fds
pub fn kill_fasync(inode: &InodeRef, dfl: i32) {
    let snapshot: Vec<Arc<File>> = {
        let mut l = FASYNC.lock();
        l.retain(|w| w.upgrade().is_some());
        l.iter()
            .filter_map(|w| w.upgrade())
            .filter(|f| Arc::ptr_eq(&f.inode, inode))
            .collect()
    };
    for f in snapshot { f.kill_fasync(dfl); }
}

impl Drop for File {
    fn drop(&mut self) {
        // Drop the fasync registration weak (Linux `__fput` -> `f_op->fasync(.,
        // 0)` for an `O_ASYNC` file). Weaks self-expire, but prune eagerly.
        if (self.flags.load(Ordering::Acquire) & O_ASYNC) != 0 {
            fasync_unregister(self);
        }
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
        // Copy the close-hook slots out under the registry lock, release it,
        // then fire each — no foreign hook runs while the lock is held.
        let close = HOOKS.lock().close;
        for slot in close.iter() {
            if let Some(f) = slot { f(&self.inode, was_writable); }
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
        // D2: snapshot `inode->i_fop` into `file->f_op` so the data path
        // dispatches through the per-open cached vtable (Linux do_dentry_open:
        // `f->f_op = fops_get(inode->i_fop)`).
        let f_op = inode.i_fop().clone();
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
            owner: core::sync::atomic::AtomicI32::new(0),
            owner_creds: AtomicU64::new(0),
            f_sig: core::sync::atomic::AtomicI32::new(0),
            // F_UNLCK (2) = no lease held (Linux `F_GETLEASE` default).
            lease: core::sync::atomic::AtomicI32::new(2),
            dnotify_mask: AtomicU32::new(0),
            f_version: AtomicU64::new(0),
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

    /// `O_ASYNC` enabled on this description (Linux `FASYNC` in `f_flags`).
    /// # C: O(1)
    pub fn is_async(&self) -> bool {
        (self.flags.load(Ordering::Acquire) & O_ASYNC) != 0
    }

    /// `kill_fasync` per-fd core (Linux `kill_fasync_rcu` -> `send_sigio`):
    /// deliver the async-ready signal to THIS description's `f_owner` via the
    /// installed SIGIO hook. `dfl` = default signal (SIGIO data / SIGURG OOB),
    /// overridden by `F_SETSIG`. No-op unless `O_ASYNC` is set, an owner is
    /// recorded, and a hook is installed. The owner credentials snapshot is
    /// forwarded for the hook's delivery permission check. # C: O(1)
    pub fn kill_fasync(&self, dfl: i32) {
        if !self.is_async() { return; }
        let owner = self.owner.load(Ordering::Acquire);
        if owner == 0 { return; }
        let h = SIGIO_HOOK.load(Ordering::Acquire);
        if h == 0 { return; }
        let sig = self.fasync_signal(dfl);
        let (uid, euid) = self.f_owner_creds();
        // SAFETY: h installed by `set_sigio_hook` with the documented
        // fn(i32,i32,u32,u32) signature; the cast round-trips that exact type.
        let f: fn(i32, i32, u32, u32) = unsafe { core::mem::transmute(h) };
        f(owner, sig, uid, euid);
    }

    /// `F_SETLEASE` (Linux `do_fcntl_add_lease`): record the lease type held on
    /// this description — `F_RDLCK`(0) / `F_WRLCK`(1) read/write lease, or
    /// `F_UNLCK`(2) to drop it. Storage only; the conflicting-open break path is
    /// the lease-manager follow-up. # C: O(1)
    pub fn set_lease(&self, ty: i32) { self.lease.store(ty, Ordering::Release); }

    /// `F_GETLEASE` (Linux `fcntl_getlease`): the lease type held — `F_RDLCK`/
    /// `F_WRLCK`, or `F_UNLCK` when none. # C: O(1)
    pub fn lease(&self) -> i32 { self.lease.load(Ordering::Acquire) }

    /// `F_NOTIFY` (Linux `fcntl_dirnotify`): set the dnotify `DN_*` watch mask
    /// on this directory fd (`0` clears). Storage only; the dir-mutation event
    /// delivery is the dnotify follow-up. # C: O(1)
    pub fn set_dnotify(&self, mask: u32) { self.dnotify_mask.store(mask, Ordering::Release); }

    /// The dnotify `DN_*` watch mask on this fd (`0` = no watch). # C: O(1)
    pub fn dnotify(&self) -> u32 { self.dnotify_mask.load(Ordering::Acquire) }

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
        // D31: advance the per-open readahead window on the buffered read path
        // (Linux `page_cache_sync_readahead`). Regular files only; the window
        // state drives the block lane's page-cache fill. Pure state update — the
        // byte count returned is still bounded by `buf`, so there is no
        // over-read past EOF.
        if !f.contains(OpenFlags::O_NONBLOCK) && matches!(self.inode.file_type(), FileType::Regular) {
            let index = pos / PAGE_SIZE;
            let req = (((buf.len() as u64) + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as u32;
            let _ = self.ra_ondemand(index, req, false);
        }
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.read_nonblock(&self.inode, pos, buf)?
        } else {
            self.f_op.read(&self.inode, pos, buf)?
        };
        self.pos.store(pos + n as u64, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        if n > 0 {
            fire_read_hook(&self.inode);
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
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.write_nonblock(&self.inode, off, buf)?
        } else {
            self.f_op.write(&self.inode, off, buf)?
        };
        self.pos.store(off + n as u64, Ordering::Release);
        drop(pos_guard); // release before the (possibly lock-taking) inotify hook
        // inotify IN_MODIFY hook (no-op when nothing installed).
        if n > 0 {
            fire_write_hook(&self.inode);
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
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.read_nonblock(&self.inode, off as u64, buf)?
        } else {
            self.f_op.read(&self.inode, off as u64, buf)?
        };
        if n > 0 {
            fire_read_hook(&self.inode);
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
        // D2: dispatch through the cached `file->f_op` (snapshotted at open).
        let n = if f.contains(OpenFlags::O_NONBLOCK) {
            self.f_op.write_nonblock(&self.inode, pos, buf)?
        } else {
            self.f_op.write(&self.inode, pos, buf)?
        };
        if n > 0 {
            fire_write_hook(&self.inode);
        }
        Ok(n)
    }

    /// `readv(2)` core (Linux `vfs_readv` -> `do_iter_read`): aggregate the
    /// destination buffers into ONE cursor-advancing read, holding `f_pos_lock`
    /// for the WHOLE walk so a dup'd / shared fd cannot interleave the cursor,
    /// and advancing `f_pos` ONCE by the grand total (Linux `__fdget_pos`).
    /// Buffer `i` fills at the running offset `pos + total`; a short fill (`0` =
    /// EOF) ends the walk per `iov_iter`. An inode error propagates only when NO
    /// bytes were read yet, else the partial count is returned. Empty buffers
    /// skipped; O_NONBLOCK routes through `read_nonblock`. # C: O(sum of buf lens)
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
        // D31: advance the readahead window once for the whole vectored read
        // (Linux `page_cache_sync_readahead`). Regular files only; the request
        // size is the grand total of the destination buffers. Pure state update.
        if !nonblock && matches!(self.inode.file_type(), FileType::Regular) {
            let bytes: u64 = bufs.iter().map(|b| b.len() as u64).sum();
            let index = pos / PAGE_SIZE;
            let req = ((bytes + PAGE_SIZE - 1) / PAGE_SIZE).max(1) as u32;
            let _ = self.ra_ondemand(index, req, false);
        }
        let mut total: u64 = 0;
        for buf in bufs.iter_mut() {
            if buf.is_empty() { continue; }
            let want = buf.len();
            let off = pos + total;
            // D2: dispatch through the cached `file->f_op` (snapshotted at open).
            let r = if nonblock { self.f_op.read_nonblock(&self.inode, off, buf) } else { self.f_op.read(&self.inode, off, buf) };
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
            fire_read_hook(&self.inode);
        }
        Ok(total as usize)
    }

    /// `writev(2)` core (Linux `vfs_writev` -> `do_iter_write`): aggregate the
    /// source buffers into ONE cursor-advancing write, holding `f_pos_lock` for
    /// the whole walk and advancing `f_pos` ONCE by the total (Linux
    /// `__fdget_pos`). `O_APPEND` forces the base to i_size ONCE (Linux
    /// `IOCB_APPEND` for the whole iocb); inter-writer append atomicity is the
    /// inode lock's job. A short write ends the walk per `iov_iter`; an inode
    /// error propagates only with no prior progress, else the partial count.
    /// Empty buffers skipped; O_NONBLOCK → `write_nonblock`. # C: O(sum of buf lens)
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
            // D2: dispatch through the cached `file->f_op` (snapshotted at open).
            let r = if nonblock { self.f_op.write_nonblock(&self.inode, off, buf) } else { self.f_op.write(&self.inode, off, buf) };
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
            fire_write_hook(&self.inode);
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
