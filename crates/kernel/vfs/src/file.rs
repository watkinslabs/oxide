// `File` per `16§5`. The kernel-side handle that an FD entry points
// to: cached inode / dentry, current position, open flags. Per-process
// FD table lives in `fdtable.rs`.
//
// Module manifest:
// - `mode`: Linux FMODE bits, mutable F_SETFL mask, seek selectors.
// - `readahead`: `file_ra_state` and per-open readahead sizing.
// - `hooks`: fsnotify/inotify close/open/read/write and clone hook registry.
// - `lock_wait`: typed scheduler hooks for blocking POSIX/BSD file locks.
// - `async_notify`: fasync/SIGIO owner delivery registry.
// - `lease`: Linux lease and dnotify registries plus per-file lease methods.
// - `model`: constructors, path/accessors, flags, version, readahead methods.
// - `io`: read/write/seek/pread/pwrite/readv/writev data paths.
// - `lifetime`: `Drop`, `get_file`, `fput`, `iput`, and `Debug`.
// - `epoll`: weak eventpoll backlinks released from final `File::drop`.
// - `open`: post-lookup open/install helpers.

extern crate alloc;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

use sync::{Spinlock, TaskList as FileLinkClass};

use crate::dentry::Dentry;
use crate::file_ops::FileOps;
use crate::inode::InodeRef;

mod async_notify;
mod cred;
mod epoll;
mod hooks;
mod io;
mod lease;
mod lock_wait;
mod lifetime;
mod model;
mod mode;
mod open;
mod readahead;

pub use async_notify::{fasync_register, fasync_registered, fasync_unregister, kill_fasync, set_sigio_hook};
pub use cred::FileCred;
pub use epoll::FileEpollLink;
pub use hooks::{fire_clone_hook, fire_dirent_create, fire_dirent_delete, set_clone_hook, set_close_hook, set_dirent_create_hook, set_dirent_delete_hook, set_drop_hook, set_open_hook, set_read_hook, set_write_hook};
pub use lease::{dnotify_emit, dnotify_register, dnotify_registered, dnotify_unregister, lease_break_signal, lease_conflict, lease_force_break, lease_register, lease_registered, lease_unregister, DN_ACCESS, DN_ATTRIB, DN_CREATE, DN_DELETE, DN_MODIFY, DN_RENAME, LEASE_BREAK_NS};
pub use lock_wait::{clear_file_lock_wait_hooks, file_lock_interrupted, file_lock_park, file_lock_schedule, file_lock_wake, set_file_lock_wait_hooks};
pub use lifetime::{fput, get_file, iput};
pub use mode::{Fmode, SeekFrom};
pub use open::{install_open_at, open_dentry_at};
pub use readahead::FileRaState;

pub(super) use async_notify::SIGIO_HOOK;
pub(super) use hooks::{fire_open_hook, fire_read_hook, fire_write_hook};
pub(super) use lease::F_UNLCK;
pub(super) use mode::{fmode_from_flags, FilePos, O_ASYNC, SETFL_MASK};
pub(super) use readahead::{FileRa, DEFAULT_RA_PAGES, PAGE_SIZE};

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
    f_cred: FileCred,
    /// `file->private_data` — per-fd driver/anon-inode state slot.
    /// Default 0; opaque to the VFS core.
    private_data: AtomicU64,
    /// Device dispatcher proof that this file reached a successful driver
    /// `->open`; final device `->release` consumes it exactly once.
    device_opened: AtomicBool,
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
    pub owner: ::core::sync::atomic::AtomicI32,
    /// `f_owner` credential snapshot (Linux `struct fown_struct.uid/.euid`)
    /// captured at `F_SETOWN`, so a deferred SIGIO permission-checks against
    /// the credentials that requested ownership, not those current when the
    /// signal fires. Packed `uid << 32 | euid`. The `Cred` subset carries one
    /// id, so uid==euid here until a separate euid lands.
    owner_creds: AtomicU64,
    /// `F_SETSIG`/`F_GETSIG` (Linux `f_owner.signum`): the signal delivered on
    /// async-I/O readiness; `0` = the default `SIGIO` (data) / `SIGURG` (OOB).
    f_sig: ::core::sync::atomic::AtomicI32,
    /// `F_SETLEASE`/`F_GETLEASE` lease type held on this open file description
    /// (Linux `fl->fl_type` of the `FL_LEASE` lock): `F_RDLCK`(0) read lease,
    /// `F_WRLCK`(1) write lease, `F_UNLCK`(2) = no lease. Default `F_UNLCK`.
    /// Storage + validation only; the lease-break delivery (a conflicting
    /// open signalling the lease holder) is the lease-manager follow-up.
    lease: ::core::sync::atomic::AtomicI32,
    /// `F_NOTIFY` (dnotify) directory-change watch mask (Linux `dnotify_struct
    /// .dn_mask`): the `DN_*` events this directory fd wants `F_SETSIG`/`SIGIO`
    /// for. `0` = no watch. `F_NOTIFY` is additive unless the caller passes a
    /// zero arg (clear). Storage + validation only; the event delivery rides
    /// the dnotify follow-up (needs dir-mutation hooks, cross-lane).
    dnotify_mask: AtomicU32,
    /// `file->f_version` (Linux): inode change-version this open last observed;
    /// directory readers compare it vs `inode->i_version` to drop a stale cursor.
    f_version: AtomicU64,
    /// `F_GET_RW_HINT`/`F_SET_RW_HINT` write-life hint (Linux
    /// `file->f_write_hint` / `inode->i_write_hint`): `RWH_WRITE_LIFE_*`
    /// (`NOT_SET`=0 / `NONE`=1 / `SHORT`=2 / `MEDIUM`=3 / `LONG`=4 /
    /// `EXTREME`=5). Advisory storage forwarded to a hinting block backend;
    /// default `0`. # C: O(1)
    rw_hint: AtomicU64,
    /// Linux `file->f_ep`: weak backlinks to epitems watching this open file
    /// description. Final `File::drop` drains them before backend teardown.
    epoll_links: Spinlock<Vec<(u32, Weak<dyn FileEpollLink>)>, FileLinkClass>,
}
