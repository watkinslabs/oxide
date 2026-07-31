//! `setattr_prepare` / `notify_change` (Linux `fs/attr.c`) — the single
//! convergence point for chmod / chown / truncate / utimes.
//!
//! `setattr_prepare` runs the DAC + idmap decision (owner/CAP_FOWNER for
//! chmod and specific-time utimes; CAP_CHOWN/owner+member for chown;
//! MAY_WRITE for truncate and now/NULL utimes), strips S_ISGID on a
//! non-member chmod, and flags S_ISUID/S_ISGID kill on a chown. Owner
//! comparisons are against the inode's *vfsuid/vfsgid* (`idmap.map_out_*`),
//! and chown/create target ids are stored as fs ids (`idmap.map_in_*`),
//! so an identity-mapped (non-idmapped) mount behaves exactly as before.

//!
//! Module manifest:
//!   gate.rs — `may_setattr`, `chown_ok`/`chgrp_ok`, the `ATTR_TOUCH` /
//!             `ATTR_TIMES_SET` classification, and the owner-mapping
//!             (`EOVERFLOW`) rule.

extern crate alloc;
use core::sync::atomic::{AtomicU64, Ordering};

mod gate;
pub use gate::{attr_times_set, attr_touch, check_owner_mappings, chgrp_ok, chown_ok, may_setattr};

use crate::idmap::Idmap;
use crate::inode::{Inode, InodeRef, inode_owner_or_capable};
use crate::getattr::default_perm_for;
use crate::inode::S_APPEND;
use crate::namei::{Cred, inode_permission, MAY_WRITE, S_ISGID, S_ISUID, S_IXGRP};
use crate::timespec::Timespec64;
use crate::types::{FileType, KResult, VfsError};

/// `ATTR_*` valid-mask bits (Linux `include/linux/fs.h`, subset). `*_SET`
/// distinguish a *specific* time from "set to now" (UTIME_NOW / NULL), which
/// the permission rule treats differently.
pub const ATTR_MODE:      u32 = 1 << 0;
pub const ATTR_UID:       u32 = 1 << 1;
pub const ATTR_GID:       u32 = 1 << 2;
pub const ATTR_SIZE:      u32 = 1 << 3;
pub const ATTR_ATIME:     u32 = 1 << 4;
pub const ATTR_MTIME:     u32 = 1 << 5;
pub const ATTR_CTIME:     u32 = 1 << 6;
pub const ATTR_ATIME_SET: u32 = 1 << 7;
pub const ATTR_MTIME_SET: u32 = 1 << 8;
pub const ATTR_KILL_SUID: u32 = 1 << 9;
pub const ATTR_KILL_SGID: u32 = 1 << 10;
/// Linux `ATTR_FORCE` — "the caller already established write authority, run
/// the change anyway" (`may_setattr`: `if (ia_valid & ATTR_FORCE) return 0;`).
/// Linux checks `inode_permission(MAY_WRITE)` for an `ATTR_SIZE` change in
/// `vfs_truncate` (the path form) and NOT at all in `do_ftruncate` (an
/// `FMODE_WRITE` descriptor IS the authority); this bit lets those two callers
/// carry that decision instead of having it re-run — and wrongly re-fail — here.
pub const ATTR_FORCE:     u32 = 1 << 11;

/// Requested attribute change (Linux `struct iattr`). `valid` selects which
/// fields apply; uid/gid are vfs ids (the caller's view) until `map_in_*` at
/// apply. Times are absolute [`Timespec64`] wall-clock instants — SIGNED
/// seconds, so a pre-1970 `utimensat` is an ordinary request, not an error
/// (Linux `fs/utimes.c` validates `tv_nsec` only). `ctime` is stamped on every
/// change.
#[derive(Clone, Copy, Default)]
pub struct Iattr {
    pub valid: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Timespec64,
    pub mtime: Timespec64,
    pub ctime: Timespec64,
}

/// Scheduler boundary for the `RLIMIT_FSIZE` half of [`inode_newsize_ok`]
/// (Linux `rlimit(RLIMIT_FSIZE)` + `send_sig(SIGXFSZ, current, 0)`). VFS owns
/// the size contract; the scheduler owns rlimits and signal delivery, so the
/// decision is installed rather than reached for — the same typed boundary the
/// file-lock wait hooks use. Returns `false` when the new size exceeds the
/// caller's SOFT limit, having already posted `SIGXFSZ`.
pub type RlimitFsizeHook = fn(u64) -> bool;

static RLIMIT_FSIZE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the `RLIMIT_FSIZE` decision. Called once at boot. # C: O(1)
pub fn set_rlimit_fsize_hook(f: RlimitFsizeHook) {
    RLIMIT_FSIZE_HOOK.store(f as usize as u64, Ordering::Release);
}

/// Drop the installed `RLIMIT_FSIZE` decision (hosted tests). # C: O(1)
pub fn clear_rlimit_fsize_hook() { RLIMIT_FSIZE_HOOK.store(0, Ordering::Release); }

/// `inode_newsize_ok` (Linux `fs/attr.c`) — the size constraints, which
/// `setattr_prepare` applies BEFORE `ATTR_FORCE` because they "can't be
/// overridden using ATTR_FORCE". Both caps bite only when the file GROWS:
/// shrinking is never limited by `RLIMIT_FSIZE`, and a size already on disk is
/// by construction within `s_maxbytes`. A soft-limit violation posts `SIGXFSZ`
/// (inside the hook) before reporting `EFBIG`. # C: O(1)
pub fn inode_newsize_ok(inode: &Inode, offset: u64) -> KResult<()> {
    if offset <= inode.size() { return Ok(()); }
    let raw = RLIMIT_FSIZE_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: `set_rlimit_fsize_hook` is the only writer and stores only a
        // `RlimitFsizeHook` fn pointer, so this transmute restores its own type.
        let f: RlimitFsizeHook = unsafe { core::mem::transmute(raw as usize) };
        if !f(offset) { return Err(VfsError::Efbig); }
    }
    if let Some(sb) = inode.i_sb() {
        if offset > sb.s_maxbytes() { return Err(VfsError::Efbig); }
    }
    Ok(())
}

/// `setattr_prepare` (Linux `fs/attr.c`): permission + idmap gate, run before
/// any mutation. Mutates `ia` to strip a disallowed S_ISGID (chmod) and to set
/// the S_ISUID/S_ISGID kill flags (chown of a non-directory). # C: O(ngroups)
pub fn setattr_prepare(idmap: &Idmap, inode: &InodeRef, ia: &mut Iattr, cred: &Cred) -> KResult<()> {
    // `may_setattr` runs first (Linux calls it at the top of `notify_change`,
    // ahead of this function): an immutable or append-only inode refuses every
    // mode / owner / explicit-timestamp change with EPERM, and the "set both
    // times to now" form is the sole attribute change a non-owner with write
    // access may make. Keeping it here rather than only in `notify_change`
    // means a direct `setattr_prepare` caller (`file_setattr`, a backend
    // `->setattr`) cannot skip the flag gate.
    may_setattr(idmap, inode, ia.valid, cred)?;
    // Linux: the size constraints "can't be overridden using ATTR_FORCE", so
    // they run ahead of it. The append-only reject on a size change lives in
    // the truncate callers (`vfs_truncate`: `error = -EPERM; if
    // (IS_APPEND(inode))`, `do_ftruncate`: `if (IS_APPEND(file_inode(file)))
    // return -EPERM;`) and is repeated here so an `O_TRUNC` open or a
    // `file_setattr` size change cannot reach a backend behind `ATTR_FORCE`.
    if ia.valid & ATTR_SIZE != 0 {
        inode_newsize_ok(inode, ia.size)?;
        if inode.i_flags() & S_APPEND != 0 { return Err(VfsError::Eperm); }
    }
    // `if (ia_valid & ATTR_FORCE) goto kill_priv;`: the caller has already
    // established authority for this change and the DAC gate below must not
    // re-derive — and wrongly re-fail — it. `truncate(2)` reaches here having
    // run `inode_permission(MAY_WRITE)`, `ftruncate(2)` having required
    // `FMODE_WRITE`, and both then carry `ATTR_MTIME | ATTR_CTIME` meaning
    // "now", which is NOT the owner-gated specific-time form.
    if ia.valid & ATTR_FORCE != 0 { return Ok(()); }

    // Linux order: chown, then chgrp, then chmod, then the timestamp gate.
    // A combined iattr reports the FIRST of those that is refused.
    if ia.valid & ATTR_UID != 0 && !chown_ok(idmap, inode, ia.uid, cred) {
        return Err(VfsError::Eperm);
    }
    if ia.valid & ATTR_GID != 0 && !chgrp_ok(idmap, inode, ia.gid, cred) {
        return Err(VfsError::Eperm);
    }

    // `inode_owner_or_capable` (Linux), NOT the open-coded `uid == vfsuid ||
    // cap_fowner`: on an idmapped mount whose extents do not cover the inode's
    // fs owner, the vfsuid is INVALID and the CAP_FOWNER path must be DENIED
    // (privilege cannot be exercised over an owner with no mapping in the
    // caller's namespace, Linux `vfsuid_has_mapping`). The inline form silently
    // granted it — the correctness edge this helper exists to close.
    let is_owner = inode_owner_or_capable(idmap, inode.as_ref(), cred);

    // chmod: owner or CAP_FOWNER, then S_ISGID strip for a non-member. The
    // group the membership test names is the one the file will END UP in — the
    // incoming `ia.gid` when this same change also sets the group, otherwise
    // the inode's current vfsgid.
    if ia.valid & ATTR_MODE != 0 {
        if !is_owner { return Err(VfsError::Eperm); }
        let vfsgid = if ia.valid & ATTR_GID != 0 { ia.gid }
                     else { idmap.map_out_gid(inode.gid().unwrap_or(0)) };
        if ia.mode & S_ISGID != 0 && !cred.cap_fsetid && !cred.in_group(vfsgid) {
            ia.mode &= !S_ISGID;
        }
    }

    // truncate reached WITHOUT `ATTR_FORCE` (an `O_TRUNC` open, a
    // `file_setattr` size change): MAY_WRITE on the inode, which also rejects
    // an S_IMMUTABLE inode with EPERM (Linux `inode_permission`). The S_APPEND
    // reject already ran above, ahead of the `ATTR_FORCE` short-circuit.
    if ia.valid & ATTR_SIZE != 0 { inode_permission(inode, MAY_WRITE, cred)?; }

    // utimes (Linux `setattr_prepare`): owner/CAP_FOWNER (EPERM) for any
    // *explicit* `times[]` that is not "set BOTH to now" — a specific instant
    // (`*_SET`) or a per-field selection touching only one of atime/mtime (the
    // other UTIME_OMIT), which Linux gates on ownership even though the live
    // field's value is "now". The "both to now" form's own gate is the
    // MAY_WRITE fallback inside `may_setattr` above.
    if attr_times_set(ia.valid) && !is_owner { return Err(VfsError::Eperm); }
    Ok(())
}

/// Fold the ATTR_KILL_SUID/SGID flags into a concrete mode (Linux
/// `notify_change`'s `ATTR_KILL_S*ID` → `ATTR_MODE` rewrite). The flags are
/// already a DECISION: whoever set them ([`setattr_should_drop_suidgid`] for
/// the write/truncate path, [`setattr_should_drop_sgid`] for chown) applied
/// the S_IXGRP / group-membership rule. Re-testing S_IXGRP here silently
/// undid the chown case, where a bare S_ISGID must drop for a caller outside
/// the file's group. # C: O(1)
pub fn apply_kill_priv(valid: u32, mut mode: u16) -> u16 {
    if valid & ATTR_KILL_SUID != 0 { mode &= !S_ISUID; }
    if valid & ATTR_KILL_SGID != 0 { mode &= !S_ISGID; }
    mode
}

/// `simple_setattr` (Linux `fs/libfs.c`) — the default `i_op->setattr`: apply
/// the prepared `ia` to the inode's native metadata, mapping owner ids back to
/// fs ids (`map_in_*`). Returns `Erofs` for inodes without native storage
/// (the kernel `notify_change` then falls back to its metadata overlay).
/// # C: O(1)
pub fn simple_setattr(inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
    // Linux `shmem_setattr` (`mm/shmem.c`): an exec-sealed memfd may change
    // other permission bits, but no chmod path may add or remove an execute
    // bit. Only shmem-style inodes expose a seal carrier, so keeping the gate
    // at this common metadata-apply boundary covers every chmod/ACL caller
    // without affecting ordinary filesystem inodes.
    if ia.valid & ATTR_MODE != 0
        && inode.fcntl_seals().is_some_and(|seals| {
            seals.load(Ordering::Acquire) & crate::inode::F_SEAL_EXEC != 0
        })
        && (inode.i_mode() as u16 ^ ia.mode) & 0o111 != 0
    {
        return Err(VfsError::Eperm);
    }
    if ia.valid & ATTR_SIZE != 0 {
        inode.truncate(ia.size)?;
        // `truncate_pagecache` (Linux `mm/truncate.c`, via `truncate_setsize`):
        // after the backend updates `i_size`, evict resident cache pages lying
        // WHOLLY beyond the new size so a later refault re-reads zeros/backing,
        // never stale post-EOF bytes. `invalidate_range` retains the page that
        // straddles the new size (the backend `truncate` zeroed its tail). On
        // grow nothing is resident past the new size, so this is a no-op — exactly
        // Linux. Inodes without an `i_mapping` (no page cache) skip it.
        if let Some(m) = inode.i_mapping() { m.invalidate_range(ia.size, u64::MAX); }
    }
    if ia.valid & (ATTR_UID | ATTR_GID) != 0 {
        let uid = if ia.valid & ATTR_UID != 0 { idmap.map_in_uid(ia.uid) } else { inode.uid().unwrap_or(0) };
        let gid = if ia.valid & ATTR_GID != 0 { idmap.map_in_gid(ia.gid) } else { inode.gid().unwrap_or(0) };
        crate::quota::dquot_transfer_owner(inode, uid, gid)?;
        inode.set_owner(uid, gid)?;
    }
    let mut mode = ia.mode;
    let mut set_mode = ia.valid & ATTR_MODE != 0;
    if ia.valid & (ATTR_KILL_SUID | ATTR_KILL_SGID) != 0 {
        let base = if set_mode { mode } else { inode.perm().unwrap_or_else(|| default_perm_for(inode.file_type())) };
        mode = apply_kill_priv(ia.valid, base);
        set_mode = true;
    }
    if set_mode { inode.set_perm(mode & 0o7777)?; }
    if ia.valid & (ATTR_ATIME | ATTR_MTIME | ATTR_CTIME) != 0 {
        let a = if ia.valid & ATTR_ATIME != 0 { Some(ia.atime) } else { None };
        let m = if ia.valid & ATTR_MTIME != 0 { Some(ia.mtime) } else { None };
        inode.set_times(a, m, ia.ctime)?;
    }
    Ok(())
}

/// `setattr_should_drop_suidgid` (Linux `fs/attr.c`): the write-path companion
/// to [`apply_kill_priv`]. Returns the `ATTR_KILL_SUID`/`ATTR_KILL_SGID` mask a
/// modifying write (or content/size change) must fold into the inode mode:
/// S_ISUID is always killed; S_ISGID only when group-executable (a bare S_ISGID
/// is a mandatory-lock mark — left alone). A caller holding CAP_FSETID over the
/// inode keeps the bits, and the drop applies to regular files only (Linux
/// `file_remove_privs` / `dentry_needs_remove_privs`). # C: O(1)
pub fn setattr_should_drop_suidgid(inode: &Inode, cred: &Cred) -> u32 {
    let mode = inode.perm().unwrap_or_else(|| default_perm_for(inode.file_type()));
    let mut kill = 0u32;
    if mode & S_ISUID != 0 { kill |= ATTR_KILL_SUID; }
    if mode & S_ISGID != 0 && mode & S_IXGRP != 0 { kill |= ATTR_KILL_SGID; }
    if kill != 0 && !cred.cap_fsetid && matches!(inode.file_type(), FileType::Regular) { kill } else { 0 }
}

/// `setattr_should_drop_sgid` (Linux `fs/attr.c`) — the idmap-aware S_ISGID
/// strip used by the chown / `setattr_copy` path (distinct from the write-path
/// [`setattr_should_drop_suidgid`], which preserves a bare mandatory-lock
/// S_ISGID). Returns `ATTR_KILL_SGID` when the inode is set-group-id AND either
/// (a) it is group-executable, or (b) the caller is NOT in the inode's *vfsgid*
/// group and lacks CAP_FSETID over it — an ownership/permission change that
/// would hand a setgid bit to a process outside the file's group drops it. The
/// inode gid is mapped THROUGH the mount idmap before the group test (Linux
/// `i_gid_into_vfsgid` + `in_group_or_capable`), so an idmapped mount compares
/// against the id the caller actually observes. # C: O(ngroups)
pub fn setattr_should_drop_sgid(idmap: &Idmap, inode: &Inode, cred: &Cred) -> u32 {
    let mode = inode.perm().unwrap_or_else(|| default_perm_for(inode.file_type()));
    if mode & S_ISGID == 0 { return 0; }
    if mode & S_IXGRP != 0 { return ATTR_KILL_SGID; }
    // in_group_or_capable: caller in the inode's vfsgid group, or CAP_FSETID.
    let vfsgid = idmap.map_out_gid(inode.gid().unwrap_or(0));
    if cred.in_group(vfsgid) || cred.cap_fsetid { 0 } else { ATTR_KILL_SGID }
}

/// `notify_change` (Linux `fs/attr.c`): `setattr_prepare` then `i_op->setattr`.
/// The kernel syscall layer adds an `Erofs`→metadata-overlay fallback for
/// pseudo-fs; this native form serves backends with real storage and the
/// hosted tests. # C: O(ngroups)
///
/// The timestamp fields are floored to the backing superblock's `s_time_gran`
/// (Linux `timestamp_truncate`): a setattr must never record sub-granularity
/// precision the filesystem cannot persist. Inodes without an `i_sb`
/// (anon/pseudo) keep full-ns values — their granularity is implicitly 1 ns.
pub fn notify_change(idmap: &Idmap, inode: &InodeRef, ia: &mut Iattr, cred: &Cred) -> KResult<()> {
    reject_symlink_mode(inode, ia.valid)?;
    setattr_prepare(idmap, inode, ia, cred)?;
    check_owner_mappings(idmap, inode, ia.valid, ia.uid, ia.gid)?;
    notify_change_applied(idmap, inode, ia)
}

/// Linux `notify_change`: "Don't allow changing the mode of symlinks". The VFS
/// ignores a symlink's mode during permission checking and no filesystem
/// implements the change, so it is `EOPNOTSUPP` for every caller — reachable
/// only through `fchmodat2(AT_SYMLINK_NOFOLLOW)` and `file_setattr` on an
/// `O_PATH|O_NOFOLLOW` descriptor. It sits AFTER the mount read-only gate and
/// the immutable/append gate, so a symlink on a read-only mount answers
/// `EROFS`. # C: O(1)
fn reject_symlink_mode(inode: &InodeRef, valid: u32) -> KResult<()> {
    if valid & ATTR_MODE != 0 && matches!(inode.file_type(), FileType::Symlink) {
        return Err(VfsError::Eopnotsupp);
    }
    Ok(())
}

/// Mount-aware `notify_change` — the form every attribute-changing syscall
/// (chmod / chown / truncate / ftruncate / utimes) converges on. Adds, ahead of
/// [`notify_change`], the two things a syscall has that a bare inode does not:
/// the `mnt_want_write` read-only gate on the mount the object was reached
/// through, and the mount's idmap. `now_ns` is the caller's monotonic stamp for
/// `ctime` (Linux `current_time(inode)`), applied on every change per
/// `setattr_copy`.
///
/// oxide backs the public device nodes (`/dev/null`, `/dev/zero`, `/dev/full`,
/// `/dev/random`, `/dev/urandom`) with ONE shared inode across every mount
/// namespace where Linux gives each private `/dev` its own copy; a per-session
/// ownership reset would otherwise lock every other process out of them, so
/// those nodes report success and keep their as-created world-rw value. The DAC
/// decision above still runs. # C: O(ngroups)
pub fn notify_change_mnt(inode: &InodeRef, mnt_id: u64, ia: &mut Iattr, cred: &Cred, now_ns: u64)
    -> KResult<()>
{
    if mnt_id != 0 {
        if let Some(m) = crate::mount::mount_by_id(mnt_id) {
            if (m.flags() & crate::mount::MNT_RDONLY) != 0 { return Err(VfsError::Erofs); }
        }
    }
    let idmap = crate::mount::idmap_for(mnt_id);
    reject_symlink_mode(inode, ia.valid)?;
    setattr_prepare(&idmap, inode, ia, cred)?;
    check_owner_mappings(&idmap, inode, ia.valid, ia.uid, ia.gid)?;
    if inode.is_public_device() && ia.valid & (ATTR_UID | ATTR_GID | ATTR_MODE) != 0 {
        return Ok(());
    }
    ia.ctime = Timespec64::from_clock_ns(now_ns);
    notify_change_applied(&idmap, inode, ia)
}

/// `notify_change` minus the DAC gate — the apply half, shared by
/// [`notify_change`] and [`notify_change_mnt`] so the timestamp-granularity
/// floor lives in exactly one place. # C: O(1)
fn notify_change_applied(idmap: &Idmap, inode: &InodeRef, ia: &mut Iattr) -> KResult<()> {
    if let Some(sb) = inode.i_sb() {
        if ia.valid & ATTR_ATIME != 0 { ia.atime = sb.timestamp_truncate(ia.atime); }
        if ia.valid & ATTR_MTIME != 0 { ia.mtime = sb.timestamp_truncate(ia.mtime); }
        if ia.valid & (ATTR_ATIME | ATTR_MTIME | ATTR_CTIME) != 0 {
            ia.ctime = sb.timestamp_truncate(ia.ctime);
        }
    }
    let r = inode.setattr(idmap, ia);
    // Linux fires notification from HERE and nowhere else: `notify_change`
    // calls `fsnotify_change(dentry, ia_valid)` once `i_op->setattr` returns 0
    // (`fs/attr.c`). Firing per-syscall instead silently skips every path that
    // does not go through that one syscall.
    if r.is_ok() { crate::file::fire_setattr_hook(inode, ia.valid); }
    r
}
