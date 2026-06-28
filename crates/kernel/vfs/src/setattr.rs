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

extern crate alloc;
use crate::idmap::Idmap;
use crate::inode::{Inode, InodeRef};
use crate::getattr::default_perm_for;
use crate::inode::S_APPEND;
use crate::namei::{Cred, inode_permission, MAY_WRITE, S_ISGID, S_ISUID, S_IXGRP};
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

/// Requested attribute change (Linux `struct iattr`). `valid` selects which
/// fields apply; uid/gid are vfs ids (the caller's view) until `map_in_*` at
/// apply. Times are absolute ns; `ctime_ns` is stamped on every change.
#[derive(Clone, Copy, Default)]
pub struct Iattr {
    pub valid: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
}

/// `setattr_prepare` (Linux `fs/attr.c`): permission + idmap gate, run before
/// any mutation. Mutates `ia` to strip a disallowed S_ISGID (chmod) and to set
/// the S_ISUID/S_ISGID kill flags (chown of a non-directory). # C: O(ngroups)
pub fn setattr_prepare(idmap: &Idmap, inode: &InodeRef, ia: &mut Iattr, cred: &Cred) -> KResult<()> {
    let vfsuid = idmap.map_out_uid(inode.uid().unwrap_or(0));
    let vfsgid = idmap.map_out_gid(inode.gid().unwrap_or(0));
    let is_owner = cred.uid == vfsuid || cred.cap_fowner;

    // chmod: owner or CAP_FOWNER, then S_ISGID strip for a non-member.
    if ia.valid & ATTR_MODE != 0 {
        if !is_owner { return Err(VfsError::Eperm); }
        if ia.mode & S_ISGID != 0 && !cred.cap_fsetid && !cred.in_group(vfsgid) {
            ia.mode &= !S_ISGID;
        }
    }

    // chown: CAP_CHOWN for uid; CAP_CHOWN or (owner AND target-group member)
    // for gid. The ATTR_KILL_SUID/SGID priv-drop flags are set by the chown
    // caller (Linux `chown_common`), not here, so `chown(-1,-1)` still drops
    // them; `apply_kill_priv` folds them into the final mode at apply time.
    if ia.valid & (ATTR_UID | ATTR_GID) != 0 {
        if ia.valid & ATTR_UID != 0 && ia.uid != vfsuid && !cred.cap_chown {
            return Err(VfsError::Eperm);
        }
        if ia.valid & ATTR_GID != 0 && ia.gid != vfsgid {
            let owner_member = cred.uid == vfsuid && cred.in_group(ia.gid);
            if !owner_member && !cred.cap_chown { return Err(VfsError::Eperm); }
        }
    }

    // truncate: MAY_WRITE on the inode (Linux `inode_permission` rejects an
    // S_IMMUTABLE inode with EPERM here), then the S_APPEND reject (Linux
    // `vfs_truncate`: `if (IS_APPEND(inode)) error = -EPERM`). An append-only
    // file can only ever grow at its end, so any size change is forbidden —
    // not even CAP_FOWNER bypasses it.
    if ia.valid & ATTR_SIZE != 0 {
        inode_permission(inode, MAY_WRITE, cred)?;
        if inode.i_flags() & S_APPEND != 0 { return Err(VfsError::Eperm); }
    }

    // utimes (Linux fs/utimes.c `utimes_common` + fs/attr.c `setattr_prepare`):
    // owner/CAP_FOWNER (EPERM) is required for any *explicit* `times[]` that is
    // not "set BOTH to now". Linux marks that case with `ATTR_TIMES_SET` (set
    // whenever `times != NULL` and not both UTIME_NOW). The sole MAY_WRITE/owner
    // (EACCES) path is setting BOTH atime AND mtime to now (NULL `times` or both
    // UTIME_NOW), which always arrives as `ATTR_ATIME | ATTR_MTIME` with no
    // `*_SET` bit. The equivalent signal here is: a *specific* time (`*_SET`),
    // OR a per-field selection touching only one of atime/mtime (the other
    // UTIME_OMIT) — e.g. `{UTIME_NOW, UTIME_OMIT}`, which Linux still gates on
    // ownership even though the live field is "now". A non-owner with mere write
    // access may only set BOTH timestamps to now.
    if ia.valid & (ATTR_ATIME | ATTR_MTIME) != 0 {
        let both_now = ia.valid & (ATTR_ATIME | ATTR_MTIME) == ATTR_ATIME | ATTR_MTIME
            && ia.valid & (ATTR_ATIME_SET | ATTR_MTIME_SET) == 0;
        if !both_now {
            if !is_owner { return Err(VfsError::Eperm); }
        } else if !is_owner {
            inode_permission(inode, MAY_WRITE, cred)?;
        }
    }
    Ok(())
}

/// Fold the ATTR_KILL_SUID/SGID flags into a concrete mode given the current
/// `cur` perm bits (Linux `setattr_copy` priv-drop). # C: O(1)
pub fn apply_kill_priv(valid: u32, mut mode: u16) -> u16 {
    if valid & ATTR_KILL_SUID != 0 { mode &= !S_ISUID; }
    if valid & ATTR_KILL_SGID != 0 && (mode & S_IXGRP != 0) { mode &= !S_ISGID; }
    mode
}

/// `simple_setattr` (Linux `fs/libfs.c`) — the default `i_op->setattr`: apply
/// the prepared `ia` to the inode's native metadata, mapping owner ids back to
/// fs ids (`map_in_*`). Returns `Erofs` for inodes without native storage
/// (the kernel `notify_change` then falls back to its metadata overlay).
/// # C: O(1)
pub fn simple_setattr<I: Inode + ?Sized>(inode: &I, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
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
        let a = if ia.valid & ATTR_ATIME != 0 { Some(ia.atime_ns) } else { None };
        let m = if ia.valid & ATTR_MTIME != 0 { Some(ia.mtime_ns) } else { None };
        inode.set_times(a, m, ia.ctime_ns)?;
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
pub fn setattr_should_drop_suidgid<I: Inode + ?Sized>(inode: &I, cred: &Cred) -> u32 {
    let mode = inode.perm().unwrap_or_else(|| default_perm_for(inode.file_type()));
    let mut kill = 0u32;
    if mode & S_ISUID != 0 { kill |= ATTR_KILL_SUID; }
    if mode & S_ISGID != 0 && mode & S_IXGRP != 0 { kill |= ATTR_KILL_SGID; }
    if kill != 0 && !cred.cap_fsetid && matches!(inode.file_type(), FileType::Regular) { kill } else { 0 }
}

/// `notify_change` (Linux `fs/attr.c`): `setattr_prepare` then `i_op->setattr`.
/// The kernel syscall layer adds an `Erofs`→metadata-overlay fallback for
/// pseudo-fs; this native form serves backends with real storage and the
/// hosted tests. # C: O(ngroups)
pub fn notify_change(idmap: &Idmap, inode: &InodeRef, ia: &mut Iattr, cred: &Cred) -> KResult<()> {
    setattr_prepare(idmap, inode, ia, cred)?;
    // Floor the timestamp fields to the backing superblock's `s_time_gran`
    // (Linux `fs/attr.c` `notify_change`, which sets each `ia_*time` through
    // `timestamp_truncate`): a setattr must never record sub-granularity
    // precision the filesystem cannot persist (ext4 1 ns vs a coarse-time
    // backend). `ctime` is stamped on every change, so it is floored whenever
    // any time field is applied. Inodes without an `i_sb` (anon/pseudo) keep
    // full-ns values — their granularity is implicitly 1 ns.
    if let Some(sb) = inode.i_sb() {
        if ia.valid & ATTR_ATIME != 0 { ia.atime_ns = sb.timestamp_truncate(ia.atime_ns); }
        if ia.valid & ATTR_MTIME != 0 { ia.mtime_ns = sb.timestamp_truncate(ia.mtime_ns); }
        if ia.valid & (ATTR_ATIME | ATTR_MTIME | ATTR_CTIME) != 0 {
            ia.ctime_ns = sb.timestamp_truncate(ia.ctime_ns);
        }
    }
    inode.setattr(idmap, ia)
}
