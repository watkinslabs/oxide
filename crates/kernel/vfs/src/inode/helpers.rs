use core::sync::atomic::Ordering;

use crate::idmap::Idmap;
use crate::pseudo_ino::{RegionAllocator, VFS_ANON};
use crate::namei::{Cred, S_ISGID, S_IXGRP};
use crate::timespec::Timespec64;
use crate::types::{FileType, KResult, S_IFMT, S_IFDIR, S_IFLNK, Umode, VfsError};

use super::flags::{
    I_VERSION_INCREMENT, I_VERSION_QUERIED, I_VERSION_QUERIED_SHIFT, S_APPEND, S_ATIME, S_CTIME,
    S_IMMUTABLE, S_MTIME, S_NOATIME, S_SYNC, S_VERSION,
};
use super::model::Inode;

/// `get_next_ino` — the anon-inode counter for the families with no number
/// range of their own (pidfd, POSIX message queues, the io_uring low half).
/// It draws from [`VFS_ANON`] rather than from 1: counting up from 1 walked
/// straight through the console tty band and then every other low-space
/// region, so a long-lived system eventually handed a pidfd the number
/// `/dev/tty1` had already taken. # C: O(1)
pub fn get_next_ino() -> u32 {
    static NEXT_ANON_INO: RegionAllocator = RegionAllocator::new(&VFS_ANON);
    NEXT_ANON_INO.alloc() as u32
}

pub fn is_immutable(inode: &Inode) -> bool { inode.i_flags() & S_IMMUTABLE != 0 }
pub fn is_append(inode: &Inode) -> bool { inode.i_flags() & S_APPEND != 0 }
pub fn is_noatime(inode: &Inode) -> bool { inode.i_flags() & S_NOATIME != 0 }
pub fn is_sync(inode: &Inode) -> bool { inode.i_flags() & S_SYNC != 0 }

pub fn inode_peek_iversion_raw(inode: &Inode) -> u64 {
    match inode.i_version_raw() { Some(v) => v.load(Ordering::Relaxed), None => 0 }
}

pub fn inode_set_iversion_raw(inode: &Inode, val: u64) {
    if let Some(v) = inode.i_version_raw() { v.store(val, Ordering::Relaxed); }
}

pub fn inode_maybe_inc_iversion(inode: &Inode, force: bool) -> bool {
    let store = match inode.i_version_raw() { Some(v) => v, None => return false };
    let mut cur = store.load(Ordering::Relaxed);
    loop {
        if !force && (cur & I_VERSION_QUERIED) == 0 { return false; }
        let new = (cur & !I_VERSION_QUERIED) + I_VERSION_INCREMENT;
        match store.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(actual) => cur = actual,
        }
    }
}

pub fn inode_inc_iversion(inode: &Inode) { inode_maybe_inc_iversion(inode, true); }

pub fn inode_query_iversion(inode: &Inode) -> u64 {
    let store = match inode.i_version_raw() { Some(v) => v, None => return 0 };
    let mut cur = store.load(Ordering::Relaxed);
    loop {
        if (cur & I_VERSION_QUERIED) != 0 { break; }
        let new = cur | I_VERSION_QUERIED;
        match store.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
    cur >> I_VERSION_QUERIED_SHIFT
}

pub fn generic_update_time(inode: &Inode, now: Timespec64, flags: u32) -> KResult<()> {
    let a = if flags & S_ATIME != 0 { Some(now) } else { None };
    let m = if flags & S_MTIME != 0 { Some(now) } else { None };
    if flags & (S_ATIME | S_MTIME | S_CTIME) != 0 {
        let ctime = if flags & S_CTIME != 0 { now } else { inode.ctime().unwrap_or_default() };
        inode.set_times(a, m, ctime)?;
    }
    if flags & S_VERSION != 0 { inode_maybe_inc_iversion(inode, false); }
    Ok(())
}

pub fn inode_owner_or_capable(idmap: &crate::idmap::Idmap, inode: &Inode, cred: &Cred) -> bool {
    let vfsuid = idmap.map_out_uid(inode.uid().unwrap_or(0));
    if vfsuid == cred.uid { return true; }
    cred.cap_fowner && vfsuid != crate::idmap::INVALID_ID
}

pub fn inode_init_owner(dir: &Inode, mode: Umode, cred: &Cred) -> (u32, u32, Umode) {
    let uid = cred.uid;
    let mut m = mode;
    let gid = if dir.i_mode() & S_ISGID != 0 {
        let dgid = dir.gid().unwrap_or(0);
        if m & crate::types::S_IFMT == crate::types::S_IFDIR {
            m |= S_ISGID;
        } else if m & (S_ISGID | S_IXGRP) == S_ISGID | S_IXGRP && !cred.in_group(dgid) && !cred.cap_fsetid {
            m &= !S_ISGID;
        }
        dgid
    } else {
        cred.gid
    };
    (uid, gid, m)
}

/// `inode_init_owner` with mount-idmapped caller ids. # C: O(extents)
pub fn inode_init_owner_idmap(idmap: &Idmap, dir: &Inode, mode: Umode, cred: &Cred) -> (u32, u32, Umode) {
    let uid = idmap.map_in_uid(cred.uid);
    let mut m = mode;
    let gid = if dir.i_mode() & S_ISGID != 0 {
        let dgid = dir.gid().unwrap_or(0);
        if m & S_IFMT == S_IFDIR {
            m |= S_ISGID;
        } else if m & (S_ISGID | S_IXGRP) == S_ISGID | S_IXGRP {
            let vfsgid = idmap.map_out_gid(dgid);
            if !cred.in_group(vfsgid) && !cred.cap_fsetid { m &= !S_ISGID; }
        }
        dgid
    } else {
        idmap.map_in_gid(cred.gid)
    };
    (uid, gid, m)
}

fn mode_strip_sgid_create(idmap: &Idmap, dir: &Inode, mode: Umode, cred: &Cred) -> Umode {
    if (mode & (S_ISGID | S_IXGRP)) != (S_ISGID | S_IXGRP) { return mode; }
    if mode & S_IFMT == S_IFDIR || dir.i_mode() & S_ISGID == 0 { return mode; }
    let dgid = dir.gid().unwrap_or(0);
    let vfsgid = idmap.map_out_gid(dgid);
    if cred.in_group(vfsgid) || cred.cap_fsetid { mode } else { mode & !S_ISGID }
}

/// Linux `vfs_prepare_mode` plus `inode_init_owner`. # C: O(extents)
pub fn prepare_create_owner_mode(idmap: &Idmap, dir: &Inode, mode: Umode, mask_perms: Umode,
    ftype: Umode, cred: &Cred, umask: Umode) -> (u32, u32, Umode)
{
    let mut m = mode_strip_sgid_create(idmap, dir, mode, cred);
    m &= !umask;
    m &= mask_perms & !S_IFMT;
    m |= ftype & S_IFMT;
    inode_init_owner_idmap(idmap, dir, m, cred)
}

/// Owner ids for a newly created symlink. # C: O(extents)
pub fn prepare_symlink_owner(idmap: &Idmap, dir: &Inode, cred: &Cred) -> (u32, u32) {
    let (uid, gid, _mode) = inode_init_owner_idmap(idmap, dir, S_IFLNK | 0o777, cred);
    (uid, gid)
}

pub(crate) fn no_data_op_errno(ft: FileType) -> VfsError {
    match ft { FileType::Directory => VfsError::Eisdir, _ => VfsError::Einval }
}
