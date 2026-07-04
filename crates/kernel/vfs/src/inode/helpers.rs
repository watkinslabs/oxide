use core::sync::atomic::{AtomicU32, Ordering};

use crate::namei::{Cred, S_ISGID, S_IXGRP};
use crate::types::{FileType, KResult, Umode, VfsError};

use super::flags::{
    I_VERSION_INCREMENT, I_VERSION_QUERIED, I_VERSION_QUERIED_SHIFT, S_APPEND, S_ATIME, S_CTIME,
    S_IMMUTABLE, S_MTIME, S_NOATIME, S_SYNC, S_VERSION,
};
use super::model::Inode;

/// `get_next_ino`. # C: O(1)
pub fn get_next_ino() -> u32 {
    static LAST_INO: AtomicU32 = AtomicU32::new(0);
    loop {
        let next = LAST_INO.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if next != 0 { return next; }
    }
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

pub fn generic_update_time(inode: &Inode, now: u64, flags: u32) -> KResult<()> {
    let a = if flags & S_ATIME != 0 { Some(now) } else { None };
    let m = if flags & S_MTIME != 0 { Some(now) } else { None };
    if flags & (S_ATIME | S_MTIME | S_CTIME) != 0 {
        let ctime = if flags & S_CTIME != 0 { now } else { inode.ctime().unwrap_or(0) };
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

pub(crate) fn no_data_op_errno(ft: FileType) -> VfsError {
    match ft { FileType::Directory => VfsError::Eisdir, _ => VfsError::Einval }
}
