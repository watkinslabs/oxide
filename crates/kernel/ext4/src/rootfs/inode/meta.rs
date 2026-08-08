use vfs::idmap::Idmap;
use vfs::inode::FS_PROJINHERIT_FL;
use vfs::{FileAttr, Iattr, Inode, KResult, Timespec64, VfsError};

use super::data::{Ext4FileData, ext4_state_of};
use crate::extent_rw::meta::InodeMetaUpdate;
use crate::superblock::{EXT4_LABEL_MAX, SB_OFF_VOLUME_NAME, SUPERBLOCK_OFFSET};

// ext4 on-disk `i_flags` (@0x20) bits — IDENTICAL to the `FS_*_FL` chattr view.
use crate::inode::flags::{EXT4_APPEND_FL, EXT4_IMMUTABLE_FL, EXT4_NOATIME_FL, EXT4_SYNC_FL};
const EXT4_JOURNAL_DATA_FL: u32 = 0x0000_4000;
const EXT4_EXTENTS_FL:   u32 = 0x0008_0000;
const EXT4_PROJINHERIT_FL: u32 = FS_PROJINHERIT_FL;
/// `lsattr`-visible ext4 flags (Linux `EXT4_FL_USER_VISIBLE` subset this
/// backend can report without advertising unsupported layouts).
const FS_FL_USER_VISIBLE:    u32 = 0x0003_DFFF | EXT4_EXTENTS_FL | EXT4_PROJINHERIT_FL;
/// `chattr`-settable ext4 flags (Linux `EXT4_FL_USER_MODIFIABLE` subset).
const FS_FL_USER_MODIFIABLE: u32 = 0x0003_80FF | EXT4_EXTENTS_FL | EXT4_PROJINHERIT_FL;

/// `ext4_fileattr_get` — the `FS_IOC_GETFLAGS` backend: the inode's on-disk
/// `i_flags` masked to the user-visible set. # C: O(1) inode read
pub(crate) fn ext4_fileattr_get(inode: &Inode) -> KResult<FileAttr> {
    let (st, ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    let raw = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?;
    let mut flags = raw.i_flags & FS_FL_USER_VISIBLE;
    if inode.file_type() == vfs::FileType::Regular {
        flags &= !FS_PROJINHERIT_FL;
    }
    // Linux `ext4_fileattr_get` publishes the translated `fsx_xflags` view;
    // `file_getattr(2)` reads `fa_xflags` straight out of it, so the
    // backend, not the consumer, owns the translation.
    let mut fa = vfs::fileattr_fill_flags(flags);
    fa.fsx_projid = if st.mount.sb.has_project() { raw.i_projid } else { 0 };
    Ok(fa)
}

/// `EXT4_IOC_GETVERSION`: return on-disk `i_generation`.
/// # C: O(1) inode read
pub(crate) fn ext4_getversion(inode: &Inode) -> KResult<u32> {
    let (st, ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    Ok(st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?.generation)
}

/// Linux `EXT4_IOC_SETVERSION` pre-copyin admission: owner/CAP_FOWNER, then
/// metadata_csum rejection before taking the mount write hold. # C: O(1)
pub(crate) fn ext4_setversion_prepare(inode: &Inode, idmap: &Idmap, cred: &vfs::Cred) -> KResult<()> {
    let (st, _ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    if !vfs::inode::inode_owner_or_capable(idmap, inode, cred) { return Err(VfsError::Eperm); }
    if st.mount.sb.has_metadata_csum() { return Err(VfsError::Enotty); }
    Ok(())
}

/// `EXT4_IOC_SETVERSION`: journal `i_generation`, stamp ctime, and bump
/// in-core i_version. # C: O(1) inode write
pub(crate) fn ext4_setversion(inode: &Inode, gen: u32) -> KResult<()> {
    let (st, ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    let raw = vfs::inode_times::realtime_now_ns();
    let ctime = vfs::inode_times::current_time(inode, raw);
    vfs::inode::inode_inc_iversion(inode);
    st.mount.persist_inode_generation(ino, gen, ctime).map_err(|_| VfsError::Eio)?;
    inode.set_times(None, None, ctime)
}

/// `FS_IOC_GETFSLABEL`: return `s_volume_name` padded with one NUL byte.
/// # C: O(1)
pub(crate) fn ext4_getfslabel(inode: &Inode) -> KResult<[u8; EXT4_LABEL_MAX + 1]> {
    let (st, _ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    let mut out = [0u8; EXT4_LABEL_MAX + 1];
    let label = st.mount.read_meta_byte_range(
        SUPERBLOCK_OFFSET + SB_OFF_VOLUME_NAME as u64,
        EXT4_LABEL_MAX,
    ).map_err(|_| VfsError::Eio)?;
    out[..EXT4_LABEL_MAX].copy_from_slice(&label);
    Ok(out)
}

/// Linux `FS_IOC_SETFSLABEL` pre-copyin admission: CAP_SYS_ADMIN first.
/// # C: O(1)
pub(crate) fn ext4_setfslabel_prepare(cap_sys_admin: bool) -> KResult<()> {
    if cap_sys_admin { Ok(()) } else { Err(VfsError::Eperm) }
}

/// `FS_IOC_SETFSLABEL`: journal the zero-padded 16-byte superblock label.
/// # C: O(SB rw)
pub(crate) fn ext4_setfslabel(inode: &Inode, label: [u8; EXT4_LABEL_MAX]) -> KResult<()> {
    let (st, _ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    st.mount.persist_fs_label(&label).map_err(|_| VfsError::Eio)
}

/// Linux ext4 `FITRIM` admission: CAP_SYS_ADMIN first, then block discard
/// capability before any usercopy. Local ext4 has no discard-capable block op.
/// # C: O(1)
pub(crate) fn ext4_fitrim_prepare(cap_sys_admin: bool) -> KResult<()> {
    if !cap_sys_admin { return Err(VfsError::Eperm); }
    Err(VfsError::Eopnotsupp)
}

/// `FITRIM` execution after ABI-layer usercopy. Unreachable until the block
/// layer advertises discard support. # C: O(1)
pub(crate) fn ext4_fitrim(_start: u64, _len: u64, _minlen: u64) -> KResult<()> {
    Err(VfsError::Eopnotsupp)
}

/// `ext4_fileattr_set` — the `FS_IOC_SETFLAGS` backend: fold the user-modifiable
/// bits of `fa.flags` over the preserved kernel-internal flags, persist to the
/// on-disk inode (journaled), and mirror IMMUTABLE/APPEND/NOATIME/SYNC into the
/// in-core VFS `i_flags` so `may_open`/`notify_change` enforce them at once.
/// # C: O(1) + one journaled inode write
pub(crate) fn ext4_fileattr_set(inode: &Inode, fa: &FileAttr) -> KResult<()> {
    let (st, ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    if st.mount.sb.is_quota_inode(ino) {
        return Err(VfsError::Eperm);
    }
    if inode.file_type() == vfs::FileType::Regular && fa.flags & EXT4_PROJINHERIT_FL != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    if fa.flags & !FS_FL_USER_VISIBLE != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    let cur = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?.i_flags;
    if (cur ^ fa.flags) & EXT4_JOURNAL_DATA_FL != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    let new = (cur & !FS_FL_USER_MODIFIABLE) | (fa.flags & FS_FL_USER_MODIFIABLE);
    ext4_ioctl_check_immutable(&st, ino, cur, fa.fsx_projid, new)?;
    if (cur ^ new) & EXT4_EXTENTS_FL != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    let raw_now = vfs::inode_times::realtime_now_ns();
    let ctime = vfs::inode_times::current_time(inode, raw_now);
    st.mount.persist_inode_flags(ino, new, ctime).map_err(|_| VfsError::Eio)?;
    vfs::inode::inode_inc_iversion(inode);
    inode.set_times(None, None, ctime)?;
    let mut s = inode.i_flags()
        & !(vfs::S_IMMUTABLE | vfs::S_APPEND | vfs::S_NOATIME | vfs::S_SYNC);
    if new & EXT4_IMMUTABLE_FL != 0 { s |= vfs::S_IMMUTABLE; }
    if new & EXT4_APPEND_FL    != 0 { s |= vfs::S_APPEND; }
    if new & EXT4_NOATIME_FL   != 0 { s |= vfs::S_NOATIME; }
    if new & EXT4_SYNC_FL      != 0 { s |= vfs::S_SYNC; }
    inode.set_i_flags(s);
    ext4_fileattr_setproject(&st, inode, ino, fa.fsx_projid)?;
    Ok(())
}

fn ext4_ioctl_check_immutable(
    st: &super::super::state::RootfsState,
    ino: u32,
    cur_flags: u32,
    projid: u32,
    new_flags: u32,
) -> KResult<()> {
    if cur_flags & EXT4_IMMUTABLE_FL == 0 || new_flags & EXT4_IMMUTABLE_FL == 0 {
        return Ok(());
    }
    if (cur_flags & !EXT4_IMMUTABLE_FL) != (new_flags & !EXT4_IMMUTABLE_FL) {
        return Err(VfsError::Eperm);
    }
    if st.mount.sb.has_project() {
        let raw = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?;
        if raw.i_projid != projid { return Err(VfsError::Eperm); }
    }
    Ok(())
}

fn ext4_fileattr_setproject(
    st: &super::super::state::RootfsState,
    inode: &Inode,
    ino: u32,
    projid: u32,
) -> KResult<()> {
    if !st.mount.sb.has_project() {
        return if projid == 0 { Ok(()) } else { Err(VfsError::Eopnotsupp) };
    }
    if st.mount.sb.inode_size as usize <= crate::csum::EXT4_GOOD_OLD_INODE_SIZE {
        return Err(VfsError::Eopnotsupp);
    }
    let raw = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?;
    if raw.i_projid == projid { return Ok(()); }
    super::super::quota::transfer_project_inode(st, inode, &raw, projid)?;
    let raw_now = vfs::inode_times::realtime_now_ns();
    let ctime = vfs::inode_times::current_time(inode, raw_now);
    vfs::inode::inode_inc_iversion(inode);
    inode.set_projid(projid);
    if st.mount.persist_inode_project(ino, projid, ctime).is_err() {
        super::super::quota::rollback_project_inode_transfer(st, inode, &raw, raw.i_projid)?;
        inode.set_projid(raw.i_projid);
        return Err(VfsError::Eio);
    }
    inode.set_times(None, None, ctime)
}

/// `ext4_setattr`: the `i_op->setattr` for every
/// ext4 inode. Apply the prepared `ia` to the in-core inode via the generic
/// `simple_setattr` (mode / owner / times / truncate + suid-kill fold), then
/// write the mutated metadata THROUGH to the on-disk inode (journaled), so
/// chmod / chown / utimes survive inode eviction and remount — the durability
/// D5 closes. Truncate already persisted its own size/extents inside
/// `simple_setattr`; this only stamps mode/owner/times. Mirrors the
/// `persist_inode_xattrs` writeback the xattr ops use. # C: O(1) + 1 journaled
/// inode write
pub(crate) fn ext4_setattr(inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
    if ia.valid & vfs::ATTR_SIZE != 0 {
        return ext4_setattr_size(inode, idmap, ia);
    }
    let old_uid = inode.uid().unwrap_or(0);
    let old_gid = inode.gid().unwrap_or(0);
    let old_mode = inode.i_mode();
    let old_atime = inode.atime().unwrap_or(Timespec64::ZERO);
    let old_mtime = inode.mtime().unwrap_or(Timespec64::ZERO);
    let old_ctime = inode.ctime().unwrap_or(Timespec64::ZERO);
    if ia.valid & (vfs::ATTR_UID | vfs::ATTR_GID) != 0 {
        if let Some((st, ino)) = ext4_state_of(inode) { refresh_cached_usage_from_raw(inode, &st, ino)?; }
    }
    vfs::simple_setattr(inode, idmap, ia)?;
    if let Some((st, ino)) = ext4_state_of(inode) {
        if st.mount.persist_inode_meta(
            ino,
            inode.i_mode(),
            inode.uid().unwrap_or(0),
            inode.gid().unwrap_or(0),
            inode.atime().unwrap_or(Timespec64::ZERO),
            inode.mtime().unwrap_or(Timespec64::ZERO),
            inode.ctime().unwrap_or(Timespec64::ZERO),
        ).is_err() {
            rollback_setattr_inode(inode, old_uid, old_gid, old_mode, old_atime, old_mtime, old_ctime)?;
            return Err(VfsError::Eio);
        }
    }
    Ok(())
}

fn ext4_setattr_size(inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
    let Some((st, ino)) = ext4_state_of(inode) else {
        return vfs::simple_setattr(inode, idmap, ia);
    };
    let old_uid = inode.uid().unwrap_or(0);
    let old_gid = inode.gid().unwrap_or(0);
    let old_mode = inode.i_mode();
    let old_atime = inode.atime().unwrap_or(Timespec64::ZERO);
    let old_mtime = inode.mtime().unwrap_or(Timespec64::ZERO);
    let old_ctime = inode.ctime().unwrap_or(Timespec64::ZERO);
    let raw_before = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?;
    inode.set_blocks(raw_before.i_blocks as u64);
    inode.set_size(raw_before.size);
    let new_uid = if ia.valid & vfs::ATTR_UID != 0 { idmap.map_in_uid(ia.uid) } else { old_uid };
    let new_gid = if ia.valid & vfs::ATTR_GID != 0 { idmap.map_in_gid(ia.gid) } else { old_gid };
    let owner_changed = new_uid != old_uid || new_gid != old_gid;
    if owner_changed {
        let usage = vfs::DquotUsage { space: raw_before.i_blocks.saturating_mul(512), reserved_space: 0, inodes: 1 };
        vfs::dquot_transfer_inode(inode, usage, vfs::DquotTransferIds {
            uid: Some(new_uid),
            gid: Some(new_gid),
            projid: None,
        })?;
        if inode.set_owner(new_uid, new_gid).is_err() {
            let _ = vfs::dquot_transfer_inode(inode, usage, vfs::DquotTransferIds {
                uid: Some(old_uid),
                gid: Some(old_gid),
                projid: None,
            });
            return Err(VfsError::Eio);
        }
        let owner_meta = size_setattr_meta(inode, ia, new_uid, new_gid, old_mode, old_atime, old_mtime, old_ctime);
        if st.mount.persist_inode_meta(
            ino,
            owner_meta.mode,
            owner_meta.uid,
            owner_meta.gid,
            owner_meta.atime,
            owner_meta.mtime,
            owner_meta.ctime,
        ).is_err() {
            rollback_setattr_inode(inode, old_uid, old_gid, old_mode, old_atime, old_mtime, old_ctime)?;
            return Err(VfsError::Eio);
        }
    }
    let meta = size_setattr_meta(inode, ia, new_uid, new_gid, old_mode, old_atime, old_mtime, old_ctime);
    st.mount.truncate_inode_with_meta(ino, ia.size, meta)
        .map_err(super::regular::vfs_error_from_mount)?;
    refresh_after_size_setattr(inode, ino, ia.size);
    let mut rest = *ia;
    rest.valid &= !(vfs::ATTR_SIZE | vfs::ATTR_UID | vfs::ATTR_GID);
    if rest.valid == 0 { return Ok(()); }
    if vfs::simple_setattr(inode, idmap, &rest).is_err() {
        rollback_setattr_inode(inode, old_uid, old_gid, old_mode, old_atime, old_mtime, old_ctime)?;
        return Err(VfsError::Eio);
    }
    Ok(())
}

fn size_setattr_meta(
    inode: &Inode,
    ia: &Iattr,
    uid: u32,
    gid: u32,
    old_mode: u16,
    old_atime: Timespec64,
    old_mtime: Timespec64,
    old_ctime: Timespec64,
) -> InodeMetaUpdate {
    let mut perm = inode.perm().unwrap_or(old_mode & 0o7777);
    if ia.valid & vfs::ATTR_MODE != 0 { perm = ia.mode & 0o7777; }
    if ia.valid & (vfs::ATTR_KILL_SUID | vfs::ATTR_KILL_SGID) != 0 {
        perm = vfs::apply_kill_priv(ia.valid, perm);
    }
    InodeMetaUpdate {
        mode: (old_mode & !0o7777) | (perm & 0o7777),
        uid,
        gid,
        atime: if ia.valid & vfs::ATTR_ATIME != 0 { ia.atime } else { old_atime },
        mtime: if ia.valid & vfs::ATTR_MTIME != 0 { ia.mtime } else { old_mtime },
        ctime: if ia.valid & vfs::ATTR_CTIME != 0 { ia.ctime } else { old_ctime },
    }
}

fn refresh_after_size_setattr(inode: &Inode, ino: u32, new_size: u64) {
    if let Some(d) = inode.private::<Ext4FileData>() {
        d.st.page_cache.invalidate(block::types::InodeId(ino as u64));
        d.frames.invalidate_range(new_size & !(4095u64), u64::MAX);
        #[cfg(feature = "ext4-frame-cache")]
        d.frames.set_size(new_size);
        d.refresh_inode_usage(inode);
    }
}

fn rollback_setattr_inode(
    inode: &Inode,
    old_uid: u32,
    old_gid: u32,
    old_mode: u16,
    old_atime: Timespec64,
    old_mtime: Timespec64,
    old_ctime: Timespec64,
) -> KResult<()> {
    if inode.uid().unwrap_or(0) != old_uid || inode.gid().unwrap_or(0) != old_gid {
        let usage = vfs::DquotUsage { space: inode.blocks().saturating_mul(512), reserved_space: 0, inodes: 1 };
        match vfs::dquot_transfer_inode(inode, usage, vfs::DquotTransferIds {
            uid: Some(old_uid),
            gid: Some(old_gid),
            projid: None,
        }) {
            Ok(()) => {}
            Err(_) => vfs::dquot_transfer_inode(inode, usage, vfs::DquotTransferIds {
                uid: Some(old_uid),
                gid: Some(old_gid),
                projid: None,
            })?,
        }
        inode.set_owner(old_uid, old_gid)?;
    }
    inode.set_perm(old_mode & 0o7777)?;
    inode.set_times(Some(old_atime), Some(old_mtime), old_ctime)
}

fn refresh_cached_usage_from_raw(
    inode: &Inode,
    st: &super::super::state::RootfsState,
    ino: u32,
) -> KResult<()> {
    let raw = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?;
    inode.set_blocks(raw.i_blocks as u64);
    inode.set_size(raw.size);
    Ok(())
}
