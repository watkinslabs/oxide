use vfs::idmap::Idmap;
use vfs::inode::FS_PROJINHERIT_FL;
use vfs::{FileAttr, Iattr, Inode, KResult, VfsError};

use super::data::ext4_state_of;

// ext4 on-disk `i_flags` (@0x20) bits — IDENTICAL to the `FS_*_FL` chattr view.
const EXT4_SYNC_FL:      u32 = 0x0000_0008;
const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
const EXT4_APPEND_FL:    u32 = 0x0000_0020;
const EXT4_NOATIME_FL:   u32 = 0x0000_0080;
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
    Ok(FileAttr {
        flags,
        fsx_projid: if st.mount.sb.has_project() { raw.i_projid } else { 0 },
        ..Default::default()
    })
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
    let ctime_ns = vfs::inode_times::current_time(inode, raw);
    vfs::inode::inode_inc_iversion(inode);
    st.mount.persist_inode_generation(ino, gen, ctime_ns).map_err(|_| VfsError::Eio)?;
    inode.set_times(None, None, ctime_ns)
}

/// `ext4_fileattr_set` — the `FS_IOC_SETFLAGS` backend: fold the user-modifiable
/// bits of `fa.flags` over the preserved kernel-internal flags, persist to the
/// on-disk inode (journaled), and mirror IMMUTABLE/APPEND/NOATIME/SYNC into the
/// in-core VFS `i_flags` so `may_open`/`notify_change` enforce them at once.
/// # C: O(1) + one journaled inode write
pub(crate) fn ext4_fileattr_set(inode: &Inode, fa: &FileAttr) -> KResult<()> {
    let (st, ino) = ext4_state_of(inode).ok_or(VfsError::Eio)?;
    if inode.file_type() == vfs::FileType::Regular && fa.flags & EXT4_PROJINHERIT_FL != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    if fa.flags & !FS_FL_USER_VISIBLE != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    let cur = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?.i_flags;
    let new = (cur & !FS_FL_USER_MODIFIABLE) | (fa.flags & FS_FL_USER_MODIFIABLE);
    ext4_ioctl_check_immutable(&st, ino, cur, fa.fsx_projid, new)?;
    if (cur ^ new) & EXT4_EXTENTS_FL != 0 {
        return Err(VfsError::Eopnotsupp);
    }
    st.mount.persist_inode_flags(ino, new).map_err(|_| VfsError::Eio)?;
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
    let raw_now = vfs::inode_times::realtime_now_ns();
    let ctime_ns = vfs::inode_times::current_time(inode, raw_now);
    st.mount.persist_inode_project(ino, projid, ctime_ns).map_err(|_| VfsError::Eio)?;
    inode.set_times(None, None, ctime_ns)
}

/// `ext4_setattr` (Linux `fs/ext4/inode.c`): the `i_op->setattr` for every
/// ext4 inode. Apply the prepared `ia` to the in-core inode via the generic
/// `simple_setattr` (mode / owner / times / truncate + suid-kill fold), then
/// write the mutated metadata THROUGH to the on-disk inode (journaled), so
/// chmod / chown / utimes survive inode eviction and remount — the durability
/// D5 closes. Truncate already persisted its own size/extents inside
/// `simple_setattr`; this only stamps mode/owner/times. Mirrors the
/// `persist_inode_xattrs` writeback the xattr ops use. # C: O(1) + 1 journaled
/// inode write
pub(crate) fn ext4_setattr(inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
    vfs::simple_setattr(inode, idmap, ia)?;
    if let Some((st, ino)) = ext4_state_of(inode) {
        st.mount.persist_inode_meta(
            ino,
            inode.i_mode(),
            inode.uid().unwrap_or(0),
            inode.gid().unwrap_or(0),
            inode.atime().unwrap_or(0),
            inode.mtime().unwrap_or(0),
            inode.ctime().unwrap_or(0),
        ).map_err(|_| VfsError::Eio)?;
    }
    Ok(())
}
