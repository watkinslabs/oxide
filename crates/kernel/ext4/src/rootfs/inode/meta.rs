use vfs::idmap::Idmap;
use vfs::inode::FS_PROJINHERIT_FL;
use vfs::{FileAttr, Iattr, Inode, KResult, VfsError};

use super::data::ext4_state_of;

// ext4 on-disk `i_flags` (@0x20) bits — IDENTICAL to the `FS_*_FL` chattr view.
const EXT4_SYNC_FL:      u32 = 0x0000_0008;
const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
const EXT4_APPEND_FL:    u32 = 0x0000_0020;
const EXT4_NOATIME_FL:   u32 = 0x0000_0080;
const EXT4_PROJINHERIT_FL: u32 = FS_PROJINHERIT_FL;
/// `lsattr`-visible flags (Linux `FS_FL_USER_VISIBLE`).
const FS_FL_USER_VISIBLE:    u32 = 0x0003_DFFF | EXT4_PROJINHERIT_FL;
/// `chattr`-settable flags (Linux `FS_FL_USER_MODIFIABLE`); everything else
/// (EXTENTS_FL 0x80000, INLINE_DATA_FL, HUGE_FILE, …) is preserved.
const FS_FL_USER_MODIFIABLE: u32 = 0x0003_80FF | EXT4_PROJINHERIT_FL;

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
    let cur = st.mount.read_inode(ino).map_err(|_| VfsError::Eio)?.i_flags;
    let new = (cur & !FS_FL_USER_MODIFIABLE) | (fa.flags & FS_FL_USER_MODIFIABLE);
    st.mount.persist_inode_flags(ino, new).map_err(|_| VfsError::Eio)?;
    let mut s = inode.i_flags()
        & !(vfs::S_IMMUTABLE | vfs::S_APPEND | vfs::S_NOATIME | vfs::S_SYNC);
    if new & EXT4_IMMUTABLE_FL != 0 { s |= vfs::S_IMMUTABLE; }
    if new & EXT4_APPEND_FL    != 0 { s |= vfs::S_APPEND; }
    if new & EXT4_NOATIME_FL   != 0 { s |= vfs::S_NOATIME; }
    if new & EXT4_SYNC_FL      != 0 { s |= vfs::S_SYNC; }
    inode.set_i_flags(s);
    ext4_fileattr_setproject(&st, fa.fsx_projid)?;
    Ok(())
}

fn ext4_fileattr_setproject(st: &super::super::state::RootfsState, projid: u32) -> KResult<()> {
    if !st.mount.sb.has_project() {
        return if projid == 0 { Ok(()) } else { Err(VfsError::Eopnotsupp) };
    }
    Err(VfsError::Eopnotsupp)
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
