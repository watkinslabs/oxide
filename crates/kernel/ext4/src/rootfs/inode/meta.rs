use vfs::idmap::Idmap;
use vfs::{Iattr, Inode, KResult, VfsError};

use super::data::ext4_state_of;

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
