use alloc::sync::Arc;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError};

/// Backend-private state (`i_private`) for a vcs inode: `with_attr` selects
/// `/dev/vcsa` (text+attr) over `/dev/vcs` (text). # C: O(1)
pub struct VcsData {
    with_attr: bool,
}

struct VcsFileOps;

impl FileOps for VcsFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let with_attr = inode
            .private::<VcsData>()
            .ok_or(VfsError::Einval)?
            .with_attr;
        let data = fbcon::kernel::screen_dump(with_attr);
        let off = off as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    fn write(&self, _i: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }
}

pub fn make_vcs_inode(attr: bool) -> InodeRef {
    let ino: Ino = if attr { crate::ids::VCSA_INO } else { crate::ids::VCS_INO };
    InodeBuilder::new(
        ino,
        mk_mode(FileType::CharDev, 0o644),
        default_inode_ops(),
        Arc::new(VcsFileOps),
    )
    .fsid(devfs::DEVFS_FSID)
    .rdev(crate::devnum::vcs_rdev(attr))
    .private(Arc::new(VcsData { with_attr: attr }))
    .build()
}
