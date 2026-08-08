use crate::inode::{InodeError, S_IFDIR, S_IFMT, S_IFREG};
use crate::mount::{Mount, MountError};
use vfs::inode::FS_PROJINHERIT_FL;

const OFF_FLAGS: usize = 0x20;
const OFF_PROJID: usize = 0x9C;
use crate::inode::flags::{EXT4_NODUMP_FL, EXT4_NOATIME_FL, EXT4_SYNC_FL};
const EXT4_FL_INHERITED: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004
    | EXT4_SYNC_FL | EXT4_NODUMP_FL | EXT4_NOATIME_FL | 0x0000_0400
    | 0x0000_4000 | 0x0000_8000 | 0x0001_0000 | FS_PROJINHERIT_FL
    | 0x4000_0000 | 0x0200_0000;
const EXT4_REG_INHERIT_DROP: u32 = 0x0001_0000 | 0x0002_0000 | 0x4000_0000
    | FS_PROJINHERIT_FL;

impl Mount {
    /// Linux `ext4_new_inode`: inherit `EXT4_FL_INHERITED` through
    /// `ext4_mask_flags`, and inherit `i_projid` only from a project-enabled
    /// parent carrying `FS_PROJINHERIT_FL`. # C: O(1) inode read
    pub(crate) fn inherit_inode_flags_project(
        &self,
        parent_ino: u32,
        mode: u16,
        bytes: &mut [u8],
    ) -> Result<(), MountError> {
        let parent = self.read_inode(parent_ino)?;
        let inherited = ext4_mask_flags(mode, parent.i_flags & EXT4_FL_INHERITED);
        let cur = u32::from_le_bytes(bytes[OFF_FLAGS..OFF_FLAGS + 4].try_into()
            .map_err(|_| MountError::Inode(InodeError::BadLen))?);
        bytes[OFF_FLAGS..OFF_FLAGS + 4].copy_from_slice(&(cur | inherited).to_le_bytes());
        if self.sb.has_project()
            && parent.i_flags & FS_PROJINHERIT_FL != 0
            && bytes.len() >= OFF_PROJID + 4
        {
            bytes[OFF_PROJID..OFF_PROJID + 4].copy_from_slice(&parent.i_projid.to_le_bytes());
        }
        Ok(())
    }
}

fn ext4_mask_flags(mode: u16, flags: u32) -> u32 {
    let ftype = mode & S_IFMT;
    if ftype == S_IFDIR { flags }
    else if ftype == S_IFREG { flags & !EXT4_REG_INHERIT_DROP }
    else { flags & (EXT4_NODUMP_FL | EXT4_NOATIME_FL) }
}
