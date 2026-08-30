use alloc::vec::Vec;

use crate::inode::{Inode, I_BLOCK_LEN, EXT4_INLINE_DATA_FL};

use super::{Mount, MountError};

/// Read bytes from Linux ext4 inline data.
///
/// `ext4_read_inline_data()` exposes the first `i_block` bytes followed by the
/// `system.data` ibody xattr.  Keep this as the single byte owner: callers must
/// not decode the xattr independently, because the same layout is used by
/// regular files, inline directories, and inline symlinks.  The mount feature
/// gate still refuses inline-data images until the matching mutation,
/// conversion, and lifetime owners exist.
/// # C: O(1) inode read + O(N_xattrs)
pub(crate) fn read_inline_data(
    mount: &Mount, inode: &Inode, byte_off: usize, len: usize,
) -> Result<Vec<u8>, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 {
        return Err(MountError::NotExtents);
    }
    let end = byte_off.checked_add(len).ok_or(MountError::BlockIo)?;
    let size = usize::try_from(inode.size).unwrap_or(usize::MAX);
    if byte_off >= size || len == 0 { return Ok(Vec::new()); }
    let end = end.min(size);
    let (raw, _) = mount.read_inode_bytes(inode.ino)?;
    let mut out = alloc::vec![0u8; end - byte_off];
    let inline_prefix = I_BLOCK_LEN.min(size);
    let mut copied = 0;
    if byte_off < inline_prefix {
        let take = (end - byte_off).min(inline_prefix - byte_off);
        out[..take].copy_from_slice(&raw[0x28 + byte_off..0x28 + byte_off + take]);
        copied += take;
    }
    if byte_off + copied < end {
        let want_start = byte_off.max(inline_prefix) - inline_prefix;
        let want_end = end - inline_prefix;
        let extra = crate::xattr::decode_ibody(
            &raw,
            crate::csum::EXT4_GOOD_OLD_INODE_SIZE
                + ibody_extra_isize(&raw, mount.sb.inode_size as usize),
            mount.sb.inode_size as usize,
        );
        let value = extra.into_iter()
            .find_map(|(name, value)| (name == "system.data").then_some(value))
            .ok_or(MountError::NotFound)?;
        let available_end = want_end.min(value.len());
        if available_end > want_start {
            let dst = byte_off.max(inline_prefix) - byte_off;
            let n = available_end - want_start;
            out[dst..dst + n].copy_from_slice(&value[want_start..available_end]);
        }
    }
    Ok(out)
}

fn ibody_extra_isize(raw: &[u8], inode_size: usize) -> usize {
    if inode_size <= crate::csum::EXT4_GOOD_OLD_INODE_SIZE { return 0; }
    let extra = u16::from_le_bytes([raw[0x80], raw[0x81]]) as usize;
    if crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra + 4 > inode_size { 0 } else { extra }
}
