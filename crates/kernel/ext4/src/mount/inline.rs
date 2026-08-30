use alloc::string::String;
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

/// Update an inline inode while it still fits in its inode and ibody xattr.
///
/// This is the first mutation leg of Linux `ext4_write_inline_data`: the
/// inode bytes and the inline payload are journaled together. Growth beyond
/// When the payload exceeds 60 bytes, the tail is stored as Linux's
/// `system.data` ibody xattr. If the complete xattr set does not fit, growth
/// is deliberately refused until the ext4 inline-to-extent conversion owner
/// exists; callers must not reinterpret the inline inode as an extent root.
pub(crate) fn write_inline_data(
    mount: &Mount, ino: u32, inode: &Inode, off: u64, data: &[u8],
) -> Result<bool, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 { return Ok(false); }
    let off = usize::try_from(off).map_err(|_| MountError::BlockIo)?;
    let end = off.checked_add(data.len()).ok_or(MountError::BlockIo)?;
    let size = usize::try_from(inode.size).unwrap_or(usize::MAX);
    let new_size = size.max(end);
    let mut body = alloc::vec![0u8; new_size];
    if size != 0 {
        let old = read_inline_data(mount, inode, 0, size)?;
        body[..old.len()].copy_from_slice(&old);
    }
    body[off..end].copy_from_slice(data);
    let (mut raw, _) = mount.read_inode_bytes(ino)?;
    raw[0x28..0x28 + I_BLOCK_LEN].fill(0);
    let prefix = body.len().min(I_BLOCK_LEN);
    raw[0x28..0x28 + prefix].copy_from_slice(&body[..prefix]);
    raw[0x04..0x08].copy_from_slice(&(new_size as u32).to_le_bytes());
    raw[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
    let isize = mount.sb.inode_size as usize;
    let extra = ibody_extra_isize(&raw, isize);
    if extra == 0 && new_size > I_BLOCK_LEN { return Err(MountError::NotExtents); }
    if extra != 0 {
        let hdr = crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra;
        let mut entries = crate::xattr::decode_ibody(&raw, hdr, isize);
        entries.retain(|(name, _)| name != "system.data");
        if new_size > I_BLOCK_LEN {
            entries.push((String::from("system.data"), body[I_BLOCK_LEN..].to_vec()));
        }
        crate::xattr::encode_ibody(&mut raw, hdr, isize, &entries)
            .map_err(|_| MountError::NotExtents)?;
    }
    mount.write_inode_bytes(ino, &raw)?;
    Ok(true)
}

fn ibody_extra_isize(raw: &[u8], inode_size: usize) -> usize {
    if inode_size <= crate::csum::EXT4_GOOD_OLD_INODE_SIZE { return 0; }
    let extra = u16::from_le_bytes([raw[0x80], raw[0x81]]) as usize;
    if crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra + 4 > inode_size { 0 } else { extra }
}
