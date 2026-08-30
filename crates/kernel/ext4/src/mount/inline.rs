use alloc::string::String;
use alloc::vec::Vec;

use crate::dir;
use crate::inode::{Inode, I_BLOCK_LEN, EXT4_INLINE_DATA_FL};

use super::{Mount, MountError};

const INLINE_DOTDOT_BYTES: usize = 4;
const INLINE_DOT_COOKIE: u64 = 12;
const INLINE_DOTDOT_COOKIE: u64 = 24;

/// Read bytes from Linux ext4 inline data.
///
/// `ext4_read_inline_data()` exposes the first `i_block` bytes followed by the
/// `system.data` ibody xattr.  Keep this as the single byte owner: callers must
/// not decode the xattr independently, because the same layout is used by
/// regular files, inline directories, and inline symlinks. The mount feature
/// gate admits the layout only because all three consumers route through this
/// owner or the canonical extent conversion owner.
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
/// inode bytes and the inline payload are journaled together. When the payload
/// exceeds 60 bytes, the tail is stored as Linux's `system.data` ibody xattr.
/// If that xattr cannot fit, the canonical inline-to-extent owner takes over.
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
    if extra == 0 && new_size > I_BLOCK_LEN {
        if inode.is_dir() { return Err(MountError::NotExtents); }
        return mount.convert_inline_data(ino, inode, off as u64, data)
            .map(|()| true);
    }
    if extra != 0 {
        let hdr = crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra;
        let mut entries = crate::xattr::decode_ibody(&raw, hdr, isize);
        entries.retain(|(name, _)| name != "system.data");
        if new_size > I_BLOCK_LEN {
            entries.push((String::from("system.data"), body[I_BLOCK_LEN..].to_vec()));
        }
        if crate::xattr::encode_ibody(&mut raw, hdr, isize, &entries).is_err() {
            if inode.is_dir() { return Err(MountError::NotExtents); }
            return mount.convert_inline_data(ino, inode, off as u64, data).map(|()| true);
        }
    }
    mount.write_inode_bytes(ino, &raw)?;
    Ok(true)
}

fn ibody_extra_isize(raw: &[u8], inode_size: usize) -> usize {
    if inode_size <= crate::csum::EXT4_GOOD_OLD_INODE_SIZE { return 0; }
    let extra = u16::from_le_bytes([raw[0x80], raw[0x81]]) as usize;
    if crate::csum::EXT4_GOOD_OLD_INODE_SIZE + extra + 4 > inode_size { 0 } else { extra }
}

/// Search an inline directory's two dirent regions. Linux reserves the first
/// four bytes of `i_block` for the parent inode and synthesizes `.` and `..`.
/// # C: O(inline directory entries)
pub(crate) fn lookup_inline_dir(
    mount: &Mount, inode: &Inode, name: &[u8],
) -> Result<Option<u32>, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 { return Ok(None); }
    if name == b"." { return Ok(Some(inode.ino)); }
    let body = read_inline_data(mount, inode, 0, inode.size as usize)?;
    if body.len() < INLINE_DOTDOT_BYTES { return Err(MountError::BlockIo); }
    if name == b".." {
        return Ok(Some(u32::from_le_bytes([body[0], body[1], body[2], body[3]])));
    }
    let first_end = body.len().min(I_BLOCK_LEN);
    if first_end > INLINE_DOTDOT_BYTES {
        if let Some(ino) = dir::lookup_bytes(&body[INLINE_DOTDOT_BYTES..first_end], name)
            .map_err(MountError::Dir)? { return Ok(Some(ino)); }
    }
    if body.len() > I_BLOCK_LEN {
        if let Some(ino) = dir::lookup_bytes(&body[I_BLOCK_LEN..], name)
            .map_err(MountError::Dir)? { return Ok(Some(ino)); }
    }
    Ok(None)
}

/// Decode inline directory entries with the byte cookies used by
/// `ext4_read_inline_dir`; `.` and `..` are synthetic, not stored dirents.
/// # C: O(inline directory entries)
pub(crate) fn read_inline_dir_entries(
    mount: &Mount, inode: &Inode,
) -> Result<Vec<(u32, u8, Vec<u8>, u64)>, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 { return Err(MountError::NotExtents); }
    let body = read_inline_data(mount, inode, 0, inode.size as usize)?;
    if body.len() < INLINE_DOTDOT_BYTES { return Err(MountError::BlockIo); }
    let parent = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let mut out = Vec::new();
    out.push((inode.ino, dir::DT_DIR, b".".to_vec(), INLINE_DOT_COOKIE));
    out.push((parent, dir::DT_DIR, b"..".to_vec(), INLINE_DOTDOT_COOKIE));
    let first_end = body.len().min(I_BLOCK_LEN);
    append_inline_dir_entries(&body[INLINE_DOTDOT_BYTES..first_end], INLINE_DOTDOT_COOKIE, &mut out)?;
    if body.len() > I_BLOCK_LEN {
        append_inline_dir_entries(&body[I_BLOCK_LEN..],
            INLINE_DOTDOT_COOKIE + (I_BLOCK_LEN - INLINE_DOTDOT_BYTES) as u64, &mut out)?;
    }
    Ok(out)
}

fn append_inline_dir_entries(
    bytes: &[u8], logical_base: u64, out: &mut Vec<(u32, u8, Vec<u8>, u64)>,
) -> Result<(), MountError> {
    let mut off = 0usize;
    while off < bytes.len() {
        let (entry, next) = dir::next_entry(bytes, off).map_err(MountError::Dir)?;
        if entry.inode != 0 {
            out.push((entry.inode, entry.file_type, entry.name.to_vec(),
                logical_base + next as u64));
        }
        off = next;
    }
    Ok(())
}

/// Insert one dirent into inline storage. `NotExtents` tells the caller to
/// invoke the canonical inline-to-directory-block conversion owner.
/// # C: O(inline directory entries + xattr rewrite)
pub(crate) fn insert_inline_dir(
    mount: &Mount, inode: &Inode, child_ino: u32, file_type: u8, name: &[u8],
) -> Result<bool, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 { return Ok(false); }
    let mut body = read_inline_data(mount, inode, 0, inode.size as usize)?;
    let first_end = body.len().min(I_BLOCK_LEN);
    if first_end > INLINE_DOTDOT_BYTES {
        match dir::insert(&mut body[INLINE_DOTDOT_BYTES..first_end], child_ino, file_type, name) {
            Ok(()) => { write_inline_data(mount, inode.ino, inode, 0, &body)?; return Ok(true); }
            Err(dir::DirError::Full) => {}
            Err(e) => return Err(MountError::Dir(e)),
        }
    }
    if body.len() > I_BLOCK_LEN {
        match dir::insert(&mut body[I_BLOCK_LEN..], child_ino, file_type, name) {
            Ok(()) => { write_inline_data(mount, inode.ino, inode, 0, &body)?; return Ok(true); }
            Err(dir::DirError::Full) => {}
            Err(e) => return Err(MountError::Dir(e)),
        }
    }
    let grow = dir::entry_actual_len(name.len() as u8);
    let old_len = body.len();
    write_inline_data(mount, inode.ino, inode, old_len as u64, &alloc::vec![0u8; grow])?;
    let current = mount.read_inode(inode.ino)?;
    body = read_inline_data(mount, &current, 0, current.size as usize)?;
    if body.len() <= I_BLOCK_LEN { return Err(MountError::NotExtents); }
    let tail = &mut body[I_BLOCK_LEN..];
    if old_len <= I_BLOCK_LEN {
        if tail.len() < 8 { return Err(MountError::NotExtents); }
        let tail_len = tail.len() as u16;
        tail[0..4].copy_from_slice(&0u32.to_le_bytes());
        tail[4..6].copy_from_slice(&tail_len.to_le_bytes());
        tail[6] = 0;
        tail[7] = 0;
    } else {
        let mut off = 0usize;
        let mut last = 0usize;
        let old_tail_len = old_len - I_BLOCK_LEN;
        while off < old_tail_len {
            let (_, next) = dir::next_entry(&tail[..old_tail_len], off).map_err(MountError::Dir)?;
            last = off;
            off = next;
        }
        let rec = u16::from_le_bytes([tail[last + 4], tail[last + 5]]) as usize;
        let new_rec = rec.checked_add(grow).ok_or(MountError::NotExtents)?;
        tail[last + 4..last + 6].copy_from_slice(&(new_rec as u16).to_le_bytes());
    }
    dir::insert(tail, child_ino, file_type, name).map_err(MountError::Dir)?;
    write_inline_data(mount, current.ino, &current, 0, &body)?;
    Ok(true)
}

/// Delete one non-dot inline dirent. `None` is the not-inline result and
/// `Some(None)` is an inline miss; callers use the inode flag to distinguish.
/// # C: O(inline directory entries + xattr rewrite)
pub(crate) fn remove_inline_dir(
    mount: &Mount, inode: &Inode, name: &[u8],
) -> Result<Option<u32>, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 { return Ok(None); }
    if name == b"." || name == b".." { return Ok(Some(0)); }
    let mut body = read_inline_data(mount, inode, 0, inode.size as usize)?;
    let first_end = body.len().min(I_BLOCK_LEN);
    if first_end > INLINE_DOTDOT_BYTES {
        match dir::remove(&mut body[INLINE_DOTDOT_BYTES..first_end], name) {
            Ok(ino) => { write_inline_data(mount, inode.ino, inode, 0, &body)?; return Ok(Some(ino)); }
            Err(dir::DirError::NotFound) => {}
            Err(e) => return Err(MountError::Dir(e)),
        }
    }
    if body.len() > I_BLOCK_LEN {
        match dir::remove(&mut body[I_BLOCK_LEN..], name) {
            Ok(ino) => { write_inline_data(mount, inode.ino, inode, 0, &body)?; return Ok(Some(ino)); }
            Err(dir::DirError::NotFound) => {}
            Err(e) => return Err(MountError::Dir(e)),
        }
    }
    Ok(Some(0))
}

pub(crate) fn set_dotdot_inline(
    mount: &Mount, inode: &Inode, parent: u32,
) -> Result<bool, MountError> {
    if inode.i_flags & EXT4_INLINE_DATA_FL == 0 { return Ok(false); }
    let mut body = read_inline_data(mount, inode, 0, inode.size as usize)?;
    if body.len() < INLINE_DOTDOT_BYTES { return Err(MountError::BlockIo); }
    body[0..4].copy_from_slice(&parent.to_le_bytes());
    write_inline_data(mount, inode.ino, inode, 0, &body)?;
    Ok(true)
}
