use super::uapi::{REMAP_FILE_CAN_SHORTEN, REMAP_FILE_DEDUP};

pub(super) fn vfs_clone_file_range(src: &vfs::File, src_off: u64, dst: &vfs::File, dst_off: u64, mut len: u64, flags: u32) -> vfs::KResult<u64> {
    if !same_superblock(src, dst) { return Err(vfs::VfsError::Exdev); }
    generic_file_rw_checks(src, dst)?;
    if !src.supports_remap_file_range() { return Err(vfs::VfsError::Eopnotsupp); }
    if flags & REMAP_FILE_DEDUP == 0 {
        let size = src.inode().size();
        if len == 0 {
            if src_off == size { return Ok(0); }
            if src_off > size { return Err(vfs::VfsError::Einval); }
            len = size - src_off;
        } else if src_off >= size {
            return Err(vfs::VfsError::Einval);
        } else if src_off.checked_add(len).is_none_or(|end| end > size)
            && flags & REMAP_FILE_CAN_SHORTEN == 0 {
            return Err(vfs::VfsError::Einval);
        }
    }
    remap_verify_area(src_off, len)?;
    remap_verify_area(dst_off, len)?;
    remap_verify_alignment(dst, src_off, dst_off)?;
    remap_verify_unshortenable_len(src, dst, src_off, len, flags)?;
    remap_verify_partial_eof_len(dst, dst_off, len, flags)?;
    if same_inode(src, dst) && ranges_overlap(src_off, dst_off, len) {
        return Err(vfs::VfsError::Einval);
    }
    src.remap_file_range(src_off, dst, dst_off, len, flags)
}

pub(super) fn vfs_dedupe_file_range_one(cur: &sched::Task, src: &vfs::File, src_off: u64, dst: &vfs::File, dst_off: u64, mut len: u64) -> vfs::KResult<()> {
    remap_verify_area(src_off, len)?;
    remap_verify_area(dst_off, len)?;
    if !may_dedupe_file(cur, dst) { return Err(vfs::VfsError::Eperm); }
    if !same_superblock(src, dst) { return Err(vfs::VfsError::Exdev); }
    if dst.inode().file_type() == vfs::FileType::Directory { return Err(vfs::VfsError::Eisdir); }
    if !dst.supports_remap_file_range() { return Err(vfs::VfsError::Einval); }
    if len == 0 { return Ok(()); }
    remap_verify_alignment(dst, src_off, dst_off)?;
    if dst_off.checked_add(len).is_none_or(|end| dst_off >= dst.inode().size() || end > dst.inode().size()) {
        return Err(vfs::VfsError::Einval);
    }
    if same_inode(src, dst) && ranges_overlap(src_off, dst_off, len) {
        return Err(vfs::VfsError::Einval);
    }
    remap_shorten_partial_eof_len(src, dst, dst_off, &mut len, REMAP_FILE_CAN_SHORTEN | REMAP_FILE_DEDUP)?;
    match src.remap_file_range(src_off, dst, dst_off, len, REMAP_FILE_CAN_SHORTEN | REMAP_FILE_DEDUP) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

fn generic_file_rw_checks(src: &vfs::File, dst: &vfs::File) -> vfs::KResult<()> {
    if src.inode().file_type() == vfs::FileType::Directory || dst.inode().file_type() == vfs::FileType::Directory {
        return Err(vfs::VfsError::Eisdir);
    }
    if src.inode().file_type() != vfs::FileType::Regular || dst.inode().file_type() != vfs::FileType::Regular {
        return Err(vfs::VfsError::Einval);
    }
    if !src.f_mode().contains(vfs::Fmode::READ)
        || !dst.f_mode().contains(vfs::Fmode::WRITE)
        || dst.flags().contains(vfs::OpenFlags::O_APPEND)
    {
        return Err(vfs::VfsError::Ebadf);
    }
    Ok(())
}

pub(super) fn remap_verify_area(pos: u64, len: u64) -> vfs::KResult<()> {
    match pos.checked_add(len) {
        Some(_) => Ok(()),
        None => Err(vfs::VfsError::Einval),
    }
}

fn remap_verify_alignment(dst: &vfs::File, src_off: u64, dst_off: u64) -> vfs::KResult<()> {
    let bs = dst.inode().i_sb().map(|sb| sb.s_blocksize as u64).filter(|bs| *bs != 0).unwrap_or(1);
    if src_off % bs != 0 || dst_off % bs != 0 { return Err(vfs::VfsError::Einval); }
    Ok(())
}

fn remap_verify_unshortenable_len(src: &vfs::File, dst: &vfs::File, src_off: u64, len: u64, flags: u32) -> vfs::KResult<()> {
    if len == 0 || flags & REMAP_FILE_CAN_SHORTEN != 0 { return Ok(()); }
    let bs = dst.inode().i_sb().map(|sb| sb.s_blocksize as u64).filter(|bs| *bs != 0).unwrap_or(1);
    if len % bs == 0 || src_off.checked_add(len) == Some(src.inode().size()) { return Ok(()); }
    Err(vfs::VfsError::Einval)
}

fn remap_verify_partial_eof_len(dst: &vfs::File, dst_off: u64, len: u64, flags: u32) -> vfs::KResult<()> {
    if len == 0 || flags & REMAP_FILE_CAN_SHORTEN != 0 { return Ok(()); }
    let bs = dst.inode().i_sb().map(|sb| sb.s_blocksize as u64).filter(|bs| *bs != 0).unwrap_or(1);
    if len % bs != 0 && dst_off.checked_add(len).is_some_and(|end| end < dst.inode().size()) { return Err(vfs::VfsError::Einval); }
    Ok(())
}

fn remap_shorten_partial_eof_len(src: &vfs::File, dst: &vfs::File, dst_off: u64, len: &mut u64, flags: u32) -> vfs::KResult<()> {
    let bs = src.inode().i_sb().map(|sb| sb.s_blocksize as u64).filter(|bs| *bs != 0).unwrap_or(1);
    let mask = bs - 1;
    if *len & mask == 0 { return Ok(()); }
    let mut new_len = *len;
    if dst_off.checked_add(*len).is_some_and(|end| end < dst.inode().size()) { new_len &= !mask; }
    if new_len == *len { return Ok(()); }
    if flags & REMAP_FILE_CAN_SHORTEN != 0 {
        *len = new_len;
        return Ok(());
    }
    if flags & REMAP_FILE_DEDUP != 0 { return Err(vfs::VfsError::Ebade); }
    Err(vfs::VfsError::Einval)
}

fn may_dedupe_file(cur: &sched::Task, file: &vfs::File) -> bool {
    if cur.has_cap(sched::cap::SYS_ADMIN) { return true; }
    if file.f_mode().contains(vfs::Fmode::WRITE) { return true; }
    let cred = dedupe_cred(cur);
    if file.inode().uid() == Some(cred.uid) { return true; }
    vfs::inode_permission(file.inode(), vfs::MAY_WRITE, &cred).is_ok()
}

fn same_superblock(a: &vfs::File, b: &vfs::File) -> bool {
    match (a.inode().i_sb(), b.inode().i_sb()) {
        (Some(x), Some(y)) => alloc::sync::Arc::ptr_eq(&x, &y),
        (None, None) => true,
        _ => false,
    }
}

fn same_inode(a: &vfs::File, b: &vfs::File) -> bool {
    alloc::sync::Arc::ptr_eq(a.inode(), b.inode())
}

fn ranges_overlap(a: u64, b: u64, len: u64) -> bool {
    len != 0 && a < b.saturating_add(len) && b < a.saturating_add(len)
}

#[cfg(not(test))]
fn dedupe_cred(_cur: &sched::Task) -> vfs::Cred {
    crate::pathresolve::current_cred()
}

#[cfg(test)]
fn dedupe_cred(cur: &sched::Task) -> vfs::Cred {
    use core::sync::atomic::Ordering;
    let effective = cur.creds.cap_effective.load(Ordering::Acquire);
    cur.creds.to_vfs_cred(cur.creds.fsuid.load(Ordering::Acquire),
        cur.creds.fsgid.load(Ordering::Acquire), effective)
}
