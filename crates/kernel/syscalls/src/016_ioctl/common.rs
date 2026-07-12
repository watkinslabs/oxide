use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

use super::uapi::*;

const INODE_BLOCK_BYTES: u64 = 512;

/// Linux `do_vfs_ioctl` common cases that run before driver/file-specific
/// `unlocked_ioctl`. # C: O(1)
pub(super) fn handle_common_ioctl(
    cur: &sched::Task,
    file: &alloc::sync::Arc<vfs::File>,
    fdt: &alloc::sync::Arc<vfs::FdTable>,
    fd: i32,
    req: u64,
    arg: u64,
) -> Option<i64> {
    match req {
        FIOCLEX => Some(match fdt.set_cloexec(fd, true) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        }),
        FIONCLEX => Some(match fdt.set_cloexec(fd, false) {
            Ok(()) => 0,
            Err(e) => -(e as i64),
        }),
        FIONBIO => Some(ioctl_fionbio(file, arg)),
        FIOASYNC => Some(ioctl_fioasync(file, fd, arg)),
        FIOQSIZE => Some(ioctl_fioqsize(file, arg)),
        FIGETBSZ => Some(ioctl_figetbsz(file, arg)),
        FICLONE => Some(ioctl_file_clone(file, fdt, arg as i64, 0, 0, 0)),
        FICLONERANGE => Some(ioctl_file_clone_range(file, fdt, arg)),
        FIDEDUPERANGE => Some(ioctl_file_dedupe_range(cur, file, fdt, arg)),
        FIBMAP if file.inode().file_type() == vfs::FileType::Regular => Some(ioctl_fibmap(cur, file, arg)),
        FS_IOC_RESVSP | FS_IOC_RESVSP64 if file.inode().file_type() == vfs::FileType::Regular => {
            Some(ioctl_preallocate(file, 0, arg))
        }
        FS_IOC_UNRESVSP | FS_IOC_UNRESVSP64 if file.inode().file_type() == vfs::FileType::Regular => {
            Some(ioctl_preallocate(file, FALLOC_FL_PUNCH_HOLE, arg))
        }
        FS_IOC_ZERO_RANGE if file.inode().file_type() == vfs::FileType::Regular => {
            Some(ioctl_preallocate(file, FALLOC_FL_ZERO_RANGE, arg))
        }
        FS_IOC_GETFLAGS => Some(super::fileattr::ioctl_getflags(file, arg)),
        FS_IOC_SETFLAGS => Some(super::fileattr::ioctl_setflags(cur, file, arg)),
        FS_IOC_FSGETXATTR => Some(super::fileattr::ioctl_fsgetxattr(file, arg)),
        FS_IOC_FSSETXATTR => Some(super::fileattr::ioctl_fssetxattr(cur, file, arg)),
        FS_IOC_GETFSUUID => Some(ioctl_getfsuuid(file, arg)),
        FS_IOC_GETFSSYSFSPATH => Some(ioctl_getfssysfspath(file, arg)),
        FIONREAD if file.inode().file_type() == vfs::FileType::Regular => {
            Some(ioctl_regular_fionread(file, arg))
        }
        _ => None,
    }
}

/// Socket/pipe queue-count ioctls used after regular-file common handling.
/// # C: O(1)
pub(super) fn handle_nonchar_queue_ioctl(file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    let cmd = match req {
        FIONREAD => vfs::IoctlIntCmd::Fionread,
        SIOCOUTQ => vfs::IoctlIntCmd::Siocoutq,
        _ => return None,
    };
    let n = match file.ioctl_int(cmd) {
        Ok(n) => n,
        Err(e) => return Some(-(e as i64)),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return Some(rv); }
    // SAFETY: arg validated writable for one Linux int out-param.
    unsafe { core::ptr::write_volatile(arg as *mut u32, n); }
    Some(0)
}

/// Linux `ioctl_fionbio`: read caller int and toggle `O_NONBLOCK`. # C: O(1)
fn ioctl_fionbio(file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated readable for one Linux int input.
    let on = unsafe { core::ptr::read_volatile(arg as *const i32) } != 0;
    let mut fl = file.flags();
    if on { fl |= vfs::OpenFlags::O_NONBLOCK; } else { fl &= !vfs::OpenFlags::O_NONBLOCK; }
    file.set_fl(fl);
    0
}

/// Linux `ioctl_fioasync`: read caller int and toggle `FASYNC`. # C: O(1)
fn ioctl_fioasync(file: &alloc::sync::Arc<vfs::File>, fd: i32, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated readable for one Linux int input.
    let on = unsafe { core::ptr::read_volatile(arg as *const i32) } != 0;
    if file.is_async() == on { return 0; }
    match file.fasync(fd, on) {
        Ok(()) => {
            if on { install_sigio_hook(); }
            0
        }
        Err(e) => -(e as i64),
    }
}

/// Kernel target wires SIGIO delivery before adding the file to fasync. Hosted
/// tests do not build `sched::live`, but still exercise the flag/registry path.
/// # C: O(1)
#[cfg(not(test))]
fn install_sigio_hook() {
    sched::live::sigpend::install_sigio_hook();
}

/// # C: O(1)
#[cfg(test)]
fn install_sigio_hook() {}

/// Linux `FIOQSIZE`: dirs, regular files, and symlinks copy `loff_t` bytes.
/// # C: O(1)
fn ioctl_fioqsize(file: &vfs::File, arg: u64) -> i64 {
    match file.inode().file_type() {
        vfs::FileType::Directory | vfs::FileType::Regular | vfs::FileType::Symlink => {}
        _ => return -(Errno::Enotty.as_i32() as i64),
    }
    if let Err(rv) = validate_user_buf_writable(arg, LOFF_BYTES, 1) { return rv; }
    let bytes = file.inode().blocks() * INODE_BLOCK_BYTES;
    // SAFETY: arg validated writable for one Linux loff_t out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i64, bytes as i64); }
    0
}

/// Linux `FIGETBSZ`: copy superblock `s_blocksize`, or `EINVAL` if absent.
/// # C: O(1)
fn ioctl_figetbsz(file: &vfs::File, arg: u64) -> i64 {
    let bs = match file.inode().i_sb() {
        Some(sb) if sb.s_blocksize != 0 => sb.s_blocksize,
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated writable for one Linux int out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i32, bs as i32); }
    0
}

/// Linux `FICLONERANGE`: copy `struct file_clone_range`, then clone. # C: FS-dependent
fn ioctl_file_clone_range(file: &alloc::sync::Arc<vfs::File>, fdt: &vfs::FdTable, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, FILE_CLONE_RANGE_BYTES, 1) { return rv; }
    let src_fd = read_i64(arg);
    let src_off = read_u64(arg + 8);
    let src_len = read_u64(arg + 16);
    let dst_off = read_u64(arg + 24);
    ioctl_file_clone(file, fdt, src_fd, src_off, src_len, dst_off)
}

/// Linux `ioctl_file_clone`: fd lookup plus `vfs_clone_file_range`. # C: FS-dependent
fn ioctl_file_clone(file: &alloc::sync::Arc<vfs::File>, fdt: &vfs::FdTable, src_fd: i64, src_off: u64, src_len: u64, dst_off: u64) -> i64 {
    let src_fd = match i32::try_from(src_fd) {
        Ok(fd) => fd,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let src = match fdt.get(src_fd) {
        Ok(f) => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    match vfs_clone_file_range(&src, src_off, file, dst_off, src_len, 0) {
        Ok(done) if src_len != 0 && done != src_len => -(Errno::Einval.as_i32() as i64),
        Ok(_) => 0,
        Err(e) => -(e as i64),
    }
}

fn vfs_clone_file_range(src: &vfs::File, src_off: u64, dst: &vfs::File, dst_off: u64, mut len: u64, flags: u32) -> vfs::KResult<u64> {
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
    if same_inode(src, dst) && ranges_overlap(src_off, dst_off, len) {
        return Err(vfs::VfsError::Einval);
    }
    src.remap_file_range(src_off, dst, dst_off, len, flags)
}

/// Linux `FIDEDUPERANGE`: variable-length input with per-destination status. # C: FS-dependent
fn ioctl_file_dedupe_range(cur: &sched::Task, file: &vfs::File, fdt: &vfs::FdTable, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, DEDUPE_RANGE_BYTES, 1) { return rv; }
    let count = read_u16(arg + DEDUPE_DEST_COUNT) as usize;
    let size = DEDUPE_RANGE_BYTES + count as u64 * DEDUPE_INFO_BYTES;
    if size > PAGE_BYTES { return -(Errno::Enomem.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_readable(arg, size, 1) { return rv; }
    let src_off = read_u64(arg + DEDUPE_SRC_OFFSET);
    let src_len_in = read_u64(arg + DEDUPE_SRC_LENGTH);
    if !file.f_mode().contains(vfs::Fmode::READ) { return -(Errno::Einval.as_i32() as i64); }
    if read_u16(arg + DEDUPE_RESERVED1) != 0 || read_u32(arg + DEDUPE_RESERVED2) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    match file.inode().file_type() {
        vfs::FileType::Directory => return -(Errno::Eisdir.as_i32() as i64),
        vfs::FileType::Regular => {}
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    if !file.supports_remap_file_range() { return -(Errno::Eopnotsupp.as_i32() as i64); }
    if let Err(e) = remap_verify_area(src_off, src_len_in) { return -(e as i64); }
    if src_off.checked_add(src_len_in).is_none_or(|end| end > file.inode().size()) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let len = core::cmp::min(src_len_in, 1 << 30);
    if let Err(rv) = validate_user_buf_writable(arg, size, 1) { return rv; }
    for i in 0..count {
        let base = arg + DEDUPE_RANGE_BYTES + i as u64 * DEDUPE_INFO_BYTES;
        write_u64(base + DEDUPE_INFO_BYTES_DEDUPED, 0);
        write_i32(base + DEDUPE_INFO_STATUS, FILE_DEDUPE_RANGE_SAME);
    }
    for i in 0..count {
        let base = arg + DEDUPE_RANGE_BYTES + i as u64 * DEDUPE_INFO_BYTES;
        let dst_fd = read_i64(base + DEDUPE_INFO_DEST_FD);
        let status = match i32::try_from(dst_fd).ok().and_then(|fd| fdt.get(fd).ok()) {
            None => -(Errno::Ebadf.as_i32()),
            Some(_) if read_u32(base + DEDUPE_INFO_RESERVED) != 0 => -(Errno::Einval.as_i32()),
            Some(dst) => match vfs_dedupe_file_range_one(cur, file, src_off, &dst, read_u64(base + DEDUPE_INFO_DEST_OFFSET), len) {
                Ok(()) => {
                    write_u64(base + DEDUPE_INFO_BYTES_DEDUPED, len);
                    FILE_DEDUPE_RANGE_SAME
                }
                Err(vfs::VfsError::Ebade) => FILE_DEDUPE_RANGE_DIFFERS,
                Err(e) => -(e as i32),
            },
        };
        write_i32(base + DEDUPE_INFO_STATUS, status);
    }
    0
}

fn vfs_dedupe_file_range_one(cur: &sched::Task, src: &vfs::File, src_off: u64, dst: &vfs::File, dst_off: u64, len: u64) -> vfs::KResult<()> {
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

fn remap_verify_area(pos: u64, len: u64) -> vfs::KResult<()> {
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

/// Linux regular-file `FIONREAD`: `i_size - f_pos` copied as an int. # C: O(1)
fn ioctl_regular_fionread(file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    let n = (file.inode().size() as i64).saturating_sub(file.pos() as i64) as i32;
    // SAFETY: arg validated writable for one Linux int out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i32, n); }
    0
}

/// Linux `FIBMAP`: capability-gated logical block to disk block query. # C: FS-dependent
fn ioctl_fibmap(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if !cur.has_cap(sched::cap::SYS_RAWIO) { return -(Errno::Eperm.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated readable for one Linux int in/out-param.
    let logical = unsafe { core::ptr::read_volatile(arg as *const i32) };
    if logical < 0 { return -(Errno::Einval.as_i32() as i64); }
    let mapped = file.inode().bmap(logical as u64);
    let (out, rv) = match mapped {
        Ok(block) if block <= i32::MAX as u64 => (block as i32, 0),
        Ok(_) => (0, -(Errno::Erange.as_i32() as i64)),
        Err(e) => (0, -(e as i64)),
    };
    if let Err(fault) = validate_user_buf_writable(arg, INT_BYTES, 1) { return fault; }
    // SAFETY: arg validated writable for one Linux int in/out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i32, out); }
    rv
}

/// Legacy XFS preallocation ioctls routed to `i_op->fallocate`. # C: FS-dependent
fn ioctl_preallocate(file: &vfs::File, mode: u32, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, SPACE_RESV_BYTES, 1) { return rv; }
    // SAFETY: copy_from_user-equivalent after validating the whole `space_resv` payload.
    let whence = unsafe { core::ptr::read_unaligned((arg + SPACE_RESV_L_WHENCE) as *const i16) };
    // SAFETY: copy_from_user-equivalent after validating the whole `space_resv` payload.
    let mut start = unsafe { core::ptr::read_unaligned((arg + SPACE_RESV_L_START) as *const i64) };
    // SAFETY: copy_from_user-equivalent after validating the whole `space_resv` payload.
    let len = unsafe { core::ptr::read_unaligned((arg + SPACE_RESV_L_LEN) as *const i64) };
    match whence {
        SEEK_SET => {}
        SEEK_CUR => start = match start.checked_add(file.pos() as i64) {
            Some(v) => v, None => return -(Errno::Einval.as_i32() as i64),
        },
        SEEK_END => start = match start.checked_add(file.inode().size() as i64) {
            Some(v) => v, None => return -(Errno::Einval.as_i32() as i64),
        },
        _ => return -(Errno::Einval.as_i32() as i64),
    }
    if start < 0 || len <= 0 { return -(Errno::Einval.as_i32() as i64); }
    if (start as u64).checked_add(len as u64).is_none() { return -(Errno::Einval.as_i32() as i64); }
    if !file.f_mode().contains(vfs::Fmode::WRITE) { return -(Errno::Ebadf.as_i32() as i64); }
    let zero = mode & FALLOC_FL_ZERO_RANGE != 0;
    let punch = mode & FALLOC_FL_PUNCH_HOLE != 0;
    match file.inode().fallocate(start as u64, len as u64, true, zero, punch) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// Linux `FS_IOC_GETFSUUID`: expose superblock UUID or `ENOTTY`. # C: O(1)
fn ioctl_getfsuuid(file: &vfs::File, arg: u64) -> i64 {
    let sb = match file.inode().i_sb() {
        Some(sb) => sb,
        None => return -(Errno::Enotty.as_i32() as i64),
    };
    let len = sb.s_uuid_len();
    if len == 0 { return -(Errno::Enotty.as_i32() as i64); }
    let uuid = sb.s_uuid();
    if let Err(rv) = validate_user_buf_writable(arg, FSUUID2_BYTES, 1) { return rv; }
    // SAFETY: arg validated writable for fixed-size Linux `struct fsuuid2`.
    unsafe {
        core::ptr::write_volatile(arg as *mut u8, len);
        core::ptr::copy_nonoverlapping(uuid.as_ptr(), (arg + 1) as *mut u8, 16);
    }
    0
}

/// Linux `FS_IOC_GETFSSYSFSPATH`: expose `fstype/s_sysfs_name`. # C: O(len name)
fn ioctl_getfssysfspath(file: &vfs::File, arg: u64) -> i64 {
    let sb = match file.inode().i_sb() {
        Some(sb) => sb,
        None => return -(Errno::Enotty.as_i32() as i64),
    };
    let name = sb.s_sysfs_name();
    if name.is_empty() { return -(Errno::Enotty.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(arg, FS_SYSFS_PATH_BYTES, 1) { return rv; }
    let ty = sb.s_type.name().as_bytes();
    let sys = name.as_bytes();
    let mut out = [0u8; FS_SYSFS_PATH_NAME_BYTES];
    let mut n = 0usize;
    for b in ty.iter().chain(core::iter::once(&b'/')).chain(sys.iter()) {
        if n + 1 >= FS_SYSFS_PATH_NAME_BYTES { break; }
        out[n] = *b;
        n += 1;
    }
    // SAFETY: arg validated writable for fixed-size Linux `struct fs_sysfs_path`.
    unsafe {
        core::ptr::write_volatile(arg as *mut u8, n as u8);
        core::ptr::copy_nonoverlapping(out.as_ptr(), (arg + 1) as *mut u8, FS_SYSFS_PATH_NAME_BYTES);
    }
    0
}

fn read_u32(addr: u64) -> u32 {
    // SAFETY: caller validated the surrounding user payload before reading this field.
    unsafe { core::ptr::read_unaligned(addr as *const u32) }
}

fn read_u16(addr: u64) -> u16 {
    // SAFETY: caller validated the surrounding user payload before reading this field.
    unsafe { core::ptr::read_unaligned(addr as *const u16) }
}

fn read_i64(addr: u64) -> i64 {
    // SAFETY: caller validated the surrounding user payload before reading this field.
    unsafe { core::ptr::read_unaligned(addr as *const i64) }
}

fn read_u64(addr: u64) -> u64 {
    // SAFETY: caller validated the surrounding user payload before reading this field.
    unsafe { core::ptr::read_unaligned(addr as *const u64) }
}

fn write_u64(addr: u64, val: u64) {
    // SAFETY: caller validated the surrounding user payload before writing this field.
    unsafe { core::ptr::write_unaligned(addr as *mut u64, val); }
}

fn write_i32(addr: u64, val: i32) {
    // SAFETY: caller validated the surrounding user payload before writing this field.
    unsafe { core::ptr::write_unaligned(addr as *mut i32, val); }
}

#[cfg(not(test))]
fn dedupe_cred(_cur: &sched::Task) -> vfs::Cred {
    crate::pathresolve::current_cred()
}

#[cfg(test)]
fn dedupe_cred(cur: &sched::Task) -> vfs::Cred {
    use core::sync::atomic::Ordering;
    let effective = cur.creds.cap_effective.load(Ordering::Acquire);
    let ng = (cur.creds.ngroups.load(Ordering::Acquire) as usize).min(vfs::CRED_NGROUPS);
    let mut groups = [0u32; vfs::CRED_NGROUPS];
    // SAFETY: hosted tests mutate the leaked task credentials before installing the current hook.
    unsafe {
        let g = &*cur.creds.groups.get();
        groups[..ng].copy_from_slice(&g[..ng]);
    }
    let has = |cap: u32| effective & (1u64 << cap) != 0;
    vfs::Cred {
        uid: cur.creds.fsuid.load(Ordering::Acquire),
        gid: cur.creds.fsgid.load(Ordering::Acquire),
        cap_dac_override: has(sched::cap::DAC_OVERRIDE),
        cap_dac_read_search: has(sched::cap::DAC_READ_SEARCH),
        cap_fowner: has(sched::cap::FOWNER),
        cap_chown: has(sched::cap::CHOWN),
        cap_fsetid: has(sched::cap::FSETID),
        ngroups: ng as u32,
        groups,
    }
}
