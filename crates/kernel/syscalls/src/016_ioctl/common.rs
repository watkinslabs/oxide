use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

use super::uapi::*;

const O_ASYNC: u32 = 0o20000;

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
        FIOASYNC => Some(ioctl_fioasync(file, arg)),
        FIOQSIZE => Some(ioctl_fioqsize(file, arg)),
        FIGETBSZ => Some(ioctl_figetbsz(file, arg)),
        FIBMAP => Some(ioctl_fibmap(cur, file, arg)),
        FS_IOC_RESVSP | FS_IOC_RESVSP64 => Some(ioctl_preallocate(file, 0, arg)),
        FS_IOC_UNRESVSP | FS_IOC_UNRESVSP64 => Some(ioctl_preallocate(file, FALLOC_FL_PUNCH_HOLE, arg)),
        FS_IOC_ZERO_RANGE => Some(ioctl_preallocate(file, FALLOC_FL_ZERO_RANGE, arg)),
        FS_IOC_FSGETXATTR => Some(ioctl_fsgetxattr(file, arg)),
        FS_IOC_FSSETXATTR => Some(ioctl_fssetxattr(cur, file, arg)),
        FS_IOC_GETFSUUID => Some(ioctl_getfsuuid(file, arg)),
        FIONREAD if file.inode().file_type() == vfs::FileType::Regular => {
            Some(ioctl_regular_fionread(file, arg))
        }
        _ => None,
    }
}

/// Socket/pipe queue-count ioctls used after regular-file common handling.
/// # C: O(1)
pub(super) fn handle_nonchar_queue_ioctl(file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    match req {
        FIONREAD | SIOCOUTQ => {
            if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return Some(rv); }
            let n: u32 = if req == FIONREAD
                && (file.inode().poll_file(file.pos()) & vfs::POLL_IN) != 0 { 1 } else { 0 };
            // SAFETY: arg validated writable for one Linux int out-param.
            unsafe { core::ptr::write_volatile(arg as *mut u32, n); }
            Some(0)
        }
        _ => None,
    }
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
fn ioctl_fioasync(file: &alloc::sync::Arc<vfs::File>, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    // SAFETY: arg validated readable for one Linux int input.
    let on = unsafe { core::ptr::read_volatile(arg as *const i32) } != 0;
    let was_async = file.is_async();
    let mut fl = file.flags();
    let async_flag = vfs::OpenFlags::from_bits_retain(O_ASYNC);
    if on { fl |= async_flag; } else { fl &= !async_flag; }
    file.set_fl(fl);
    let now_async = file.is_async();
    if now_async && !was_async {
        register_fasync(file);
    } else if was_async && !now_async {
        vfs::file::fasync_unregister(file);
    }
    0
}

/// Kernel target wires SIGIO delivery before adding the file to fasync. Hosted
/// tests do not build `sched::live`, but still exercise the flag/registry path.
/// # C: O(1)
#[cfg(not(test))]
fn register_fasync(file: &alloc::sync::Arc<vfs::File>) {
    sched::live::sigpend::install_sigio_hook();
    vfs::file::fasync_register(file);
}

/// # C: O(1)
#[cfg(test)]
fn register_fasync(file: &alloc::sync::Arc<vfs::File>) {
    vfs::file::fasync_register(file);
}

/// Linux `FIOQSIZE`: dirs, regular files, and symlinks copy `loff_t` bytes.
/// # C: O(1)
fn ioctl_fioqsize(file: &vfs::File, arg: u64) -> i64 {
    match file.inode().file_type() {
        vfs::FileType::Directory | vfs::FileType::Regular | vfs::FileType::Symlink => {}
        _ => return -(Errno::Enotty.as_i32() as i64),
    }
    if let Err(rv) = validate_user_buf_writable(arg, LOFF_BYTES, 1) { return rv; }
    // SAFETY: arg validated writable for one Linux loff_t out-param.
    unsafe { core::ptr::write_volatile(arg as *mut i64, file.inode().size() as i64); }
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

/// Linux `FS_IOC_FSGETXATTR`: copy `struct fsxattr` from fileattr state. # C: O(1)
fn ioctl_fsgetxattr(file: &vfs::File, arg: u64) -> i64 {
    let fa = match file.inode().fileattr_get() {
        Ok(fa) => fattr_fill_xflags(fa),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, FSXATTR_BYTES, 1) { return rv; }
    write_u32(arg, fa.fsx_xflags & FS_XFLAGS_MASK);
    write_u32(arg + 4, 0);
    write_u32(arg + 8, 0);
    write_u32(arg + 12, fa.fsx_projid);
    write_u32(arg + 16, 0);
    write_u64(arg + 20, 0);
    0
}

/// Linux `FS_IOC_FSSETXATTR`: copy fsxattr, validate xflags, set fileattr. # C: FS-dependent
fn ioctl_fssetxattr(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, FSXATTR_BYTES, 1) { return rv; }
    let xflags = read_u32(arg);
    if xflags & !FS_XFLAGS_MASK != 0 { return -(Errno::Eopnotsupp.as_i32() as i64); }
    let projid = read_u32(arg + 12);
    let want = fattr_fill_xflags(vfs::FileAttr {
        flags: 0,
        fsx_xflags: xflags & !FS_XFLAG_RDONLY_MASK,
        fsx_projid: projid,
    });
    if file.inode().uid() != Some(current_fsuid()) && !cur.has_cap(sched::cap::FOWNER) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let old = match file.inode().fileattr_get() {
        Ok(fa) => fattr_fill_xflags(fa),
        Err(e) => return -(e as i64),
    };
    if (want.flags ^ old.flags) & (FS_APPEND_FL | FS_IMMUTABLE_FL) != 0
        && !cur.has_cap(sched::cap::LINUX_IMMUTABLE)
    {
        return -(Errno::Eperm.as_i32() as i64);
    }
    match file.inode().fileattr_set(&want) {
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

fn fattr_fill_xflags(mut fa: vfs::FileAttr) -> vfs::FileAttr {
    if fa.fsx_xflags == 0 && fa.flags != 0 {
        if fa.flags & FS_SYNC_FL      != 0 { fa.fsx_xflags |= FS_XFLAG_SYNC; }
        if fa.flags & FS_IMMUTABLE_FL != 0 { fa.fsx_xflags |= FS_XFLAG_IMMUTABLE; }
        if fa.flags & FS_APPEND_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_APPEND; }
        if fa.flags & FS_NODUMP_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_NODUMP; }
        if fa.flags & FS_NOATIME_FL   != 0 { fa.fsx_xflags |= FS_XFLAG_NOATIME; }
        if fa.flags & FS_DAX_FL       != 0 { fa.fsx_xflags |= FS_XFLAG_DAX; }
        if fa.flags & FS_PROJINHERIT_FL != 0 { fa.fsx_xflags |= FS_XFLAG_PROJINHERIT; }
        if fa.flags & FS_VERITY_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_VERITY; }
    }
    if fa.flags == 0 && fa.fsx_xflags != 0 {
        if fa.fsx_xflags & FS_XFLAG_IMMUTABLE != 0 { fa.flags |= FS_IMMUTABLE_FL; }
        if fa.fsx_xflags & FS_XFLAG_APPEND    != 0 { fa.flags |= FS_APPEND_FL; }
        if fa.fsx_xflags & FS_XFLAG_SYNC      != 0 { fa.flags |= FS_SYNC_FL; }
        if fa.fsx_xflags & FS_XFLAG_NOATIME   != 0 { fa.flags |= FS_NOATIME_FL; }
        if fa.fsx_xflags & FS_XFLAG_NODUMP    != 0 { fa.flags |= FS_NODUMP_FL; }
        if fa.fsx_xflags & FS_XFLAG_DAX       != 0 { fa.flags |= FS_DAX_FL; }
        if fa.fsx_xflags & FS_XFLAG_PROJINHERIT != 0 { fa.flags |= FS_PROJINHERIT_FL; }
        if fa.fsx_xflags & FS_XFLAG_VERITY    != 0 { fa.flags |= FS_VERITY_FL; }
    }
    fa
}

fn read_u32(addr: u64) -> u32 {
    // SAFETY: caller validated the surrounding user payload before reading this field.
    unsafe { core::ptr::read_unaligned(addr as *const u32) }
}

fn write_u32(addr: u64, val: u32) {
    // SAFETY: caller validated the surrounding user payload before writing this field.
    unsafe { core::ptr::write_unaligned(addr as *mut u32, val); }
}

fn write_u64(addr: u64, val: u64) {
    // SAFETY: caller validated the surrounding user payload before writing this field.
    unsafe { core::ptr::write_unaligned(addr as *mut u64, val); }
}

#[cfg(not(test))]
fn current_fsuid() -> u32 {
    crate::pathresolve::current_cred().uid
}

#[cfg(test)]
fn current_fsuid() -> u32 {
    0
}
