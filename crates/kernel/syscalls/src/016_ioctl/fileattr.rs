use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

use super::uapi::*;

/// Linux `FS_IOC_FSGETXATTR`: copy `struct fsxattr` from fileattr state. # C: O(1)
pub(super) fn ioctl_fsgetxattr(file: &vfs::File, arg: u64) -> i64 {
    let fa = match file.inode().fileattr_get() {
        Ok(fa) => fattr_fill_xflags(fa),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, FSXATTR_BYTES, 1) { return rv; }
    write_u32(arg, fa.fsx_xflags & FS_XFLAGS_MASK);
    write_u32(arg + 4, fa.fsx_extsize);
    write_u32(arg + 8, fa.fsx_nextents);
    write_u32(arg + 12, fa.fsx_projid);
    write_u32(arg + 16, fa.fsx_cowextsize);
    write_u64(arg + 20, 0);
    0
}

/// Linux `FS_IOC_FSSETXATTR`: copy fsxattr, validate xflags, set fileattr. # C: FS-dependent
pub(super) fn ioctl_fssetxattr(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, FSXATTR_BYTES, 1) { return rv; }
    let xflags = read_u32(arg);
    if xflags & !FS_XFLAGS_MASK != 0 { return -(Errno::Eopnotsupp.as_i32() as i64); }
    let extsize = read_u32(arg + 4);
    let nextents = read_u32(arg + 8);
    let projid = read_u32(arg + 12);
    let cowextsize = read_u32(arg + 16);
    let want = fattr_fill_xflags(vfs::FileAttr {
        flags: 0,
        fsx_xflags: xflags & !FS_XFLAG_RDONLY_MASK,
        fsx_extsize: extsize,
        fsx_nextents: nextents,
        fsx_projid: projid,
        fsx_cowextsize: cowextsize,
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
    let want = match fileattr_set_prepare(file.inode().file_type(), want) {
        Ok(fa) => fa,
        Err(e) => return -(e as i64),
    };
    match file.inode().fileattr_set(&want) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

fn fileattr_set_prepare(ft: vfs::FileType, mut fa: vfs::FileAttr) -> vfs::KResult<vfs::FileAttr> {
    if fa.fsx_xflags & FS_XFLAG_EXTSIZE != 0 && ft != vfs::FileType::Regular {
        return Err(vfs::VfsError::Einval);
    }
    if fa.fsx_xflags & FS_XFLAG_EXTSZINHERIT != 0 && ft != vfs::FileType::Directory {
        return Err(vfs::VfsError::Einval);
    }
    if fa.fsx_xflags & FS_XFLAG_COWEXTSIZE != 0
        && ft != vfs::FileType::Regular && ft != vfs::FileType::Directory
    {
        return Err(vfs::VfsError::Einval);
    }
    if fa.fsx_xflags & FS_XFLAG_DAX != 0
        && ft != vfs::FileType::Regular && ft != vfs::FileType::Directory
    {
        return Err(vfs::VfsError::Einval);
    }
    if fa.fsx_extsize == 0 { fa.fsx_xflags &= !(FS_XFLAG_EXTSIZE | FS_XFLAG_EXTSZINHERIT); }
    if fa.fsx_cowextsize == 0 { fa.fsx_xflags &= !FS_XFLAG_COWEXTSIZE; }
    Ok(fa)
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
