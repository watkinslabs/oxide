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

/// Linux `FS_IOC_GETFLAGS`: copy the legacy `FS_*_FL` flag word. # C: O(1)
pub(super) fn ioctl_getflags(file: &vfs::File, arg: u64) -> i64 {
    let fa = match file.inode().fileattr_get() {
        Ok(fa) => fa,
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    write_u32(arg, fa.flags);
    0
}

/// Linux `FS_IOC_SETFLAGS`: set the legacy `FS_*_FL` flag word. # C: FS-dependent
pub(super) fn ioctl_setflags(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    let flags = read_u32(arg);
    let want = fattr_fill_flags(vfs::FileAttr { flags, ..Default::default() });
    vfs_fileattr_set(cur, file, want, vfs::FileAttrSource::Flags)
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
    vfs_fileattr_set(cur, file, want, vfs::FileAttrSource::Fsxattr)
}

fn vfs_fileattr_set(cur: &sched::Task, file: &vfs::File, want: vfs::FileAttr, source: vfs::FileAttrSource) -> i64 {
    let m = file.vfsmount();
    if let Some(ref mnt) = m {
        if let Err(e) = vfs::mount::mnt_want_write(mnt) { return -(e as i64); }
        if mnt.sb().is_readonly() {
            vfs::mount::mnt_drop_write(mnt);
            return -(vfs::VfsError::Erofs as i64);
        }
    }
    let rv = vfs_fileattr_set_inner(cur, file, want, source);
    if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); }
    rv
}

fn vfs_fileattr_set_inner(cur: &sched::Task, file: &vfs::File, want: vfs::FileAttr, source: vfs::FileAttrSource) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = current_cred();
    if !vfs::inode::inode_owner_or_capable(&idmap, file.inode().as_ref(), &cred) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let old = match file.inode().fileattr_get() {
        Ok(fa) => fattr_fill_xflags(fa),
        Err(e) => return -(e as i64),
    };
    let want = match vfs::fileattr_prepare_set(&idmap, file.inode(), old, want, source, &cred,
        cur_in_init_user_ns(cur) && cur.has_cap(sched::cap::LINUX_IMMUTABLE),
        cur_in_init_user_ns(cur))
    {
        Ok(fa) => fa,
        Err(e) => return -(e as i64),
    };
    match file.inode().fileattr_set(&want) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
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

fn fattr_fill_flags(mut fa: vfs::FileAttr) -> vfs::FileAttr {
    if fa.flags & FS_SYNC_FL      != 0 { fa.fsx_xflags |= FS_XFLAG_SYNC; }
    if fa.flags & FS_IMMUTABLE_FL != 0 { fa.fsx_xflags |= FS_XFLAG_IMMUTABLE; }
    if fa.flags & FS_APPEND_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_APPEND; }
    if fa.flags & FS_NODUMP_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_NODUMP; }
    if fa.flags & FS_NOATIME_FL   != 0 { fa.fsx_xflags |= FS_XFLAG_NOATIME; }
    if fa.flags & FS_DAX_FL       != 0 { fa.fsx_xflags |= FS_XFLAG_DAX; }
    if fa.flags & FS_PROJINHERIT_FL != 0 { fa.fsx_xflags |= FS_XFLAG_PROJINHERIT; }
    if fa.flags & FS_VERITY_FL    != 0 { fa.fsx_xflags |= FS_XFLAG_VERITY; }
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
fn current_cred() -> vfs::Cred {
    crate::pathresolve::current_cred()
}

#[cfg(test)]
fn current_cred() -> vfs::Cred {
    vfs::Cred::root()
}

#[cfg(not(test))]
fn cur_in_init_user_ns(cur: &sched::Task) -> bool {
    cur.user_ns.load(core::sync::atomic::Ordering::Acquire) == 0
}

#[cfg(test)]
fn cur_in_init_user_ns(_cur: &sched::Task) -> bool {
    true
}
