use syscall::errno::Errno;

use crate::ioctl_user as user;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

use super::uapi::*;

/// Linux `FS_IOC_FSGETXATTR`: copy `struct fsxattr` from fileattr state. # C: O(1)
pub(super) fn ioctl_fsgetxattr(file: &vfs::File, arg: u64) -> i64 {
    let fa = match vfs::fileattr_get(file.inode()) {
        Ok(fa) => fattr_fill_xflags(fa),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, FSXATTR_BYTES, 1) { return rv; }
    let mut out = [0u8; FSXATTR_BYTES as usize];
    out[0..4].copy_from_slice(&(fa.fsx_xflags & FS_XFLAGS_MASK).to_ne_bytes());
    out[4..8].copy_from_slice(&fa.fsx_extsize.to_ne_bytes());
    out[8..12].copy_from_slice(&fa.fsx_nextents.to_ne_bytes());
    out[12..16].copy_from_slice(&fa.fsx_projid.to_ne_bytes());
    out[16..20].copy_from_slice(&fa.fsx_cowextsize.to_ne_bytes());
    match user::put_bytes(arg, &out) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux `FS_IOC_GETFLAGS`: copy the legacy `FS_*_FL` flag word. # C: O(1)
pub(super) fn ioctl_getflags(file: &vfs::File, arg: u64) -> i64 {
    let fa = match vfs::fileattr_get(file.inode()) {
        Ok(fa) => fa,
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = validate_user_buf_writable(arg, INT_BYTES, 1) { return rv; }
    match user::put_u32(arg, fa.flags) { Ok(()) => 0, Err(rv) => rv }
}

/// Linux `FS_IOC_SETFLAGS`: set the legacy `FS_*_FL` flag word. # C: FS-dependent
pub(super) fn ioctl_setflags(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, INT_BYTES, 1) { return rv; }
    let flags = match user::get_u32(arg) { Ok(v) => v, Err(rv) => return rv };
    let want = fattr_fill_flags(vfs::FileAttr { flags, ..Default::default() });
    vfs_fileattr_set(cur, file, want, vfs::FileAttrSource::Flags)
}

/// Linux `FS_IOC_FSSETXATTR`: copy fsxattr, validate xflags, set fileattr. # C: FS-dependent
pub(super) fn ioctl_fssetxattr(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_readable(arg, FSXATTR_BYTES, 1) { return rv; }
    let fsx = match user::get_bytes::<{ FSXATTR_BYTES as usize }>(arg) { Ok(b) => b, Err(rv) => return rv };
    let fld = |off: usize| u32::from_ne_bytes([fsx[off], fsx[off + 1], fsx[off + 2], fsx[off + 3]]);
    let xflags = fld(0);
    if xflags & !FS_XFLAGS_MASK != 0 { return -(Errno::Eopnotsupp.as_i32() as i64); }
    let extsize = fld(4);
    let nextents = fld(8);
    let projid = fld(12);
    let cowextsize = fld(16);
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
    match vfs::fileattr_set(&idmap, file.inode(), want, source, &cred,
        cur_in_init_user_ns(cur) && cur.has_cap(sched::cap::LINUX_IMMUTABLE),
        cur_in_init_user_ns(cur))
    {
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
        if fa.flags & FS_CASEFOLD_FL  != 0 { fa.fsx_xflags |= FS_XFLAG_CASEFOLD; }
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
        if fa.fsx_xflags & FS_XFLAG_CASEFOLD  != 0 { fa.flags |= FS_CASEFOLD_FL; }
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
    if fa.flags & FS_CASEFOLD_FL  != 0 { fa.fsx_xflags |= FS_XFLAG_CASEFOLD; }
    fa
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
    cur.namespace_id(namespace_identity::NamespaceKind::User) == Some(0)
}

#[cfg(test)]
fn cur_in_init_user_ns(_cur: &sched::Task) -> bool {
    true
}
