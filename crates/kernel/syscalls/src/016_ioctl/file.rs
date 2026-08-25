use super::*;

pub(super) fn handle_file_ioctl(cur: &sched::Task, file: &vfs::File, req: u64, arg: u64) -> Option<i64> {
    match req {
        super::uapi::EXT4_IOC_GETVERSION | super::uapi::FS_IOC_GETVERSION =>
            Some(ioctl_getversion(file, arg)),
        super::uapi::EXT4_IOC_SETVERSION | super::uapi::FS_IOC_SETVERSION =>
            Some(ioctl_setversion(file, arg)),
        super::uapi::FS_IOC_GETFSLABEL => Some(ioctl_getfslabel(file, arg)),
        super::uapi::FS_IOC_SETFSLABEL => Some(ioctl_setfslabel(cur, file, arg)),
        super::uapi::FITRIM => Some(ioctl_fitrim(cur, file, arg)),
        super::uapi::FAT_IOCTL_GET_ATTRIBUTES => Some(ioctl_fat_get_attributes(file, arg)),
        super::uapi::FAT_IOCTL_SET_ATTRIBUTES => Some(ioctl_fat_set_attributes(cur, file, arg)),
        super::uapi::VFAT_IOCTL_READDIR_BOTH => Some(ioctl_fat_readdir(file, arg, false)),
        super::uapi::VFAT_IOCTL_READDIR_SHORT => Some(ioctl_fat_readdir(file, arg, true)),
        _ => None,
    }
}

fn ioctl_fat_get_attributes(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    let attr = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::FatGetAttributes) {
        Ok(vfs::FileIoctlReply::U32(v)) => v,
        Ok(_) => return -(Errno::Enotty.as_i32() as i64),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::INT_BYTES, 1) { return rv; }
    match user::put_u32(arg, attr) { Ok(()) => 0, Err(rv) => rv }
}

fn ioctl_fat_set_attributes(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::INT_BYTES, 1) { return rv; }
    let attr = match user::get_u32(arg) { Ok(v) => v, Err(rv) => return rv };
    match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::FatSetAttributes {
        attr, cap_linux_immutable: cur.has_cap(sched::cap::LINUX_IMMUTABLE),
    }) { Ok(_) => 0, Err(e) => -(e as i64) }
}

fn ioctl_fat_readdir(file: &vfs::File, arg: u64, short_only: bool) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, 560, 1) { return rv; }
    let (bytes, len) = match file.unlocked_ioctl(&idmap, &cred,
        vfs::FileIoctlCmd::FatReadDir { short_only }) {
        Ok(vfs::FileIoctlReply::Bytes(bytes, len)) => (bytes, len),
        Ok(_) => return -(Errno::Enotty.as_i32() as i64),
        Err(e) => return -(e as i64),
    };
    match user::put_bytes(arg, &bytes[..len]) { Ok(()) => 0, Err(rv) => rv }
}

fn ioctl_getversion(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    let gen = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::GetVersion) {
        Ok(vfs::FileIoctlReply::U32(v)) => v,
        Ok(_) => return -(Errno::Enotty.as_i32() as i64),
        Err(e) => return -(e as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::INT_BYTES, 1) { return rv; }
    match user::put_u32(arg, gen) { Ok(()) => 0, Err(rv) => rv }
}

fn ioctl_setversion(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    if let Err(e) = file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetVersionPrepare) { return -(e as i64); }
    let m = file.vfsmount();
    if let Some(ref mnt) = m {
        if let Err(e) = vfs::mount::mnt_want_write(mnt) { return -(e as i64); }
        if mnt.sb().is_readonly() { vfs::mount::mnt_drop_write(mnt); return -(vfs::VfsError::Erofs as i64); }
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::INT_BYTES, 1) {
        if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); } return rv;
    }
    let gen = match user::get_u32(arg) {
        Ok(v) => v,
        Err(rv) => { if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); } return rv; }
    };
    let rv = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetVersion(gen)) {
        Ok(_) => 0, Err(e) => -(e as i64),
    };
    if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); }
    rv
}

fn ioctl_getfslabel(file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    let label = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::GetFsLabel) {
        Ok(vfs::FileIoctlReply::Label(v)) => v,
        Ok(_) => return -(Errno::Enotty.as_i32() as i64), Err(e) => return -(e as i64),
    };
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::EXT4_LABEL_BYTES, 1) { return rv; }
    match user::put_bytes(arg, &label) { Ok(()) => 0, Err(rv) => rv }
}

fn ioctl_setfslabel(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    let cap = cur.has_cap(sched::cap::SYS_ADMIN);
    if let Err(e) = file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetFsLabelPrepare(cap)) { return -(e as i64); }
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::EXT4_LABEL_BYTES, 1) { return rv; }
    let mut buf = [0u8; super::uapi::EXT4_LABEL_MAX + 1];
    if let Err(rv) = user::get_into(arg, &mut buf) { return rv; }
    let len = match buf.iter().position(|&b| b == 0) { Some(n) => n, None => return -(Errno::Einval.as_i32() as i64) };
    let mut label = [0u8; super::uapi::EXT4_LABEL_MAX]; label[..len].copy_from_slice(&buf[..len]);
    let m = file.vfsmount();
    if let Some(ref mnt) = m {
        if let Err(e) = vfs::mount::mnt_want_write(mnt) { return -(e as i64); }
        if mnt.sb().is_readonly() { vfs::mount::mnt_drop_write(mnt); return -(vfs::VfsError::Erofs as i64); }
    }
    let rv = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::SetFsLabel(label)) { Ok(_) => 0, Err(e) => -(e as i64) };
    if let Some(ref mnt) = m { vfs::mount::mnt_drop_write(mnt); }
    rv
}

fn ioctl_fitrim(cur: &sched::Task, file: &vfs::File, arg: u64) -> i64 {
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let cred = crate::pathresolve::current_cred();
    let cap = cur.has_cap(sched::cap::SYS_ADMIN);
    if let Err(e) = file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::FitTrimPrepare(cap)) { return -(e as i64); }
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(arg, super::uapi::FSTRIM_RANGE_BYTES, 1) { return rv; }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(arg, super::uapi::FSTRIM_RANGE_BYTES, 1) { return rv; }
    let range = match user::get_bytes::<{ super::uapi::FSTRIM_RANGE_BYTES as usize }>(arg) { Ok(b) => b, Err(rv) => return rv };
    let fld = |o: usize| { let mut v = [0u8; 8]; v.copy_from_slice(&range[o..o + 8]); u64::from_ne_bytes(v) };
    let (start, len, minlen) = (fld(0), fld(8), fld(16));
    let rv = match file.unlocked_ioctl(&idmap, &cred, vfs::FileIoctlCmd::FitTrim { start, len, minlen }) { Ok(_) => 0, Err(e) => return -(e as i64) };
    let mut out = [0u8; super::uapi::FSTRIM_RANGE_BYTES as usize];
    out[..8].copy_from_slice(&start.to_ne_bytes()); out[8..16].copy_from_slice(&len.to_ne_bytes()); out[16..24].copy_from_slice(&minlen.to_ne_bytes());
    if let Err(fault) = user::put_bytes(arg, &out) { return fault; }
    rv
}
