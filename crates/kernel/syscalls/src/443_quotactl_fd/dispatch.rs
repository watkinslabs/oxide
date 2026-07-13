use syscall::errno::Errno;

/// File-target dispatch for `quotactl_fd`; caller owns fd lookup. # C: O(1)+FS
pub fn quotactl_fd_file(file: &vfs::File, cmd: u64, id: u64, addr: u64) -> i64 {
    if !crate::s179_quotactl::quotactl_cmd_type_valid(cmd) { return -(Errno::Einval.as_i32() as i64); }
    let mnt = match file.vfsmount() { Some(m) => m, None => return -(Errno::Enodev.as_i32() as i64) };
    let sb = mnt.sb();

    let write = crate::s179_quotactl::quotactl_cmd_write(cmd);
    if write {
        if let Err(e) = vfs::mount::mnt_want_write(&mnt) { return -(e as i64); }
        if !sb.sb_start_write() {
            vfs::mount::mnt_drop_write(&mnt);
            return -(vfs::VfsError::Erofs as i64);
        }
        if sb.is_readonly() {
            sb.sb_end_write();
            vfs::mount::mnt_drop_write(&mnt);
            return -(vfs::VfsError::Erofs as i64);
        }
    }
    let rv = crate::s179_quotactl::quotactl_dispatch_sb_fd(sb, cmd, id, addr);
    if write {
        sb.sb_end_write();
        vfs::mount::mnt_drop_write(&mnt);
    }
    rv
}
