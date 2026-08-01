#![cfg(target_os = "oxide-kernel")]

use super::lookup::resolve_path_raw;

/// Linux `fs/exec.c` `do_open_execat` — resolve the pathname, apply the
/// `may_open(..., MAY_EXEC, 0)` gate (`fs/namei.c:4236`), then read the image.
///
/// The resolved [`vfs::VfsPath`] comes back with the blob because the exec
/// credential transition must be computed from the SAME inode and mount this
/// check ran against: `bprm_fill_uid` re-reads the mode and re-runs
/// `inode_permission(MAY_EXEC)` on `file_inode(bprm->file)`, and `mnt_may_suid`
/// reads `file->f_path.mnt`. Re-resolving the path afterwards would open a
/// window in which the checked file and the credited file differ.
///
/// Errors come back already negated for the caller to forward:
///   * `ENOENT` / `ENOTDIR` / `ELOOP` — from the lookup itself
///   * `EACCES` — not a regular file, no execute permission, or a `noexec` mount
///   * `EIO` — the image could not be read
/// # C: O(components) + O(size/PAGE)
pub fn open_exec(path: &[u8]) -> Result<(alloc::vec::Vec<u8>, vfs::VfsPath), i64> {
    let s = vfs::path_from_bytes(path);
    let vp = resolve_path_raw(&s, false).map_err(crate::namei_common::errno_from_vfs)?;
    exec_permission(&vp)?;
    let blob = read_exec_inode(&vp.inode)
        .ok_or(-(syscall::errno::Errno::Eio.as_i32() as i64))?;
    Ok((blob, vp))
}

/// The `may_open(..., MAY_EXEC, 0)` half of `do_open_execat`: the file-type
/// ladder, `path_noexec` (`mount -o noexec`), then the DAC test. Split out so
/// the shebang chain applies the identical gate to every interpreter it walks
/// to — Linux re-opens each one through `do_open_execat`.
/// # C: O(ngroups)
pub fn exec_permission(vp: &vfs::VfsPath) -> Result<(), i64> {
    use syscall::errno::Errno;
    crate::execveat_at::may_exec_file_type(vp.inode.file_type())
        .map_err(|e| -(e.as_i32() as i64))?;
    // `path_noexec(path)` (`fs/exec.c`): `(mnt->mnt_flags & MNT_NOEXEC) ||
    // (mnt->mnt_sb->s_iflags & SB_I_NOEXEC)`. `s_iflags` is the KERNEL-INTERNAL
    // word procfs/sysfs/pseudo-fs stamp at fill-super — a different field from
    // the user-visible `s_flags` `SB_NOEXEC`, and the only one those backends
    // set, so testing `s_flags` alone let an execve off /proc or /sys through.
    if let Some(m) = vfs::mount::mount_by_id(vp.mnt_id) {
        if m.is_noexec() || m.sb().is_noexec() || m.sb().is_sb_i_noexec() {
            return Err(-(Errno::Eacces.as_i32() as i64));
        }
    }
    // The sandbox execute right, applied to every interpreter in a shebang
    // chain because each one is opened for execution in turn.
    crate::landlock::check(vp, ::landlock::uapi::ACCESS_FS_EXECUTE)?;
    vfs::inode_permission(&vp.inode, vfs::MAY_EXEC, &super::cred::current_cred())
        .map_err(crate::namei_common::errno_from_vfs)
}

/// # C: O(size/PAGE)
pub fn read_exec_inode(inode: &vfs::InodeRef) -> Option<alloc::vec::Vec<u8>> {
    if inode.file_type() != vfs::FileType::Regular { return None; }
    let total = inode.size() as usize;
    let mut out = alloc::vec::Vec::with_capacity(total);
    out.resize(total, 0u8);
    let mut off = 0usize;
    while off < total {
        match inode.read(off as u64, &mut out[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(_) => return None,
        }
    }
    out.truncate(off);
    Some(out)
}
