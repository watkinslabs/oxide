#![cfg(target_os = "oxide-kernel")]

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use hal::USER_VA_END;
use syscall::errno::Errno;
use vfs::{File, InodeRef, OpenFlags};

/// Read a user pathname that may legally be empty for AT_EMPTY_PATH-style mount
/// operations. Path bytes are opaque Linux bytes, so decode with the VFS
/// reversible path codec instead of requiring UTF-8. # C: O(PATH_MAX)
pub(crate) fn read_path_allow_empty(p: u64) -> Result<String, i64> {
    if p == 0 || p >= USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
    // SAFETY: p in user range; bounded read via the shared helper.
    let b = unsafe { devfs::read_user_cstr(p, vfs::path::PATH_MAX) }
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    let path = vfs::path_from_bytes(b);
    if !path.is_empty() {
        vfs::path::check_path_len(&path).map_err(crate::namei_common::errno_from_vfs)?;
    }
    Ok(path)
}

/// Read a required user C string. Bad pointers are `EFAULT`; invalid UTF-8 is
/// `EINVAL`. # C: O(max)
pub(crate) fn read_cstr_req(p: u64, max: usize) -> Result<String, i64> {
    if p == 0 || p >= USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
    // SAFETY: p in user range; bounded read via the shared helper.
    let b = unsafe { devfs::read_user_cstr(p, max) }
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    core::str::from_utf8(b)
        .map(|s| s.to_string())
        .map_err(|_| -(Errno::Einval.as_i32() as i64))
}

/// `strndup_user(p, n)` (`mm/util.c`): a string that does not terminate inside
/// `n` bytes is EINVAL, NOT a silent `n`-byte prefix. `fsconfig(2)` bounds both
/// its key and its string value this way, so an over-long option name is
/// refused rather than truncated into a DIFFERENT option that the filesystem
/// may well accept. # C: O(n)
pub(crate) fn read_cstr_strndup(p: u64, n: usize) -> Result<String, i64> {
    if p == 0 || p >= USER_VA_END { return Err(-(Errno::Efault.as_i32() as i64)); }
    // SAFETY: p in user range; bounded read via the shared helper, which stops
    // at the first NUL or at `n` bytes, whichever comes first.
    let b = unsafe { devfs::read_user_cstr(p, n) }
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    crate::fsconfig_abi::strndup_admit(b, n)
        .map(|s| s.to_string())
        .map_err(|e| -(e.as_i32() as i64))
}

/// # C: O(1)
pub(crate) fn install_fd(inode: InodeRef, name: &str, cloexec: bool) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = vfs::dcache::d_alloc_pseudo(name, inode.clone(), &crate::anon_dname::ANON_INODE_OPS);
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => { if cloexec { let _ = fdt.set_cloexec(fd, true); } fd as i64 }
        Err(e) => -(e as i64),
    }
}

/// Install the `O_PATH` file returned by non-clone `open_tree(2)`. Linux uses
/// `dentry_open(&path, O_PATH, current_cred())`, so the fd must retain the
/// resolved mount id and dentry rather than becoming an anonymous inode.
/// # C: O(1)
pub(crate) fn install_path_fd(path: vfs::VfsPath, cloexec: bool) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cred = match crate::pathresolve::file_cred_for(cur) {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = File::new_at(
        path.inode, path.dentry, OpenFlags::O_PATH, path.mnt_id, cred,
    );
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => {
            if cloexec { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
        Err(e) => -(e as i64),
    }
}

/// # C: O(1)
pub(crate) fn fd_inode(fd: i32) -> Option<InodeRef> {
    fd_file(fd).map(|f| f.inode().clone())
}

/// `fget_raw(fd)` (`fs/file.c`) — the open file description behind `fd` with a
/// reference held for the caller, O_PATH descriptions included. `fsconfig`'s
/// `FSCONFIG_SET_FD` pins the file this way so the parameter survives the
/// caller closing the fd mid-parse (`fs/fsopen.c`). # C: O(1)
pub(crate) fn fd_file(fd: i32) -> Option<Arc<File>> {
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(fd).ok()
}

/// Install the `fsmount(2)` fd: an `O_PATH` file over the anonymous mount's
/// root, marked as the mount's sole holder.
///
/// Linux `dentry_open(&new_path, O_PATH, fc->cred)` followed by `f_mode |=
/// FMODE_NEED_UNMOUNT`. Being a path fd is what makes it usable as a `dirfd`
/// and what gives it a real mount id; the mark is what stops the mount leaking
/// when the fd is closed without a `move_mount(2)`.
/// # C: O(1)
pub(crate) fn install_mount_path_fd(path: vfs::VfsPath, mnt_id: u64, cloexec: bool) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cred = match crate::pathresolve::file_cred_for(cur) {
        Some(c) => c,
        None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = File::new_at(path.inode, path.dentry, OpenFlags::O_PATH, path.mnt_id, cred);
    file.set_need_unmount(mnt_id);
    match fdt.alloc_limit(file, cur.nofile_soft()) {
        Ok(fd) => { if cloexec { let _ = fdt.set_cloexec(fd, true); } fd as i64 }
        Err(e) => -(e as i64),
    }
}
