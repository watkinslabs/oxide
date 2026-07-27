// `getcwd(2)` / `chdir(2)` / `fchdir(2)` / `chroot(2)` work-fns — Linux
// `fs/d_path.c` (`SYSCALL_DEFINE2(getcwd)` → `prepend_path`) and `fs/open.c`
// (`chdir`, `fchdir`, `chroot` → `path_permission(MAY_EXEC | MAY_CHDIR)` →
// `set_fs_pwd` / `set_fs_root`).
// The syscall shims own only argument fetch, path/fd resolution, and the
// user-buffer copy-out.

extern crate alloc;

use alloc::string::String;

use syscall::errno::Errno;
use vfs::{FileType, VfsPath};

/// Prefix Linux `getcwd(2)` prepends when `prepend_path` could not reach the
/// caller's root — the pwd escaped the chroot (Linux `fs/d_path.c`).
const UNREACHABLE_PREFIX: &str = "(unreachable)";

/// Render the caller's current working directory the way Linux does: from the
/// LIVE `(vfsmount, dentry)` pwd pair on every call, never from a string
/// captured at `chdir` time. Renaming an ancestor of the cwd therefore shows
/// up immediately, and no path string is a second source of truth.
///
/// Errors follow `SYSCALL_DEFINE2(getcwd)` exactly:
/// - `ENOENT` when the pwd dentry is unlinked (`d_unlinked`) — a removed
///   directory has no name to report, and this is NOT the `" (deleted)"`
///   suffix, which belongs to `/proc/<pid>/cwd` readlink rendering.
/// - `ENAMETOOLONG` when the rendered path plus its NUL exceeds `PATH_MAX`.
/// A pwd outside the caller's root renders `"(unreachable)"`-prefixed rather
/// than failing. The `ERANGE`/`EFAULT` half belongs to the copy-out and stays
/// in the shim. # C: O(depth)
pub fn getcwd_path() -> Result<String, i64> {
    let Some(cur) = sched::current() else {
        return Err(-(Errno::Einval.as_i32() as i64));
    };
    let snapshot = cur.fs_context_snapshot();
    // No pwd path installed yet (pre-`chdir` init context) — the pwd is the
    // filesystem root, which is what the context was constructed with.
    let Some(pwd) = snapshot.cwd_vfs() else { return Ok(String::from("/")) };
    if pwd.dentry.is_unlinked() { return Err(-(Errno::Enoent.as_i32() as i64)); }
    let absolute = vfs::mount::render_path_for_mount(pwd.mnt_id, &pwd.dentry);
    let root = snapshot.root_vfs()
        .map(|r| vfs::mount::render_path_for_mount(r.mnt_id, &r.dentry));
    // `project_path_under_root(_, None)` is the unconfined `/` root.
    let confine = root.as_deref().filter(|r| *r != "/");
    let rendered = match vfs::mount::project_path_under_root(&absolute, confine) {
        Some(path) => path,
        None => {
            let mut out = String::from(UNREACHABLE_PREFIX);
            out.push_str(&absolute);
            out
        }
    };
    // Linux measures the NUL-terminated length against PATH_MAX.
    if rendered.len() + 1 > vfs::path::PATH_MAX {
        return Err(-(Errno::Enametoolong.as_i32() as i64));
    }
    Ok(rendered)
}

/// `set_fs_pwd` half of `chdir(2)` / `fchdir(2)` (Linux `fs/open.c`): require a
/// directory, then `MAY_EXEC` search permission on it (`EACCES`), then install
/// it as the shared filesystem owner's pwd. Both syscalls converge here, which
/// is why `fchdir` is permission-checked at all — Linux runs the same
/// `MAY_EXEC | MAY_CHDIR` test through `file_permission`. # C: O(depth)
pub fn set_fs_pwd(path: VfsPath, cred: &vfs::Cred) -> i64 {
    if !matches!(path.inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let Some(cur) = sched::current() else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if let Err(e) = vfs::inode_permission(&path.inode, vfs::MAY_EXEC, cred) {
        return -(e as i64);
    }
    let rendered = vfs::mount::render_path_for_mount(path.mnt_id, &path.dentry);
    cur.set_fs_cwd(rendered, path);
    0
}

/// `set_fs_root` half of `chroot(2)` (Linux `fs/open.c`
/// `SYSCALL_DEFINE1(chroot)`), in Linux's exact order:
///
/// ```text
/// error = filename_lookup(AT_FDCWD, name, LOOKUP_FOLLOW|LOOKUP_DIRECTORY, &path, NULL);
/// if (error) return error;                       /* shim: resolution errno  */
/// error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
/// if (error) goto dput_and_out;                  /* EACCES                  */
/// error = -EPERM;
/// if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT)) goto dput_and_out;
/// set_fs_root(current->fs, &path);
/// ```
///
/// The order matters and is observable: a caller WITHOUT `CAP_SYS_CHROOT`
/// naming an unsearchable directory gets EACCES, not EPERM. `permitted` is a
/// closure so it is evaluated only at Linux's point in the ladder.
///
/// `chroot` deliberately leaves the pwd alone — that asymmetry is the classic
/// escape route (`chroot(dir)` without `chdir(dir)` leaves the cwd outside the
/// new root), and reproducing it is required for `RootDirectory=` parity.
///
/// The root is installed on the SHARED `FsContext` (Linux `fs_struct`), so a
/// `CLONE_FS` sibling sees the new root and a `fork(2)` child gets a private
/// copy of it. # C: O(depth)
pub fn set_fs_root(path: VfsPath, cred: &vfs::Cred, permitted: impl FnOnce() -> bool) -> i64 {
    if !matches!(path.inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let Some(cur) = sched::current() else {
        return -(Errno::Einval.as_i32() as i64);
    };
    if let Err(e) = vfs::inode_permission(&path.inode, vfs::MAY_EXEC, cred) {
        return -(e as i64);
    }
    if !permitted() { return -(Errno::Eperm.as_i32() as i64); }
    let rendered = vfs::mount::render_path_for_mount(path.mnt_id, &path.dentry);
    cur.set_fs_root(rendered, path);
    0
}
