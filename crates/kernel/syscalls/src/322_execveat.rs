// sys_execveat (NR_EXECVEAT=322) per docs/53§0 — per-syscall-file module.
// ABI shim: validates the AT_* flags, resolves the target the way
// `do_execveat_common`/`do_open_execat` do, then hands a resolved pathname to
// the shared `execve_inner`. The flag/empty-path/file-type rules live in
// `execveat_at.rs` (non-gated, hosted-tested); shared execve machinery lives
// in `execve_common.rs`.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::execveat_at::{
    AT_EXECVE_CHECK, AT_SYMLINK_NOFOLLOW, empty_path_verdict, fd_exec_path,
    join_dirfd_path, may_exec_file_type, needs_dirfd_base, validate_flags,
};
use crate::pathresolve::AT_FDCWD;
use crate::s059_execve::execve_inner;

#[inline]
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `execveat(dirfd, path, argv, envp, flags)` — `SYSCALL_DEFINE5(execveat)`.
/// `AT_EMPTY_PATH` execs the open file description behind
/// `dirfd` (the kernel side of `fexecve(3)`); a relative pathname resolves
/// from `dirfd`; `AT_SYMLINK_NOFOLLOW` refuses a symlink target with `ELOOP`;
/// `AT_EXECVE_CHECK` runs the checks and returns without exec'ing.
/// # C: O(path + dentry depth) + execve_inner cost
pub fn sys_execveat(args: &SyscallArgs) -> i64 {
    let dirfd = args.a0 as i32;
    let pathp = args.a1;
    let argv  = args.a2;
    let envp  = args.a3;
    // Linux declares `int flags`; only the low 32 bits reach the handler.
    let flags = args.a4 as u32;
    // `do_open_execat` rejects undefined bits BEFORE `do_file_open` unwraps
    // the `getname_uflags` result, so EINVAL outranks the EFAULT/ENOENT a bad
    // or empty pathname would otherwise produce.
    if let Err(e) = validate_flags(flags) { return err(e); }
    let empty = match crate::pathresolve::at_path_empty(pathp) {
        Ok(b) => b, Err(rv) => return rv,
    };
    if empty {
        if let Err(e) = empty_path_verdict(flags) { return err(e); }
        return exec_open_fd(dirfd, argv, envp, flags);
    }
    exec_pathname(dirfd, pathp, argv, envp, flags)
}

/// `AT_EMPTY_PATH`: exec the file description `dirfd` already holds.
/// `path_init` fetches it with `fd_raw` — so an `O_PATH` fd is accepted — and
/// `may_open` then applies the file-type ladder to its inode (an `AT_FDCWD`
/// "empty path" lands on the cwd DIRECTORY, hence EACCES).
/// # C: O(1) + execve_inner cost
fn exec_open_fd(dirfd: i32, argv: u64, envp: u64, flags: u32) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Ebadf) };
    // SAFETY: running task; sole reader of fd_table slot per `13§5`.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return err(Errno::Ebadf),
    };
    let inode = if dirfd == AT_FDCWD {
        match cur.fs_context_snapshot().cwd_vfs() { Some(p) => p.inode, None => return err(Errno::Ebadf) }
    } else {
        match fdt.get(dirfd) { Ok(f) => f.inode().clone(), Err(_) => return err(Errno::Ebadf) }
    };
    if let Err(e) = may_exec_file_type(inode.file_type()) { return err(e); }
    if flags & AT_EXECVE_CHECK != 0 { return exec_permission(&inode); }
    // Exec the open file description, never a re-walked pathname: `/dev/fd/N`
    // is the spelling `alloc_bprm` records AND the one oxide's
    // `pathresolve::lookup::dup_fd_target` short-circuits to
    // `proc_fd_file` — a pure string fast-path that needs no `/proc` mount, so
    // a sealed memfd (whose synthetic d_path can never re-resolve on any
    // filesystem) still execs.
    exec_with_path(fd_exec_path(dirfd), argv, envp)
}

/// Non-empty pathname. Resolution starts at `dirfd` unless the pathname is
/// absolute or `dirfd` is `AT_FDCWD` (`path_init`).
/// # C: O(components × dir-lookup) + execve_inner cost
fn exec_pathname(dirfd: i32, pathp: u64, argv: u64, envp: u64, flags: u32) -> i64 {
    let raw = match crate::namei_common::read_user_path(pathp) { Ok(s) => s, Err(rv) => return rv };
    let nofollow = flags & AT_SYMLINK_NOFOLLOW != 0;
    let at_base  = needs_dirfd_base(dirfd, &raw);
    let check    = flags & AT_EXECVE_CHECK != 0;
    let mut path = raw;
    if at_base || nofollow || check {
        // `AT_SYMLINK_NOFOLLOW` clears `LOOKUP_FOLLOW`.
        let lf = vfs::LookupFlags { no_follow_final: nofollow, follow: !nofollow, ..Default::default() };
        match crate::pathresolve::resolve_at_path(dirfd, &path, lf) {
            Ok(vp) => {
                if nofollow || check {
                    if let Err(e) = may_exec_file_type(vp.inode.file_type()) { return err(e); }
                }
                // The full gate, mount included: Linux's `AT_EXECVE_CHECK`
                // runs the same `may_open` a real exec would, so a `noexec`
                // mount must answer EACCES here too.
                if check {
                    return match crate::pathresolve::exec_permission(&vp) { Ok(()) => 0, Err(rc) => rc };
                }
                if at_base {
                    // `execve_inner` re-resolves from the task's cwd/root, so
                    // the dirfd-relative walk has to be rendered back into a
                    // pathname the second walk reaches.
                    path = render_resolved(&vp, dirfd, &path);
                }
            }
            // Only the dirfd-relative walk has no fallback: `execve_inner`
            // would silently re-resolve against the cwd, which is the wrong
            // directory. An absolute/AT_FDCWD miss keeps falling through so
            // `execve_inner`'s own loader (including its ext4 rootfs path)
            // still gets its turn and reports the error.
            Err(rv) => if at_base || check { return rv; },
        }
    }
    exec_with_path(path, argv, envp)
}

/// Render a resolved `VfsPath` back to a pathname the follow-up walk in
/// `execve_inner` reaches. Falls back to splicing the dirfd's own rendered
/// directory path with the relative pathname when the target itself has no
/// renderable path.
/// # C: O(path len)
fn render_resolved(vp: &vfs::VfsPath, dirfd: i32, rel: &str) -> String {
    let rendered = vfs::mount::render_path_for_mount(vp.mnt_id, &vp.dentry);
    if rendered.starts_with('/') && rendered.len() > 1 { return rendered; }
    let cur = match sched::live::current() { Some(c) => c, None => return rendered };
    // SAFETY: running task; sole reader of fd_table slot per `13§5`.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return rendered };
    let f = match fdt.get(dirfd) { Ok(f) => f, Err(_) => return rendered };
    join_dirfd_path(&vfs::mount::render_path_for_mount(f.mnt_id(), f.dentry()), rel)
}

/// `AT_EXECVE_CHECK` for an exec'able reached through a file
/// DESCRIPTOR, which carries no resolved mount: everything `bprm_execve` does
/// up to and including the credential check runs, then the call returns without
/// parsing or replacing the image. The pathname form uses
/// `pathresolve::exec_permission`, which adds the `noexec` mount test.
/// # C: O(1)
fn exec_permission(inode: &vfs::InodeRef) -> i64 {
    match vfs::inode_permission(inode, vfs::MAY_EXEC, &crate::pathresolve::current_cred()) {
        Ok(()) => 0,
        Err(e) => crate::namei_common::errno_from_vfs(e),
    }
}

/// Hand a resolved pathname to the shared execve body. `execve_inner` reads
/// argv/envp from `a1`/`a2` and takes the pathname as its second argument.
/// # C: execve_inner cost
fn exec_with_path(path: String, argv: u64, envp: u64) -> i64 {
    let sa = SyscallArgs { a0: 0, a1: argv, a2: envp, a3: 0, a4: 0, a5: 0 };
    execve_inner(&sa, path.into_bytes())
}
