// `sys_chroot(path)` — slot 161 (F95). Per-task root prefix that
// devfs::lookup applies to absolute paths. Inherited by fork; cleared
// only via explicit chroot. Requires CAP_SYS_CHROOT.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_chroot(path)` — slot 161.
/// # C: O(len)
pub fn sys_chroot(args: &SyscallArgs) -> i64 {
    let p = args.a0;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_CHROOT) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    // D1/D2: PATH_MAX errno contract (EFAULT/ENOENT-on-empty/ENAMETOOLONG).
    let path = match crate::namei_common::read_user_path(p) {
        Ok(s)   => s,
        Err(rv) => return rv,
    };
    let s: &str = path.as_str();
    // chroot(2) accepts a RELATIVE path (resolved against cwd) — Linux
    // `set_fs_root` takes `user_path_at(AT_FDCWD, ...)`. systemd's
    // `mount_switch_root` does `chroot(".")` after MS_MOVE-ing the assembled
    // sandbox root onto `/` and `chdir`-ing into it; rejecting non-absolute
    // paths failed that with EINVAL (step NAMESPACE status=226).
    //
    // A relative path MUST resolve against the cwd DENTRY via namei, NOT by
    // re-resolving the cwd path STRING: the MS_MOVE/pivot that just ran
    // relocated the sandbox root, so the cwd's recorded path string is stale
    // and re-resolving it ENOENTs (the chroot then returns ENOENT, the same
    // step-NAMESPACE failure). `resolve_path` walks from `cwd_vfs.dentry`,
    // which travelled WITH the moved mount, landing on the live moved root.
    // An absolute path keeps the legacy nested-chroot prefix concat (F95).
    // # C: O(components)
    let (new_root, root_obj) = if !s.starts_with('/') {
        let p = match crate::pathresolve::resolve_path_result(s, false) {
            Ok(p) if matches!(p.inode.file_type(), vfs::FileType::Directory) => p,
            Ok(_)  => return -(Errno::Enotdir.as_i32() as i64),
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        let abs = alloc::string::String::from_utf8(p.dentry.absolute_path())
            .unwrap_or_else(|_| alloc::string::String::from("/"));
        (abs, p)
    } else {
        // SAFETY: task.root single-mutator per `13§5`; running task on this CPU is the sole writer (chroot only mutates the calling task's root).
        let new_root = unsafe {
            let cur_root = (*cur.root.get()).clone();
            if cur_root == "/" {
                alloc::string::String::from(s)
            } else {
                let mut out = cur_root;
                if out.ends_with('/') { out.pop(); }
                out.push_str(s);
                out
            }
        };
        let p = match crate::pathresolve::resolve_path_result(&new_root, false) {
            Ok(p) if matches!(p.inode.file_type(), vfs::FileType::Directory) => p,
            Ok(_)  => return -(Errno::Enotdir.as_i32() as i64),
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        };
        (new_root, p)
    };
    // SAFETY: task.root/root_vfs single-mutator per `13§5`; the running task on this CPU is the sole writer (chroot only mutates the calling task's root).
    unsafe {
        *cur.root.get() = new_root;
        *cur.root_vfs.get() = Some(root_obj);
    }
    0
}
