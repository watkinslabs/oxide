// Shared path-resolution helpers used by every syscall that takes a
// user-mode path argument. Centralizes the cwd-join + lexical-normalize
// dance so we don't fork the rule (skip "." vs preserve ".", etc.) per
// callsite.
//
// All resolution is lexical only (no FS lookup, no symlink expansion).
// Caller hands the result to vfs::mount::lookup / ext4::rootfs::* /
// other backends.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use syscall::errno::Errno;
use sync::{MountTable as RootClass, Spinlock};

pub const AT_FDCWD: i32 = -100;

/// Cached root dentry — the start of every absolute `path_lookup`. Built
/// lazily from the ext4 root inode (ext4 is mounted at `/`). One global
/// node shared by all tasks (dentries are process-independent; only
/// cwd/root pointers are per-task). chroot/dirfd bases ride later stages.
static ROOT_DENTRY: Spinlock<Option<Arc<vfs::Dentry>>, RootClass> = Spinlock::new(None);

pub fn root_dentry() -> Option<Arc<vfs::Dentry>> {
    {
        let g = ROOT_DENTRY.lock();
        if let Some(d) = g.as_ref() { return Some(d.clone()); }
    }
    let root_inode = ext4::rootfs::lookup_inode_any(b"/")?;
    let d = vfs::Dentry::new_root(root_inode);
    let mut g = ROOT_DENTRY.lock();
    Some(g.get_or_insert(d).clone())
}

/// The resolution root + whether to confine `..` to it. For a non-chrooted
/// task (`task.root == "/"`, the default) this is the global ext4 root with
/// no `..` clamp — identical to pre-chroot behaviour. After `chroot(jail)`,
/// it resolves `jail` to its dentry and returns `(jail_dentry, beneath=true)`
/// so every absolute path restarts at the jail and `..` cannot ascend above
/// it (Linux chroot confinement, `13§5`). Boot-safe: nothing chroots at boot.
/// # C: O(1) un-chrooted; O(jail components) chrooted
fn resolution_root() -> Option<(Arc<vfs::Dentry>, bool)> {
    let global = root_dentry()?;
    let Some(cur) = sched::live::current() else { return Some((global, false)); };
    // SAFETY: task.root_vfs single-mutator per 13§5; the running task on
    // this CPU is the sole writer.
    if let Some(p) = unsafe { (*cur.root_vfs.get()).clone() } {
        return Some((p.dentry, true));
    }
    // SAFETY: task.root single-mutator per 13§5; the running task on this
    // CPU is the sole writer (chroot only mutates the calling task's root).
    let rp = unsafe { (*cur.root.get()).clone() };
    if rp == "/" { return Some((global, false)); }
    let f = vfs::LookupFlags::default();
    let (_i, d) = vfs::path_lookup(global.clone(), global, &rp, f).ok()?;
    Some((d, true))
}

/// Resolve absolute `abs` to its inode via the dentry path-walk
/// (`vfs::path_lookup`) — THE resolver (`docs/16§3`): ALWAYS per-component
/// (`d_lookup → i_op->lookup → d_add`), crossing mounts at each mount root
/// (`mount_root_at`), following symlinks (intermediate always; final unless
/// `no_follow_final`) with ELOOP at depth>40, confined to the task's chroot
/// root. Returns `None` if unresolved or ext4 isn't mounted yet (very early
/// boot). `no_follow_final` = O_NOFOLLOW / AT_SYMLINK_NOFOLLOW (lstat).
/// # C: O(components × dir-lookup)
pub fn resolve(abs: &str, no_follow_final: bool) -> Option<vfs::InodeRef> {
    resolve_path(abs, no_follow_final).map(|p| p.inode)
}

/// Resolve absolute `abs` to its full VFS path object.
/// # C: O(components × dir-lookup)
pub fn resolve_path(abs: &str, no_follow_final: bool) -> Option<vfs::VfsPath> {
    let (root, beneath) = resolution_root()?;
    let flags = vfs::LookupFlags { no_follow_final, beneath, ..Default::default() };
    let Some(cur) = sched::live::current() else {
        return vfs::path_lookup_path(root.clone(), root, abs, flags).ok();
    };
    // SAFETY: single-mutator per 13§5; current task is the sole writer.
    let start = unsafe { (*cur.cwd_vfs.get()).clone().map(|p| p.dentry) }
        .unwrap_or_else(|| root.clone());
    vfs::path_lookup_path(start, root, abs, flags).ok()
}

/// Resolve a mount-point path `abs` to the `Arc<Dentry>` the mount engine
/// takes (the single namei walk Linux `do_mount` hands `mnt_set_mountpoint`
/// as `struct path.dentry`). Follows the final symlink — a bind target of
/// `/proc/self/fd/N` lands on the real file's dentry (e.g. /etc/machine-id),
/// the Linux mount-target semantics. `None` pre-mount (root dentry not built
/// yet) or if `abs` doesn't resolve (target missing → caller ENOENT).
/// # C: O(components × dir-lookup)
pub fn mount_dentry(abs: &str) -> Option<Arc<vfs::Dentry>> {
    resolve_path(abs, false).map(|p| p.dentry)
}

/// Invalidate the cached child dentry for absolute `abs` (Linux `d_delete`).
/// MUST be called after a successful unlink / rmdir / rename so a stale
/// POSITIVE dentry isn't reused: without it, `stat`/`open` after `unlink`
/// resolve the dead inode through the dcache (reporting the file still
/// exists), e.g. Info-ZIP's `replace()` LSTATs the just-unlinked output
/// and then fails to re-unlink it. Splits `abs` into parent + final
/// component, resolves the PARENT via the chroot-aware namei walk (NOT a
/// mount-engine resolver), and drops the child from its dentry cache.
/// # C: O(components)
pub fn d_delete_path(abs: &str) {
    let trimmed = abs.trim_end_matches('/');
    if trimmed.is_empty() { return; }
    let (parent, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None    => return,
    };
    if name.is_empty() { return; }
    if let Some(pd) = resolve_path(parent, false).map(|p| p.dentry) {
        pd.forget_child(name);
    }
}

/// Read an executable's full bytes by resolving `path` through the
/// dentry walk (`resolve`, follows symlinks + crosses mounts), then
/// pulling the regular-file contents via the inode's `read`. THE exec
/// loader path (`docs/16§3`, `31§4`): `/bin/sh`→`bash` symlinks and
/// merged-usr `/bin`→`/usr/bin` resolve here exactly as Linux's
/// `do_open_execat` walks the path. Returns `None` when the root dentry
/// isn't built yet (pre-mount early boot — caller falls back to the raw
/// ext4 reader), when the path doesn't resolve, or when the target isn't
/// a regular file.
/// # C: O(components) + O(size/PAGE)
pub fn read_exec(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let s = core::str::from_utf8(path).ok()?;
    let abs = resolve_cwd(s);
    // Magic fd-link exec: `/proc/{self|<pid>}/fd/<n>`, `/dev/fd/<n>`,
    // `/dev/std{in,out,err}` exec the OPEN file description's backing
    // inode directly — mirroring open(2)'s `dup_fd_target` fast-path
    // (`open_common::dup_fd_target` → `proc_fd_file`). Linux
    // `do_execveat_common` execs a `struct file`, never a path re-resolve;
    // a sealed memfd's d_path (`/memfd:NAME (deleted)`) can never
    // re-resolve, so the per-component walk below would wrongly return
    // ENOENT. fd-based load is also valid pre-mount (no root dentry yet).
    if let Some((tid_opt, fd)) = vfs::path::dup_fd_target(&abs) {
        let file = sched::proclink::proc_fd_file(tid_opt, fd)?;
        return read_exec_inode(file.inode());
    }
    if root_dentry().is_none() { return None; }       // pre-mount: caller falls back
    let inode = resolve_path(abs.as_str(), false)?.inode;        // execve follows symlinks
    read_exec_inode(&inode)
}

/// Read a regular-file inode's full contents (the exec read loop). Shared
/// by `read_exec`'s path walk and its magic-fd fast-path so the byte read
/// is identical whether the executable came from a pathname or an open
/// file description (memfd / `/proc/self/fd/N` / `fexecve`). `None` if the
/// inode isn't a regular file or a read errors mid-stream.
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

/// Resolve a `(dirfd, raw)` pair to an absolute, lexically-normalised
/// path — real `openat(2)`/`*at` dirfd semantics (`docs/16§3`). THE
/// shared dirfd resolver every `*at` syscall routes through (aarch64
/// musl has only the `*at` forms, so this is the arm path too):
///   - absolute `raw` → ignore dirfd, lexically normalise;
///   - `dirfd == AT_FDCWD` → resolve against the task cwd;
///   - a real `dirfd` → resolve against THAT fd's directory (its open
///     File's dentry absolute path), as `openat` does.
/// `None` on a bad dirfd / no current task.
/// # C: O(N_path) + O(1) fd lookup
pub fn resolve_at_result(dirfd: i32, raw: &str) -> Result<String, i64> {
    if raw.starts_with('/') {
        return Ok(vfs::path::lexical_normalize(raw).unwrap_or_else(|| raw.into()));
    }
    if dirfd == AT_FDCWD {
        return Ok(resolve_cwd(raw));
    }
    let cur = sched::live::current().ok_or(-(Errno::Ebadf.as_i32() as i64))?;
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }
        .ok_or(-(Errno::Ebadf.as_i32() as i64))?
        .clone();
    let f = fdt.get(dirfd).map_err(|_| -(Errno::Ebadf.as_i32() as i64))?;
    if f.inode().file_type() != vfs::FileType::Directory {
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    let base_bytes = f.dentry().absolute_path();
    let base = core::str::from_utf8(&base_bytes)
        .map_err(|_| -(Errno::Enotdir.as_i32() as i64))?;
    Ok(vfs::path::resolve_against_cwd(base, raw).unwrap_or_else(|| {
        let mut s = String::from(base);
        if !s.ends_with('/') { s.push('/'); }
        s.push_str(raw);
        s
    }))
}

pub fn resolve_at(dirfd: i32, raw: &str) -> Option<String> {
    resolve_at_result(dirfd, raw).ok()
}

/// Resolve `raw` against the running task's cwd. Absolute paths
/// short-circuit through the lexical normalizer (collapses `.` /
/// `..`); relative paths are joined to cwd then normalized.
/// Falls back to the raw string only when no current task or the
/// normalize step rejected `..`-escapes-root.
/// # C: O(N_path components)
pub fn resolve_cwd(raw: &str) -> String {
    if raw.starts_with('/') {
        return vfs::path::lexical_normalize(raw).unwrap_or_else(|| raw.into());
    }
    let Some(cur) = sched::live::current() else { return raw.into(); };
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, raw).unwrap_or_else(|| raw.into())
}
