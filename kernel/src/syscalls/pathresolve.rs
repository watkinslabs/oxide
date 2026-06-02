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
use sync::{MountTable as RootClass, Spinlock};

/// Cached root dentry — the start of every absolute `path_lookup`. Built
/// lazily from the ext4 root inode (ext4 is mounted at `/`). One global
/// node shared by all tasks (dentries are process-independent; only
/// cwd/root pointers are per-task). chroot/dirfd bases ride later stages.
static ROOT_DENTRY: Spinlock<Option<Arc<vfs::Dentry>>, RootClass> = Spinlock::new(None);

fn root_dentry() -> Option<Arc<vfs::Dentry>> {
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
    // SAFETY: task.root single-mutator per 13§5; the running task on this
    // CPU is the sole writer (chroot only mutates the calling task's root).
    let rp = unsafe { (*cur.root.get()).clone() };
    if rp == "/" { return Some((global, false)); }
    let f = vfs::LookupFlags::default();
    let (_i, d) = vfs::path_lookup(global.clone(), global, &rp, f).ok()?;
    Some((d, true))
}

/// Resolve absolute `abs` to its inode via the dentry path-walk
/// (`vfs::path_lookup`) — THE resolver (`docs/16§3`): per-component,
/// crossing mounts (`mount_root_at`) and delegating whole-path
/// filesystems (`mount_whole_path`) to their owning mount, following
/// symlinks (intermediate always; final unless `no_follow_final`) with
/// ELOOP at depth>40, confined to the task's chroot root. Returns `None`
/// if unresolved or ext4 isn't mounted yet (very early boot).
/// `no_follow_final` = O_NOFOLLOW / AT_SYMLINK_NOFOLLOW (lstat).
/// # C: O(components × dir-lookup)
pub fn resolve(abs: &str, no_follow_final: bool) -> Option<vfs::InodeRef> {
    let (root, beneath) = resolution_root()?;
    let flags = vfs::LookupFlags { no_follow_final, beneath, ..Default::default() };
    vfs::path_lookup(root.clone(), root, abs, flags).ok().map(|(i, _)| i)
}

/// Resolve absolute `abs` to its canonical DENTRY (not just the inode)
/// via the dentry path-walk, following the final symlink. Installed as
/// `vfs::mount`'s mount-point dentry resolver so `register`/`register_bind`
/// can mark the mounted-on dentry by identity (`docs/16§3`). A bind target
/// of `/proc/self/fd/N` follows the magic symlink to the real file's
/// dentry (e.g. /etc/machine-id) — the Linux mount-target semantics.
/// `None` pre-mount (root dentry not built yet) or if `abs` doesn't
/// resolve. # C: O(components × dir-lookup)
pub fn resolve_dentry(abs: &str) -> Option<Arc<vfs::Dentry>> {
    let (root, beneath) = resolution_root()?;
    let flags = vfs::LookupFlags { beneath, ..Default::default() };
    vfs::path_lookup(root.clone(), root, abs, flags).ok().map(|(_, d)| d)
}

/// Read an executable's full bytes by resolving `path` through the
/// dentry walk (`resolve`, follows symlinks + crosses mounts), then
/// pulling the regular-file contents via the inode's `read`. THE exec
/// loader path (`docs/16§3`, `31§4`): `/bin/sh`→`busybox` symlinks and
/// merged-usr `/bin`→`/usr/bin` resolve here exactly as Linux's
/// `do_open_execat` walks the path. Returns `None` when the root dentry
/// isn't built yet (pre-mount early boot — caller falls back to the raw
/// ext4 reader), when the path doesn't resolve, or when the target isn't
/// a regular file.
/// # C: O(components) + O(size/PAGE)
pub fn read_exec(path: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    if root_dentry().is_none() { return None; }       // pre-mount: caller falls back
    let s = core::str::from_utf8(path).ok()?;
    let abs = resolve_cwd(s);
    let inode = resolve(abs.as_str(), false)?;        // execve follows symlinks
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
pub fn resolve_at(dirfd: i32, raw: &str) -> Option<String> {
    const AT_FDCWD: i32 = -100;
    if raw.starts_with('/') {
        return Some(vfs::path::lexical_normalize(raw).unwrap_or_else(|| raw.into()));
    }
    if dirfd == AT_FDCWD {
        return Some(resolve_cwd(raw));
    }
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    let f = fdt.get(dirfd).ok()?;
    let base_bytes = f.dentry().absolute_path();
    let base = core::str::from_utf8(&base_bytes).ok()?;
    Some(vfs::path::resolve_against_cwd(base, raw).unwrap_or_else(|| {
        let mut s = String::from(base);
        if !s.ends_with('/') { s.push('/'); }
        s.push_str(raw);
        s
    }))
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
