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
use hal::USER_VA_END;
use syscall::errno::Errno;
use sync::{MountTable as RootClass, Spinlock};
use vfs::fs::FileSystem;

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

/// Snapshot the running task's credentials into the VFS `Cred` (Linux
/// `current_cred()` subset: fsuid/fsgid + the two DAC-bypass caps).
/// Used at open to populate `file->f_cred`. Falls back to root when
/// there is no current task (early boot / host paths).
/// # C: O(1)
pub fn current_cred() -> vfs::Cred {
    cred_for(false)
}

/// Like `current_cred()` but built from the task's REAL uid/gid rather than
/// the fsuid/fsgid. `access(2)` (without `AT_EACCESS`) checks against the
/// real ids per POSIX; `faccessat2(AT_EACCESS)` and every other path use the
/// effective (fs) ids. # C: O(NGROUPS)
pub fn current_cred_real() -> vfs::Cred {
    cred_for(true)
}

/// Snapshot the running task's credentials into the VFS `Cred`: fsuid/fsgid
/// (or ruid/rgid when `real`), supplementary groups, and the DAC/owner/chown
/// bypass caps. Falls back to root when there is no current task (early boot /
/// host paths). # C: O(NGROUPS)
fn cred_for(real: bool) -> vfs::Cred {
    use core::sync::atomic::Ordering;
    let Some(c) = sched::live::current() else { return vfs::Cred::root(); };
    let eff = c.creds.cap_effective.load(Ordering::Acquire);
    let (uid, gid) = if real {
        (c.creds.ruid.load(Ordering::Acquire), c.creds.rgid.load(Ordering::Acquire))
    } else {
        (c.creds.fsuid.load(Ordering::Acquire), c.creds.fsgid.load(Ordering::Acquire))
    };
    let ng = (c.creds.ngroups.load(Ordering::Acquire) as usize).min(vfs::CRED_NGROUPS);
    let mut groups = [0u32; vfs::CRED_NGROUPS];
    // SAFETY: groups slot is single-mutator per `13§5`; the running task on
    // this CPU is the sole writer, so this read of its own group list is sound.
    unsafe {
        let g = &*c.creds.groups.get();
        groups[..ng].copy_from_slice(&g[..ng]);
    }
    let has = |cap: u32| eff & (1u64 << cap) != 0;
    vfs::Cred {
        uid, gid,
        cap_dac_override:    has(sched::cap::DAC_OVERRIDE),
        cap_dac_read_search: has(sched::cap::DAC_READ_SEARCH),
        cap_fowner:          has(sched::cap::FOWNER),
        cap_chown:           has(sched::cap::CHOWN),
        cap_fsetid:          has(sched::cap::FSETID),
        ngroups: ng as u32,
        groups,
    }
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
    resolve_path_result(abs, no_follow_final).ok()
}

/// Like `resolve` but preserves the path-walk `VfsError` so the caller can
/// surface the true errno (ENOTDIR / ELOOP / ENAMETOOLONG / EACCES) per the
/// Linux contract instead of collapsing every miss to ENOENT.
/// # C: O(components × dir-lookup)
pub fn resolve_result(abs: &str, no_follow_final: bool) -> Result<vfs::InodeRef, vfs::VfsError> {
    resolve_path_result(abs, no_follow_final).map(|p| p.inode)
}

/// Resolve absolute `abs` to its full VFS path object, preserving the
/// path-walk error.
/// # C: O(components × dir-lookup)
pub fn resolve_path_result(abs: &str, no_follow_final: bool) -> Result<vfs::VfsPath, vfs::VfsError> {
    resolve_path_flags(abs, vfs::LookupFlags { no_follow_final, ..Default::default() })
}

/// Like `resolve_path_result` but with caller-supplied extra `LookupFlags` —
/// the openat2 RESOLVE_* bits that do NOT change the resolution START
/// (NO_SYMLINKS, NO_MAGICLINKS, NO_XDEV, CACHED, plus NO_FOLLOW). The chroot
/// `beneath`/root from `resolution_root` is OR-ed in (BENEATH/IN_ROOT, which
/// re-base the START on the dirfd, go through `resolve_confined`).
/// # C: O(components × dir-lookup)
pub fn resolve_path_flags(abs: &str, mut flags: vfs::LookupFlags) -> Result<vfs::VfsPath, vfs::VfsError> {
    let (root, beneath) = resolution_root().ok_or(vfs::VfsError::Enoent)?;
    flags.beneath = flags.beneath || beneath;
    let Some(cur) = sched::live::current() else {
        // No task (early boot / kernel-internal resolve): default-allow root cred.
        return vfs::path_lookup_cred(root.clone(), root, abs, flags, vfs::Cred::root());
    };
    // SAFETY: cwd_vfs slot single-mutator per 13§5; current task is the sole writer.
    let start = unsafe { (*cur.cwd_vfs.get()).clone().map(|p| p.dentry) }
        .unwrap_or_else(|| root.clone());
    // Enforce per-directory search permission (`may_lookup`, MAY_EXEC) against
    // the caller's cred (Linux `link_path_walk`). Root keeps CAP_DAC_OVERRIDE
    // so early boot / privileged services are unaffected.
    match vfs::path_lookup_cred(start, root, abs, flags, current_cred()) {
        Ok(p) => Ok(p),
        Err(vfs::VfsError::Enoent) if abs.starts_with("/proc/") => {
            resolve_procfs_fallback(abs).ok_or(vfs::VfsError::Enoent)
        }
        Err(e) => Err(e),
    }
}

/// openat2 RESOLVE_BENEATH / RESOLVE_IN_ROOT: the `dirfd` IS the scoped
/// resolution root. START and root both become the dirfd's dentry (the task
/// cwd for `AT_FDCWD`), so the vfs walker enforces the boundary itself — an
/// escape attempt under BENEATH errors `EXDEV`; under IN_ROOT `..`, absolute
/// paths and absolute symlink targets are confined to it. `raw` is walked
/// as-is (relative or absolute). `flags` must already carry beneath_exdev /
/// in_root. # C: O(components × dir-lookup)
pub fn resolve_confined(dirfd: i32, raw: &str, flags: vfs::LookupFlags) -> Result<vfs::VfsPath, i64> {
    let base = dirfd_dentry(dirfd)?;
    vfs::path_lookup_cred(base.clone(), base, raw, flags, current_cred())
        .map_err(crate::namei_common::errno_from_vfs)
}

/// The `Arc<Dentry>` a dirfd names (the resolution base for the confined
/// openat2 modes): the task cwd dentry for `AT_FDCWD`, else the open fd's
/// dentry (which must be a directory). `EBADF` for a bad fd / no task,
/// `ENOTDIR` for a non-directory fd. # C: O(1)
fn dirfd_dentry(dirfd: i32) -> Result<Arc<vfs::Dentry>, i64> {
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    let cur = sched::live::current().ok_or(ebadf)?;
    if dirfd == AT_FDCWD {
        // SAFETY: cwd_vfs slot single-mutator per 13§5; current task is sole writer.
        let cwd = unsafe { (*cur.cwd_vfs.get()).clone().map(|p| p.dentry) };
        return cwd.or_else(root_dentry).ok_or(ebadf);
    }
    // SAFETY: running task on this CPU; sole reader of its fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(ebadf)?.clone();
    let f = fdt.get(dirfd).map_err(|_| ebadf)?;
    if f.inode().file_type() != vfs::FileType::Directory {
        return Err(-(Errno::Enotdir.as_i32() as i64));
    }
    Ok(f.dentry().clone())
}

fn resolve_procfs_fallback(abs: &str) -> Option<vfs::VfsPath> {
    let rest = abs.strip_prefix("/proc/")?;
    if rest.is_empty() {
        return None;
    }
    let mut inode = procfs::static_files::proc_root() as vfs::InodeRef;
    let fs = Arc::new(procfs::fs_impl::ProcfsFs) as Arc<dyn FileSystem>;
    let sb = vfs::SuperBlock::for_backend(
        fs,
        Some(inode.clone()),
        0,
        String::from("procfs-fallback"),
    );
    let mut dentry = vfs::d_make_root(inode.clone(), &sb);
    for comp in rest.split('/').filter(|c| !c.is_empty()) {
        let child = match vfs::d_lookup(&dentry, comp) {
            Some(d) if !d.is_negative() => d,
            _ => {
                let ci = inode.lookup(comp).ok()?;
                vfs::d_add(&dentry, comp, ci)
            }
        };
        inode = child.inode()?;
        dentry = child;
    }
    Some(vfs::VfsPath { mnt_id: 0, dentry, inode, last_component: None })
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
/// mount-engine resolver), and `d_drop`s the child — UNHASHING it from the
/// global `DENTRY_HASHTABLE` (which `d_lookup` reads) and dropping its inode
/// alias, not merely forgetting the per-parent `d_subdirs` entry. A bare
/// `forget_child` left the child hashed, so `d_lookup` (the walker fast path)
/// still returned the dead positive dentry after unlink.
/// # C: O(components)
pub fn d_delete_path(abs: &str) {
    drop_cached_child(abs);
}

/// Flush the cached NEGATIVE dentry for absolute `abs` after a SUCCESSFUL
/// create (open O_CREAT / mknod / mkdir / symlink / hardlink) so a negative
/// planted by the pre-create existence probe (`path_exists`) — or by an earlier
/// `stat`/`open` of the not-yet-existing name — does NOT mask the freshly
/// created file. The next walk then misses the dcache and re-resolves via
/// `i_op->lookup`, finding the new inode. Linux instantiates the create's OWN
/// leaf dentry (`d_instantiate`); these create handlers bypass the leaf dentry
/// and call the backend on the parent inode, so the stale negative must be
/// dropped explicitly. Shares `drop_cached_child` with `d_delete_path` (it
/// `d_drop`s any cached child — positive or negative — unhashing it).
/// # C: O(components)
pub fn d_drop_path(abs: &str) {
    drop_cached_child(abs);
}

/// Split absolute `abs` into `(parent, name)` for the dcache mutation
/// helpers. `None` for `/`, an empty path, or a trailing-slash-only path.
/// # C: O(len)
fn split_parent_name(abs: &str) -> Option<(&str, &str)> {
    let trimmed = abs.trim_end_matches('/');
    if trimmed.is_empty() { return None; }
    let (parent, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None    => return None,
    };
    if name.is_empty() { return None; }
    Some((parent, name))
}

/// Resolve `abs`'s parent and `d_drop` the cached child (unhash from the
/// global `DENTRY_HASHTABLE` + drop its inode alias), else forget the bare
/// `d_subdirs` index entry. The shared core of `d_delete_path` (unlink/rmdir/
/// rename) and `d_drop_path` (post-create negative flush). # C: O(components)
fn drop_cached_child(abs: &str) {
    let Some((parent, name)) = split_parent_name(abs) else { return; };
    if let Some(pd) = resolve_path(parent, false).map(|p| p.dentry) {
        match pd.cached_child(name).or_else(|| vfs::d_lookup(&pd, name)) {
            Some(child) => vfs::d_drop(&child),
            None        => pd.forget_child(name),
        }
    }
}

/// Invalidate `abs`'s whole cached subtree (Linux `d_invalidate`): unhash the
/// dentry AND every cached descendant (e.g. negative dentries that accumulated
/// inside a now-removed directory). Used on rmdir success — a plain
/// single-name `d_drop` would leave those descendants hashed and reachable.
/// # C: O(subtree)
pub fn d_invalidate_path(abs: &str) {
    let Some((parent, name)) = split_parent_name(abs) else { return; };
    if let Some(pd) = resolve_path(parent, false).map(|p| p.dentry) {
        match pd.cached_child(name).or_else(|| vfs::d_lookup(&pd, name)) {
            Some(child) => vfs::d_invalidate(&child),
            None        => pd.forget_child(name),
        }
    }
}

/// Rehome the cached dentry for `from_abs` to `to_abs` (Linux `d_move`), the
/// dcache half of `rename(2)`. Resolves both parents, `d_drop`s any stale dentry
/// already cached at the destination name (so `d_move`'s `d_add` is not lost to
/// the `or_insert` race-winner), then `d_move`s the source child under the new
/// (parent,name). When nothing is cached at the source, falls back to dropping
/// both names so a later walk re-resolves. # C: O(components)
pub fn d_move_path(from_abs: &str, to_abs: &str) {
    let (Some((fp, fname)), Some((tp, tname))) =
        (split_parent_name(from_abs), split_parent_name(to_abs))
    else { drop_cached_child(from_abs); drop_cached_child(to_abs); return; };
    let from_pd = resolve_path(fp, false).map(|p| p.dentry);
    let to_pd   = resolve_path(tp, false).map(|p| p.dentry);
    let (Some(from_pd), Some(to_pd)) = (from_pd, to_pd) else {
        drop_cached_child(from_abs); drop_cached_child(to_abs); return;
    };
    // Drop any stale dentry sitting at the destination name first.
    if let Some(old) = to_pd.cached_child(tname).or_else(|| vfs::d_lookup(&to_pd, tname)) {
        vfs::d_drop(&old);
    }
    match from_pd.cached_child(fname).or_else(|| vfs::d_lookup(&from_pd, fname)) {
        Some(child) => { vfs::d_move(&child, &to_pd, tname); }
        None        => { from_pd.forget_child(fname); }
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

/// True if the user pathname at `ptr` is empty (`""`) or NULL — the
/// AT_EMPTY_PATH probe. A NULL pointer counts as empty (Linux lets
/// `path == NULL` stand in for `""` under AT_EMPTY_PATH); an out-of-range
/// non-NULL pointer is NOT treated as empty so the full read below raises
/// EFAULT. # C: O(1)
fn at_path_empty(ptr: u64) -> bool {
    if ptr == 0 { return true; }
    if ptr >= USER_VA_END { return false; }
    // SAFETY: ptr is non-NULL and below USER_VA_END (user range); a bounded
    // one-byte probe of the caller's mapped page tests only for an empty path.
    unsafe { devfs::read_user_cstr(ptr, 1) }.map_or(true, |b| b.is_empty())
}

/// THE centralized `*at` resolver: resolve a `(dirfd, path_ptr)` pair to its
/// `VfsPath` honoring AT_EMPTY_PATH through the engine's LOOKUP_EMPTY
/// (`flags.empty`) plus the trailing-symlink policy carried in `flags`
/// (`follow` / `no_follow_final`). Replaces the per-handler `if path.is_empty()`
/// special-casing: an EMPTY (or NULL) pathname with `flags.empty` set operates
/// on the dirfd's own open file — its inode + mount id, ANY file type (Linux
/// AT_EMPTY_PATH; `AT_FDCWD` → the task cwd); WITHOUT the flag an empty pathname
/// is ENOENT (the engine `path_init` contract). A non-empty pathname is read
/// with the full PATH_MAX errno contract (EFAULT / ENAMETOOLONG), resolved
/// against the dirfd (`resolve_at_result`), then walked through the engine
/// (`resolve_path_flags`) with `flags`. # C: O(components × dir-lookup)
pub fn resolve_at_lookup(dirfd: i32, path_ptr: u64, flags: vfs::LookupFlags)
    -> Result<vfs::VfsPath, i64>
{
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    if at_path_empty(path_ptr) {
        // LOOKUP_EMPTY gate: empty pathname is ENOENT unless AT_EMPTY_PATH.
        if !flags.empty { return Err(-(Errno::Enoent.as_i32() as i64)); }
        if dirfd == AT_FDCWD {
            let cur = sched::live::current().ok_or(ebadf)?;
            // SAFETY: cwd_vfs slot single-mutator per 13§5; current task sole writer.
            if let Some(p) = unsafe { (*cur.cwd_vfs.get()).clone() } { return Ok(p); }
            let dentry = root_dentry().ok_or(ebadf)?;
            let inode = dentry.inode().ok_or(ebadf)?;
            return Ok(vfs::VfsPath { mnt_id: 0, dentry, inode, last_component: None });
        }
        let cur = sched::live::current().ok_or(ebadf)?;
        // SAFETY: running task on this CPU; sole reader of its fd_table slot.
        let fdt = unsafe { cur.fd_table_ref() }.ok_or(ebadf)?.clone();
        let f = fdt.get(dirfd).map_err(|_| ebadf)?;
        return Ok(vfs::VfsPath {
            mnt_id: f.mnt_id(), dentry: f.dentry().clone(),
            inode: f.inode().clone(), last_component: None,
        });
    }
    let raw = crate::namei_common::read_user_path(path_ptr)?;
    let abs = resolve_at_result(dirfd, &raw)?;
    resolve_path_flags(&abs, flags).map_err(crate::namei_common::errno_from_vfs)
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
