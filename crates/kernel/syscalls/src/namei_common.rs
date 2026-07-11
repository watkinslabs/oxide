// namei shared helpers — THE resolver feeding namespace mutations
// (docs/16§3) + path/errno utilities used by ≥2 namei handlers.
// Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// debug-boot: trace the syscalls systemd-logind runs while classifying
/// `/dev/dri/card0` for `TakeDevice`. mutter reports `Failed to open gpu ...
/// ENODEV` when logind's `session_device_new` → `sd_device_new_from_devnum` /
/// `detect_device_type` fails; that failure is a readlink/open/stat on the
/// card's sysfs (`/sys/dev/char/226:0`, `.../drm/card0/subsystem`, `.../uevent`)
/// or the `/dev/dri/card0` node returning an errno. Log the resolved path +
/// return value for the logind process so the exact failing step is visible.
/// Gated; no effect in prod. # C: O(len)
#[cfg(feature = "debug-boot")]
pub(crate) fn trace_logind_dev(op: &'static [u8], path: &str, rv: i64) {
    let hit = path.contains("card0") || path.contains("226:0")
        || path.contains("dri/card") || path.contains("/dri")
        || path.contains("drm/card") || path.contains("class/drm");
    if !hit { return; }
    let is_logind = sched::live::current()
        .and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.contains("logind")) })
        .unwrap_or(false);
    if !is_logind { return; }
    klog::write_raw(b"[LGD "); klog::write_raw(op);
    klog::write_raw(b" rv=");
    if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
    else { klog::write_dec_u64(rv as u64); }
    klog::write_raw(b" path="); klog::write_raw(path.as_bytes());
    klog::write_raw(b"]\n");
}

/// Read a user-space pathname with the full Linux errno contract:
///   * NULL / out-of-range ptr  → **EFAULT**
///   * empty string (`""`)      → **ENOENT** (callers without AT_EMPTY_PATH)
///   * pathname ≥ PATH_MAX bytes → **ENAMETOOLONG** (`vfs::path::check_path_len`)
///   * non-UTF-8 bytes          → byte-preserved (Linux paths are opaque
///     byte strings, `path_resolution(7)`); decoded via
///     `vfs::path_from_bytes` so a non-UTF-8 component still resolves.
/// Returns `Ok(empty)` is impossible — empty maps to ENOENT here; callers
/// that allow AT_EMPTY_PATH must probe emptiness before calling. The
/// total-length limit + its gate are owned by `vfs::path` (the work-fn crate
/// per `53`); this shim only fetches the bytes and applies the gate.
/// # C: O(strlen)
pub(crate) fn read_user_path(ptr: u64) -> Result<String, i64> {
    if ptr == 0 || ptr >= USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); PATH_MAX bound.
    let bytes = unsafe { devfs::read_user_cstr(ptr, vfs::path::PATH_MAX) }
        .ok_or(-(Errno::Efault.as_i32() as i64))?;
    if bytes.is_empty() {
        return Err(-(Errno::Enoent.as_i32() as i64));
    }
    let path = vfs::path_from_bytes(bytes);
    // No NUL within PATH_MAX bytes → pathname too long (Linux ENAMETOOLONG).
    vfs::path::check_path_len(&path).map_err(errno_from_vfs)?;
    Ok(path)
}

/// D26: every path leaves through the lexical normalizer — an absolute path is
/// normalized (no raw-string passthrough), a relative path is joined to cwd then
/// normalized. A normalization miss returns `None` (callers map to ENOENT, Linux
/// for a path that cannot be normalized), never a silent raw unnormalized string;
/// this keeps path resolution deterministic.
/// # C: O(1)
pub(crate) fn resolve(path_raw: &str) -> Option<String> {
    if path_raw.starts_with('/') { return vfs::path::lexical_normalize(path_raw); }
    let cur = sched::live::current()?;
    // SAFETY: cwd slot single-mutator per `13§5`; current task is sole writer.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, path_raw)
}

/// # C: O(1)
/// Distinct `st_dev` per filesystem, derived from the inode-number namespace
/// each FS allocates from: ext4 stamps `EXT4_INO_MARK` (0x6E54..) in the top
/// 32 bits; the synthetic FSes use distinct high nibbles (devfs 0x2xxx_xxxx,
/// procfs 0x3xxx_xxxx, tmpfs 0x4xxx_xxxx+, sysfs/bpf above). systemd's
/// mount-boundary detection compares `st_dev` across a path — with every
/// `st_dev == 0` it cannot tell one filesystem from another, which breaks its
/// cgroup/credentials/os-release boundary walks. Linux gives each mount its
/// own `dev_t` (a block dev_t or an anon-bdev); this is the stable analogue.
/// # C: O(1)
pub(crate) fn encode_dev(major: u32, minor: u32) -> u64 {
    ((minor & 0xff) as u64)
        | (((major & 0xfff) as u64) << 8)
        | (((minor & !0xff) as u64) << 12)
        | (((major & !0xfff) as u64) << 32)
}

pub(crate) fn dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff)) as u32
}

pub(crate) fn dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & !0xff)) as u32
}

/// Encode a filesystem identity into Linux `dev_t`. The source identity is
/// owned by the filesystem (`Inode::fsid()`); this helper only gives it the
/// ABI shape expected by stat/statx.
/// # C: O(1)
pub(crate) fn fsid_to_dev(fsid: u64) -> u64 {
    // Single source of truth in `vfs::fsid_to_dev` so autofs OPENMOUNT (which
    // must reproduce the `st_dev` userspace stat'd) can never drift from the
    // value this stat path encodes.
    vfs::fsid_to_dev(fsid)
}

/// Map a `VfsError` to the negative Linux errno the ABI returns. Complete
/// over every `VfsError` discriminant so a path-walk error (ELOOP /
/// ENAMETOOLONG / ENOTDIR / EACCES) propagates with its true errno instead
/// of collapsing to EIO/ENOENT.
/// # C: O(1)
pub(crate) fn errno_from_vfs(e: vfs::VfsError) -> i64 {
    -(match e {
        vfs::VfsError::Eperm   => Errno::Eperm   as i32,
        vfs::VfsError::Enoent  => Errno::Enoent  as i32,
        vfs::VfsError::Eintr   => Errno::Eintr   as i32,
        vfs::VfsError::Eio     => Errno::Eio     as i32,
        vfs::VfsError::Enxio   => Errno::Enxio   as i32,
        vfs::VfsError::Ebadf   => Errno::Ebadf   as i32,
        vfs::VfsError::Enomem  => Errno::Enomem  as i32,
        vfs::VfsError::Eacces  => Errno::Eacces  as i32,
        vfs::VfsError::Efault  => Errno::Efault  as i32,
        vfs::VfsError::Eexist  => Errno::Eexist  as i32,
        vfs::VfsError::Exdev   => Errno::Exdev   as i32,
        vfs::VfsError::Enodev  => Errno::Enodev  as i32,
        vfs::VfsError::Enotdir => Errno::Enotdir as i32,
        vfs::VfsError::Eisdir  => Errno::Eisdir  as i32,
        vfs::VfsError::Einval  => Errno::Einval  as i32,
        vfs::VfsError::Emfile  => Errno::Emfile  as i32,
        vfs::VfsError::Enotty  => Errno::Enotty  as i32,
        vfs::VfsError::Etxtbsy => Errno::Etxtbsy as i32,
        vfs::VfsError::Efbig   => Errno::Efbig   as i32,
        vfs::VfsError::Espipe  => Errno::Espipe  as i32,
        vfs::VfsError::Eagain  => Errno::Eagain  as i32,
        vfs::VfsError::Epipe   => Errno::Epipe   as i32,
        vfs::VfsError::Erofs   => Errno::Erofs   as i32,
        vfs::VfsError::Ebusy   => Errno::Ebusy   as i32,
        vfs::VfsError::Enospc  => Errno::Enospc  as i32,
        vfs::VfsError::Enotempty => Errno::Enotempty as i32,
        vfs::VfsError::Enosys  => Errno::Enosys  as i32,
        vfs::VfsError::Eloop   => Errno::Eloop   as i32,
        vfs::VfsError::Eopnotsupp => Errno::Eopnotsupp as i32,
        vfs::VfsError::Enametoolong => Errno::Enametoolong as i32,
        vfs::VfsError::Enotconn => Errno::Enotconn as i32,
    } as i64)
}

/// Boot diagnostic for namespace mutation failures during systemd setup.
pub(crate) fn trace_run_vfs_error(op: &[u8], path: &str, e: vfs::VfsError) {
    klog::write_raw(b"[NAMEI] ");
    klog::write_raw(op);
    klog::write_raw(b" path=\"");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"\" err=");
    klog::write_dec_u64(e as u64);
    klog::write_raw(b"\n");
}

/// Resolve the PARENT directory of absolute `p` through the engine
/// LOOKUP_PARENT walk (`pathresolve::resolve_parent_path`, Linux
/// `filename_parentat`) and return `(parent_inode, leaf_name)` — THE resolver
/// feeding every namespace mutation per `docs/16§3` (namei D16). The walk
/// stops before the final component, returning the resolved parent dir inode +
/// the leaf reported VERBATIM (so a not-yet-existing leaf is fine; the per-
/// component child op on the parent then services the create/unlink/rename).
/// Replaces the old `split_parent` (`rfind('/')`) string split + a separate
/// full `resolve(parent)` walk; the leaf classification (`.`/`..`/root) is
/// owned by the engine (`VfsPath::last_type`) but the callers still pre-reject
/// the dot-forms on the RAW path (`rmdir_dot_errno`/`rename_component_busy`)
/// before lexical normalization collapses them. The owning mount's inode
/// services the op (ext4 dir → ext4 create/unlink; tmpfs → tmpfs; read-only
/// pseudo-fs → Erofs), exactly as Linux `inode_operations`. A `/` (no leaf,
/// `last_type == Root`) maps to EINVAL — the same error the old `split_parent`
/// returned for a parent-less path. # C: O(N parent components)
pub(crate) fn resolve_parent(p: &str) -> Result<(vfs::InodeRef, String), i64> {
    let vp = crate::pathresolve::resolve_parent_path(p).map_err(errno_from_vfs)?;
    match vp.last_component {
        Some(name) => Ok((vp.inode, name)),
        None       => Err(-(Errno::Einval.as_i32() as i64)),
    }
}

/// True if `p` already resolves to an existing inode (final component
/// not followed if it's a symlink). Linux checks target existence
/// before the fs-specific `mkdir`, returning EEXIST regardless of
/// parent writability. Without this, `mkdir` of an existing dir whose
/// parent is a read-only pseudo-fs leaks the parent's EROFS — e.g.
/// systemd's `cg_create("/")` does `mkdir("/sys/fs/cgroup")` (already
/// present), whose parent `/sys/fs` is sysfs → EROFS instead of the
/// EEXIST systemd treats as success, aborting its cgroup setup.
/// # C: O(N path components)
pub(crate) fn path_exists(p: &str) -> bool {
    crate::pathresolve::resolve(p, true).is_some()
}

/// Resolve a create target's parent through the real `*at` base, preserving the
/// walked parent `(mnt,dentry)` as authority and returning only the final leaf
/// name as text. Dot leaves name an already-existing object in Linux's create
/// family; root keeps the legacy EINVAL behavior this tree already exposed.
/// # C: O(N parent components)
pub(crate) fn resolve_create_parent_at(dirfd: i32, raw: &str) -> Result<(vfs::VfsPath, String), i64> {
    let vp = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    match vp.last_type() {
        vfs::LastType::Norm => match vp.last_component.clone() {
            Some(name) => Ok((vp, name)),
            None => Err(-(Errno::Einval.as_i32() as i64)),
        },
        vfs::LastType::Dot | vfs::LastType::Dotdot => Err(-(Errno::Eexist.as_i32() as i64)),
        vfs::LastType::Root => Err(-(Errno::Einval.as_i32() as i64)),
    }
}

/// Resolve a hardlink destination parent. Existing directory/root/dot targets
/// are EEXIST for Linux link(2), not the create-family legacy EINVAL-on-root.
/// # C: O(N parent components)
pub(crate) fn resolve_link_parent_at(dirfd: i32, raw: &str) -> Result<(vfs::VfsPath, String), i64> {
    let vp = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    match vp.last_type() {
        vfs::LastType::Norm => match vp.last_component.clone() {
            Some(name) => Ok((vp, name)),
            None => Err(-(Errno::Eexist.as_i32() as i64)),
        },
        vfs::LastType::Dot | vfs::LastType::Dotdot | vfs::LastType::Root =>
            Err(-(Errno::Eexist.as_i32() as i64)),
    }
}

/// Resolve an unlink target's parent without collapsing the authority back into
/// a string. Dot/root targets are directories to Linux unlink(2), so reject them
/// before backend `unlink("."/"..")` can manufacture filesystem-specific ENOENT.
/// # C: O(N parent components)
pub(crate) fn resolve_unlink_parent_at(dirfd: i32, raw: &str) -> Result<(vfs::VfsPath, String), i64> {
    let vp = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    match vp.last_type() {
        vfs::LastType::Norm => match vp.last_component.clone() {
            Some(name) => Ok((vp, name)),
            None => Err(-(Errno::Eisdir.as_i32() as i64)),
        },
        vfs::LastType::Dot | vfs::LastType::Dotdot | vfs::LastType::Root =>
            Err(-(Errno::Eisdir.as_i32() as i64)),
    }
}

/// Resolve an rmdir target's parent. The raw `.`/`..` split is handled by
/// `rmdir_dot_errno`; removing the root is Linux EBUSY. # C: O(N parent components)
pub(crate) fn resolve_rmdir_parent_at(dirfd: i32, raw: &str) -> Result<(vfs::VfsPath, String), i64> {
    let vp = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    match vp.last_type() {
        vfs::LastType::Norm => match vp.last_component.clone() {
            Some(name) => Ok((vp, name)),
            None => Err(-(Errno::Ebusy.as_i32() as i64)),
        },
        vfs::LastType::Root => Err(-(Errno::Ebusy.as_i32() as i64)),
        vfs::LastType::Dot | vfs::LastType::Dotdot => Err(-(Errno::Einval.as_i32() as i64)),
    }
}

/// Resolve a rename side's parent. Linux `do_renameat2` only accepts
/// `LAST_NORM`; root/dot/dotdot are `EBUSY`.
/// # C: O(N parent components)
pub(crate) fn resolve_rename_parent_at(dirfd: i32, raw: &str) -> Result<(vfs::VfsPath, String), i64> {
    let vp = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    match vp.last_type() {
        vfs::LastType::Norm => match vp.last_component.clone() {
            Some(name) => Ok((vp, name)),
            None => Err(-(Errno::Ebusy.as_i32() as i64)),
        },
        vfs::LastType::Dot | vfs::LastType::Dotdot | vfs::LastType::Root =>
            Err(-(Errno::Ebusy.as_i32() as i64)),
    }
}

/// Render a resolved parent path for hooks/diagnostics. Display only; never
/// feed the result back into authority decisions. # C: O(depth)
pub(crate) fn render_parent_path(parent: &vfs::VfsPath) -> String {
    vfs::mount::render_path_for_mount(parent.mnt_id, &parent.dentry)
}

/// Render `parent/leaf` for Landlock/logging from exact parent identity.
/// Display only; authority remains `parent`. # C: O(depth + leaf)
pub(crate) fn render_child_path(parent: &vfs::VfsPath, leaf: &str) -> String {
    let mut p = render_parent_path(parent);
    if p == "/" {
        p.push_str(leaf);
    } else {
        p.push('/');
        p.push_str(leaf);
    }
    p
}

/// True if `leaf` exists below the exact parent dentry. This replaces whole-path
/// string re-walks for create EEXIST ordering. # C: O(1) expected + fs lookup
pub(crate) fn child_exists(parent: &vfs::VfsPath, leaf: &str) -> Result<bool, i64> {
    if let Some(d) = vfs::d_lookup(&parent.dentry, leaf) {
        return Ok(d.inode().is_some());
    }
    match parent.inode.lookup(leaf) {
        Ok(_) => Ok(true),
        Err(vfs::VfsError::Enoent) => Ok(false),
        Err(e) => Err(errno_from_vfs(e)),
    }
}

/// Lookup a child inode below an exact parent. `None` means a real negative
/// result; other lookup failures preserve their errno. # C: O(1) expected + fs lookup
pub(crate) fn child_inode(parent: &vfs::VfsPath, leaf: &str) -> Result<Option<vfs::InodeRef>, i64> {
    if let Some(d) = vfs::d_lookup(&parent.dentry, leaf) {
        return Ok(d.inode());
    }
    match parent.inode.lookup(leaf) {
        Ok(i) => Ok(Some(i)),
        Err(vfs::VfsError::Enoent) => Ok(None),
        Err(e) => Err(errno_from_vfs(e)),
    }
}

/// Capture the positive child dentry under an already-resolved parent, without
/// rendering/re-walking the full path. Used before unlink/rmdir so the VFS tail
/// can update the exact alias the backend removed. # C: O(1) expected + fs lookup
pub(crate) fn child_dentry(parent: &vfs::VfsPath, leaf: &str) -> Option<Arc<vfs::Dentry>> {
    match vfs::d_lookup(&parent.dentry, leaf) {
        Some(d) if d.inode().is_some() => Some(d),
        Some(_) => None,
        None => match parent.inode.lookup(leaf) {
            Ok(i) => Some(vfs::d_add(&parent.dentry, leaf, i)),
            Err(_) => None,
        },
    }
}

/// Read-only check by the already-resolved owning mount. # C: O(log N)
pub(crate) fn parent_mount_readonly(parent: &vfs::VfsPath) -> bool {
    vfs::mount::mount_by_id(parent.mnt_id)
        .map(|m| (m.flags() & vfs::mount::MNT_RDONLY) != 0)
        .unwrap_or(false)
}

/// Drop stale child cache by object parent, not rendered pathname. # C: O(1)
pub(crate) fn drop_child_cache(parent: &vfs::VfsPath, leaf: &str) {
    vfs::d_drop_child(&parent.dentry, leaf);
}

/// Linux pathname AF_UNIX sockets are removed from the filesystem namespace by
/// unlink(2). Existing socket objects stay alive, but a later bind to the same
/// pathname must be allowed. Our socket registry is separate from tmpfs, so
/// unlink has to drop the registry key as well as the socket inode. The caller
/// owns dcache invalidation through its already-resolved parent identity.
/// # C: O(log N)
pub(crate) fn unlink_unix_socket_path(p: &str) -> bool {
    if net::unix_path_is_abstract(p) || !net::sock::UNIX_REGISTRY.is_bound(p) {
        return false;
    }
    net::sock::UNIX_REGISTRY.unbind(p);
    net::sock::UNIX_REGISTRY.dgram_unbind(p);
    true
}

/// Final path component of a raw user pathname (Linux `last` of
/// `filename_parentat`). Trailing slashes are stripped first; the root `/`
/// and a bare empty string yield `""`. # C: O(N)
pub(crate) fn last_component(raw: &str) -> &str {
    let trimmed = raw.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// Parent path string for fsnotify hooks after a successful mutation. Inputs
/// here are resolved absolute paths; root children report parent `/`.
/// # C: O(N)
pub(crate) fn parent_path(abs: &str) -> &str {
    let trimmed = abs.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => "/",
        Some(i) => &trimmed[..i],
        _ => "/",
    }
}

/// Linux `do_rmdirat`: a final component of `.` → EINVAL, `..` → ENOTEMPTY
/// (the `LAST_DOT` / `LAST_DOTDOT` cases). Checked on the raw path before
/// resolution, which would otherwise normalise the dots away. # C: O(N)
pub(crate) fn rmdir_dot_errno(raw: &str) -> Option<i64> {
    match last_component(raw) {
        "."  => Some(-(Errno::Einval.as_i32() as i64)),
        ".." => Some(-(Errno::Enotempty.as_i32() as i64)),
        _    => None,
    }
}

/// Linux `do_renameat2`: EBUSY when either side's final component is not
/// `LAST_NORM` — i.e. `.`, `..`, or the root (`""` after trimming). # C: O(N)
pub(crate) fn rename_component_busy(raw: &str) -> bool {
    matches!(last_component(raw), "" | "." | "..")
}

/// Strip a trailing `/` for the PARENT-SPLIT of create ops (`mkdir`/`mkdirat`):
/// `mkdir /var/` ≡ `mkdir /var` (POSIX). Root `/` is preserved. GNU `mkdir -p`
/// walks ancestors with a trailing slash on each prefix; without this the ext4
/// backend resolves `/var/` to a missing child and returns ENOENT for a dir
/// that exists.
///
/// NOTE — the trailing-slash DIRECTORY semantics (Linux LOOKUP_DIRECTORY: a
/// `foo/` pathname's final component must resolve to a directory, else ENOTDIR,
/// and a final symlink is followed even under O_NOFOLLOW) are NOT discarded by
/// stripping here: they are enforced authoritatively in the vfs walker
/// (`vfs::namei::Nameidata::walk` detects the trailing slash on the INPUT path
/// and sets `LookupFlags::directory`). This helper exists ONLY to compute the
/// parent for the create family; it does not gate the resolution itself.
/// # C: O(1)
pub(crate) fn strip_trailing_slash(p: &str) -> &str {
    if p.len() > 1 { p.strip_suffix('/').unwrap_or(p) } else { p }
}
