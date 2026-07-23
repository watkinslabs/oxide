// namei shared helpers — THE resolver feeding namespace mutations
// (docs/16§3) + path/errno utilities used by ≥2 namei handlers.
// Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use hal::USER_VA_END;

mod errno;
pub(crate) use errno::errno_from_vfs;

#[cfg(feature = "debug-udevdb")]
fn is_udevdb_path_bytes(path: &[u8]) -> bool {
    const DATA: &[u8] = b"/run/udev/data";
    const TAGS: &[u8] = b"/run/udev/tags";
    path.windows(DATA.len()).any(|w| w == DATA)
        || path.windows(TAGS.len()).any(|w| w == TAGS)
}

#[cfg(feature = "debug-udevdb")]
pub(crate) fn trace_udevdb_path(op: &'static [u8], path: &str, rv: i64) {
    if !is_udevdb_path_bytes(path.as_bytes()) { return; }
    klog::write_raw(b"[UDEVDB ");
    klog::write_raw(op);
    klog::write_raw(b" rv=");
    if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
    else { klog::write_dec_u64(rv as u64); }
    klog::write_raw(b" tid=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b"/");
        klog::write_raw(c.name.as_bytes());
    } else {
        klog::write_raw(b"0");
    }
    klog::write_raw(b" path=");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"]\n");
}

#[cfg(feature = "debug-udevdb")]
pub(crate) fn trace_udevdb_file(op: &'static [u8], file: &vfs::File, rv: i64) {
    let path = vfs::mount::render_path_for_mount(file.mnt_id(), file.dentry());
    if !is_udevdb_path_bytes(path.as_bytes()) { return; }
    klog::write_raw(b"[UDEVDB ");
    klog::write_raw(op);
    klog::write_raw(b" rv=");
    if rv < 0 { klog::write_raw(b"-"); klog::write_dec_u64(rv.wrapping_neg() as u64); }
    else { klog::write_dec_u64(rv as u64); }
    klog::write_raw(b" tid=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b"/");
        klog::write_raw(c.name.as_bytes());
    } else {
        klog::write_raw(b"0");
    }
    klog::write_raw(b" path=");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"]\n");
}

/// debug-boot: trace DRM device discovery by logind and the compositor.  Both
/// resolve `/sys/dev/char/226:0` and the card's class links, but they consume
/// the result differently: logind gates `TakeDevice`, while Mesa/libdrm turns
/// a failed topology probe into "failed to retrieve device information".  Keep
/// both callers visible so a GNOME black screen can be assigned to the actual
/// discovery failure instead of guessing at KMS or scanout.  Gated; no effect
/// in production. # C: O(len)
#[cfg(feature = "debug-boot")]
pub(crate) fn trace_logind_dev(op: &'static [u8], path: &str, rv: i64) {
    let hit = path.contains("card0") || path.contains("226:0")
        || path.contains("dri/card") || path.contains("/dri")
        || path.contains("drm/card") || path.contains("class/drm");
    if !hit { return; }
    let who = sched::live::current()
        .and_then(|c| c.with_exe_path(|p| p.and_then(|s| {
            if s.contains("logind") { Some(b"LGD" as &[u8]) }
            else if s.contains("gnome-shell") || s.contains("mutter") { Some(b"DRMDISC" as &[u8]) }
            else { None }
        })));
    let Some(who) = who else { return; };
    klog::write_raw(b"["); klog::write_raw(who); klog::write_raw(b" "); klog::write_raw(op);
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

/// Read a user pathname while preserving the exact non-NUL byte payload.
/// Symlink targets use this path: Linux `symlink(2)` stores `oldname` verbatim
/// after `getname`, it does not round-trip through a UTF-8 string.
/// # C: O(strlen)
pub(crate) fn read_user_path_bytes(ptr: u64) -> Result<Vec<u8>, i64> {
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
    vfs::path::check_path_len(&path).map_err(errno_from_vfs)?;
    Ok(bytes.to_vec())
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

/// Feature-gated create-parent DAC diagnostic. Creation failures happen before
/// a final inode exists, so the ordinary open diagnostic cannot name the
/// denied parent. Keep this available for real boot diagnosis without adding
/// work to non-debug kernels.
#[cfg(feature = "debug-eacces")]
pub(crate) fn trace_create_eacces(
    op: &[u8], path: &str, parent: &vfs::InodeRef, cred: &vfs::Cred,
) {
    klog::write_raw(b"[EACCES] ");
    klog::write_raw(op);
    klog::write_raw(b" path=\"");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"\" parent_ino=");
    klog::write_hex_u64(parent.ino());
    klog::write_raw(b" parent_uid=");
    klog::write_dec_u64(parent.uid().unwrap_or(0) as u64);
    klog::write_raw(b" parent_gid=");
    klog::write_dec_u64(parent.gid().unwrap_or(0) as u64);
    klog::write_raw(b" parent_mode=");
    klog::write_hex_u64(parent.i_mode() as u64);
    klog::write_raw(b" c_uid=");
    klog::write_dec_u64(cred.uid as u64);
    klog::write_raw(b" c_gid=");
    klog::write_dec_u64(cred.gid as u64);
    klog::write_raw(b"\n");
}

/// Feature-gated diagnostic for an EACCES while walking a create target's
/// parent. There is no resolved parent inode in this case, so report the
/// authoritative requested path instead.
#[cfg(feature = "debug-eacces")]
pub(crate) fn trace_create_resolve_eacces(op: &[u8], path: &str) {
    klog::write_raw(b"[EACCES] ");
    klog::write_raw(op);
    klog::write_raw(b" parent-resolve path=\"");
    klog::write_raw(path.as_bytes());
    klog::write_raw(b"\"\n");
}

/// Resolve the PARENT directory of absolute `p` through the engine
/// Resolve a create target's parent through the real `*at` base, preserving the
/// walked parent `(mnt,dentry)` as authority and returning only the final leaf
/// name as text. Non-normal leaves name an already-existing object in Linux's
/// create family (`filename_create` seeds `-EEXIST` before `LAST_NORM` check).
/// # C: O(N parent components)
pub(crate) fn resolve_create_parent_at(dirfd: i32, raw: &str) -> Result<(vfs::VfsPath, String), i64> {
    let vp = crate::pathresolve::resolve_parent_at(dirfd, raw)?;
    match vp.last_type() {
        vfs::LastType::Norm => match vp.last_component.clone() {
            Some(name) => Ok((vp, name)),
            None => Err(-(Errno::Einval.as_i32() as i64)),
        },
        vfs::LastType::Dot | vfs::LastType::Dotdot => Err(-(Errno::Eexist.as_i32() as i64)),
        vfs::LastType::Root => Err(-(Errno::Eexist.as_i32() as i64)),
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

/// Resolve a user AF_UNIX sockaddr path to the kernel rendezvous key. Abstract
/// addresses stay byte-name keyed in the caller's netns; pathname addresses use
/// the caller's VFS root/cwd and follow the final symlink to the socket inode.
/// # C: O(path components)
pub(crate) fn resolve_unix_addr(path: alloc::vec::Vec<u8>) -> Result<net::UnixAddr, i64> {
    if net::unix_path_is_abstract(&path) {
        return Ok(net::UnixAddr::from_sockaddr_path(path));
    }
    let decoded = vfs::path_from_bytes(&path);
    let p = crate::pathresolve::resolve_path_raw(&decoded, false)
        .map_err(errno_from_vfs)?;
    if p.inode.file_type() != vfs::FileType::Socket {
        return Err(-(Errno::Econnrefused.as_i32() as i64));
    }
    Ok(net::UnixAddr::from_inode_bytes(path, &p.inode))
}

/// Drop a pathname AF_UNIX registry binding after VFS unlink removed the socket
/// inode. Existing connected socket objects stay alive. # C: O(log N)
pub(crate) fn unlink_unix_socket_addr(addr: &net::UnixAddr) -> bool {
    if !addr.is_pathname() || !net::sock::UNIX_REGISTRY.is_bound_addr(addr) {
        return false;
    }
    net::sock::UNIX_REGISTRY.unlink_addr(addr);
    net::sock::UNIX_REGISTRY.dgram_unbind_addr(addr);
    true
}

/// Final path component of a raw user pathname (Linux `last` of
/// `filename_parentat`). Trailing slashes are stripped first; the root `/`
/// and a bare empty string yield `""`. # C: O(N)
pub(crate) fn last_component(raw: &str) -> &str {
    let trimmed = raw.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
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
