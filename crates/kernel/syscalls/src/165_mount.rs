// 165 mount — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.
//
// Real `sys_mount(source, target, fstype, flags, data)` — slot 165.
// V1 honours fstype="tmpfs" by spawning a fresh TmpfsRootInode at
// `target` in devfs. Other fstypes return EOPNOTSUPP. Requires
// CAP_SYS_ADMIN. Per-NS mount-table virtualisation is a follow-up (per-NS mount table)
// once a real backend (ext4 + block) lands; until then mount(2)
// affects the global registry shared by all mount_ns ids.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::{String, ToString};
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::fs::FileSystem;
use vfs::InodeRef;

use crate::mount_common::read_user_cstr_owned;
use crate::fsmount_common::mount_fstype;

// mount(2) flag bits (linux/mount.h).
const MS_REMOUNT:    u64 = 0x20;
const MS_RDONLY:     u64 = 0x1;
const MS_NOSUID:     u64 = 0x2;
const MS_NODEV:      u64 = 0x4;
const MS_NOEXEC:     u64 = 0x8;
const MS_SYNCHRONOUS: u64 = 0x10;
const MS_MANDLOCK:   u64 = 0x40;
const MS_DIRSYNC:    u64 = 0x80;
const MS_NOATIME:    u64 = 0x400;
const MS_NODIRATIME: u64 = 0x800;
const MS_RELATIME:   u64 = 1 << 21;
const MS_STRICTATIME: u64 = 1 << 24;
const MS_LAZYTIME:   u64 = 1 << 25;
const MS_BIND:       u64 = 0x1000;
const MS_MOVE:       u64 = 0x2000;
const MS_REC:        u64 = 0x4000;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE:    u64 = 1 << 18;
const MS_SLAVE:      u64 = 1 << 19;
const MS_SHARED:     u64 = 1 << 20;
const MS_PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;
const MS_REMOUNTABLE: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SYNCHRONOUS
    | MS_MANDLOCK | MS_DIRSYNC | MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME
    | MS_LAZYTIME;

fn canonical_mount_path(path: String) -> String {
    let Some((tid_opt, fd)) = vfs::path::dup_fd_target(&path) else {
        return path;
    };
    let Some(file) = sched::proclink::proc_fd_file(tid_opt, fd) else {
        return path;
    };
    let bytes = file.dentry().absolute_path();
    match core::str::from_utf8(&bytes) {
        Ok(s) if s.starts_with('/') => String::from(s),
        _ => path,
    }
}

/// Bind mount MARKER (Linux: a bind has no superblock of its own — it is
/// `(vfsmount, mnt_root = source dentry)` sharing the source SB). The mount
/// table stores the resolved SOURCE root inode in `Mount.root` (via
/// `register_bind`), so the path walk crosses into the bind and then
/// resolves every component on the source's REAL inodes per-component
/// (`d_lookup → i_op->lookup → d_add`). This struct only carries the
/// fstype name / statfs magic / `/proc/mounts` line — NO path lookup.
/// # C: O(1)
pub struct BindFs {
    source: String,
}

impl FileSystem for BindFs {
    fn name(&self) -> &str { "bind" }
    /// A bind mount reports the backing fs of its source subtree
    /// (statfs through a bind sees the real fs, as on Linux).
    /// # C: O(N_mounts)
    fn magic(&self) -> u64 {
        vfs::mount::resolve_mount(&self.source)
            .map(|(m, _)| m.fs.magic())
            .filter(|&m| m != 0)
            .unwrap_or(0xEF53)
    }
    fn mounts_line(&self, mount_point: &str) -> String {
        let mut s = String::new();
        s.push_str(&self.source);
        s.push(' ');
        s.push_str(mount_point);
        s.push_str(" none rw,relatime,bind 0 0\n");
        s
    }
}

/// `sys_mount(source, target, fstype, flags, data)` — slot 165.
/// # C: O(N_path)
pub fn sys_mount(args: &SyscallArgs) -> i64 {
    let rv = sys_mount_impl(args);
    // Failure-only trace: logging every successful mount floods the UART and
    // shifts boot timing into the intermittent wedge before logind runs. Only
    // failures matter for 226/NAMESPACE diagnosis.
    #[cfg(feature = "debug-mount")]
    {
        let tgt0 = crate::mount_common::read_user_cstr_owned(args.a1, 256).unwrap_or_default();
        // Log failures AND any mount that touches /proc or /sys (success too) —
        // the 226 is a shadowing /proc mount in the sandbox hiding the static
        // /proc/sys/kernel/domainname leaf. Need to see what gets mounted there.
        if rv < 0 || tgt0.contains("/proc") || tgt0.contains("/sys") {
        let tgt = tgt0;
        let src = crate::mount_common::read_user_cstr_owned(args.a0, 128).unwrap_or_default();
        let fst = crate::mount_common::read_user_cstr_owned(args.a2, 32).unwrap_or_default();
        // src/fstype/flags inline so a failing /proc/self/fd/N mount shows what
        // it actually is (bind vs fstype vs the unknown-fstype EOPNOTSUPP path).
        let mut tag = alloc::string::String::from(tgt.as_str());
        tag.push_str(" src="); tag.push_str(&src);
        tag.push_str(" fst="); tag.push_str(&fst);
        tag.push_str(" fl=");
        crate::mount_common::mnt_log_hex("mount", &tag, args.a3, rv);
        }
    }
    rv
}

fn sys_mount_impl(args: &SyscallArgs) -> i64 {
    let source_p = args.a0;
    let target_p = args.a1;
    let fstype_p = args.a2;
    let flags    = args.a3;
    let _data    = args.a4;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let target_raw = match read_user_cstr_owned(target_p, 256) { Ok(s) => s, Err(rv) => return rv };
    let target = crate::pathresolve::resolve_cwd(&target_raw);
    if !target.starts_with('/') {
        return -(Errno::Einval.as_i32() as i64);
    }
    let ns = cur.mount_ns.load(core::sync::atomic::Ordering::Acquire);

    // Normalize a trailing slash so `/x/` and `/x` register identically.
    let target = if target.len() > 1 { target.trim_end_matches('/').to_string() } else { target };
    let target = canonical_mount_path(target);

    // MS_REMOUNT changes options on an EXISTING mount — it carries no
    // source, so it MUST be handled before MS_BIND (systemd remounts the
    // machine-id bind read-only with MS_RDONLY|MS_REMOUNT|MS_BIND; the
    // bind branch would read a NULL source and EFAULT).
    if flags & MS_REMOUNT != 0 {
        return match vfs::mount::remount_flags(&target, flags & MS_REMOUNTABLE) {
            Ok(()) => 0,
            Err(vfs::VfsError::Einval) => -(Errno::Einval.as_i32() as i64),
            Err(_) => -(Errno::Ebusy.as_i32() as i64),
        };
    }

    // MS_BIND: redirect `target` into the `source` subtree. fstype is
    // ignored (may be NULL). Source is required.
    if flags & MS_BIND != 0 {
        let source_raw = match read_user_cstr_owned(source_p, 256) { Ok(s) => s, Err(rv) => return rv };
        let source = crate::pathresolve::resolve_cwd(&source_raw);
        if !source.starts_with('/') { return -(Errno::Einval.as_i32() as i64); }
        let source = if source.len() > 1 { source.trim_end_matches('/').to_string() } else { source };
        // Bind-as-clone (docs/16§6): resolve the source subtree's root
        // inode via the dentry walk (follows symlinks, crosses mounts) and
        // mount it at target. The walk then mirrors the source subtree via
        // per-component Inode::lookup — no BindFs path rewrite.
        let root = match crate::pathresolve::resolve(&source, false) {
            Some(i) => i,
            None    => return -(Errno::Enoent.as_i32() as i64),
        };
        // Peer-group inheritance (docs/16§6): binding a SHARED source
        // makes the new mount a peer of the source's group (same shared:N,
        // future propagation events reach it). Captured before the bind.
        let src_pg = vfs::mount::peer_group_of(&source);
        let bind = Arc::new(BindFs { source: source.clone() });
        // Global mount table (per-NS bind rides the per-ns mount tree).
        let _ = vfs::mount::register_bind(&target, bind, root);
        vfs::mount::join_peer_group(&target, src_pg);
        // MS_REC: also clone every mount nested under `source` to the
        // matching path under `target` (recursive bind, docs/16§6).
        if flags & MS_REC != 0 {
            let _ = vfs::mount::bind_submounts_rec(&source, &target);
        }
        // Propagation: if `target`'s parent is a shared mount, replicate
        // this bind to the parent's peers (docs/16§6).
        let _ = vfs::mount::propagate_mount(&target);
        let _ = ns;
        return 0;
    }

    // Propagation (MS_SHARED/PRIVATE/SLAVE/UNBINDABLE) retunes an
    // EXISTING mount in place — systemd's early setup issues
    // `mount(NULL,"/",NULL,MS_REC|MS_SHARED)`. Record the type on the
    // target mount (surfaced in /proc/mountinfo); peer-propagation
    // *event* delivery rides a follow-up. MS_REC recursive retune is
    // also a follow-up. Changing propagation of a non-mount → EINVAL.
    if flags & MS_PROPAGATION != 0 {
        use vfs::mount::Propagation;
        let kind = if flags & MS_UNBINDABLE != 0 { Propagation::Unbindable }
            else if flags & MS_SLAVE != 0 { Propagation::Slave }
            else if flags & MS_SHARED != 0 { Propagation::Shared }
            else { Propagation::Private };
        // Record on the target if it's a real entry in the unified
        // mount table. Some mounts (tmpfs) still register via the devfs
        // registry rather than vfs::mount::TABLE (fragmented table —
        // unified in later K2/K3 work); for those, accept-and-noop as
        // before rather than spuriously EINVAL and regress systemd.
        let _ = vfs::mount::set_propagation(&target, kind);
        return 0;
    }
    // MS_MOVE: relocate the mount currently at `source` to `target`.
    // The mount tree is implicit (parent = longest-prefix mount_point),
    // so the move is a mount_point rewrite preserving mnt_id +
    // propagation; the new parent_id falls out of the recompute. Source
    // is the existing mount point (required, absolute).
    if flags & MS_MOVE != 0 {
        let source_raw = match read_user_cstr_owned(source_p, 256) { Ok(s) => s, Err(rv) => return rv };
        let source = crate::pathresolve::resolve_cwd(&source_raw);
        if !source.starts_with('/') { return -(Errno::Einval.as_i32() as i64); }
        let source = if source.len() > 1 { source.trim_end_matches('/').to_string() } else { source };
        return match vfs::mount::move_mount(&source, &target) {
            Ok(())                    => 0,
            Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
            Err(_)                    => -(Errno::Einval.as_i32() as i64),
        };
    }

    // New mount by fstype.
    let source = read_user_cstr_owned(source_p, 256).unwrap_or_default();
    let fstype = match read_user_cstr_owned(fstype_p, 32)  { Ok(s) => s, Err(rv) => return rv };
    #[cfg(feature = "debug-boot")]
    if target.contains("credentials") {
        let ns = sched::live::current().map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0);
        klog::write_raw(b"[cred mount] fstype="); klog::write_raw(fstype.as_bytes());
        klog::write_raw(b" ns="); klog::write_dec_u64(ns);
        klog::write_raw(b" path="); klog::write_raw(target.as_bytes());
        klog::write_raw(b"\n");
    }
    mount_fstype(&source, &fstype, &target)
}
