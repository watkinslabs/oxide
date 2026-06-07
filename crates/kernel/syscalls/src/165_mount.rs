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

// mount(2) flag bits (linux/mount.h).
const MS_REMOUNT:    u64 = 0x20;
const MS_BIND:       u64 = 0x1000;
const MS_MOVE:       u64 = 0x2000;
const MS_REC:        u64 = 0x4000;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE:    u64 = 1 << 18;
const MS_SLAVE:      u64 = 1 << 19;
const MS_SHARED:     u64 = 1 << 20;
const MS_PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

/// Bind mount: a FileSystem at `target` whose lookups redirect into
/// the `source` subtree. `mount(src, tgt, NULL, MS_BIND)` makes
/// `tgt/<x>` resolve to `src/<x>` — what shells, systemd `PrivateTmp=`/
/// `ProtectSystem=`, and container tooling rely on. Lookups re-enter
/// the unified resolver against the rewritten path.
/// # C: O(path)
pub struct BindFs {
    source: String,
    target: String,
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
    fn lookup(&self, path: &str) -> Option<InodeRef> {
        // Rewrite the target-prefixed path onto the source subtree.
        let rel = path.strip_prefix(self.target.as_str()).unwrap_or("");
        let mut src = self.source.clone();
        src.push_str(rel);
        // Re-resolve via the unified path resolver, then the devfs/ext4
        // backends — mirrors the open(2) lookup order. (Source must not
        // live under the target; callers don't bind a dir onto itself.)
        vfs::mount::lookup(&src).ok()
            .or_else(|| devfs::lookup(&src))
            .or_else(|| ext4::rootfs::lookup_inode_any(src.as_bytes()))
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
    let target = match read_user_cstr_owned(target_p, 256) { Ok(s) => s, Err(rv) => return rv };
    if !target.starts_with('/') {
        return -(Errno::Einval.as_i32() as i64);
    }
    let ns = cur.mount_ns.load(core::sync::atomic::Ordering::Acquire);

    // Normalize a trailing slash so `/x/` and `/x` register identically.
    let target = if target.len() > 1 { target.trim_end_matches('/').to_string() } else { target };

    // MS_REMOUNT changes options on an EXISTING mount — it carries no
    // source, so it MUST be handled before MS_BIND (systemd remounts the
    // machine-id bind read-only with MS_RDONLY|MS_REMOUNT|MS_BIND; the
    // bind branch would read a NULL source and EFAULT). We keep no
    // remountable options yet, so admit-and-noop (don't EFAULT on the
    // NULL fstype/source a remount passes).
    if flags & MS_REMOUNT != 0 {
        return 0;
    }

    // MS_BIND: redirect `target` into the `source` subtree. fstype is
    // ignored (may be NULL). Source is required.
    if flags & MS_BIND != 0 {
        let source = match read_user_cstr_owned(source_p, 256) { Ok(s) => s, Err(rv) => return rv };
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
        let bind = Arc::new(BindFs { source: source.clone(), target: target.clone() });
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
        let source = match read_user_cstr_owned(source_p, 256) { Ok(s) => s, Err(rv) => return rv };
        if !source.starts_with('/') { return -(Errno::Einval.as_i32() as i64); }
        let source = if source.len() > 1 { source.trim_end_matches('/').to_string() } else { source };
        return match vfs::mount::move_mount(&source, &target) {
            Ok(())                    => 0,
            Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
            Err(_)                    => -(Errno::Einval.as_i32() as i64),
        };
    }

    // New mount by fstype.
    let fstype = match read_user_cstr_owned(fstype_p, 32)  { Ok(s) => s, Err(rv) => return rv };
    match fstype.as_str() {
        "tmpfs" => {
            // U3-b: tmpfs mounts live in the unified per-ns mount table,
            // not the devfs registry. register_bind installs the
            // TmpfsRootInode as the mount root; path_lookup crosses in and
            // resolves files via the inode's tmpfs file store. So
            // `mount -t tmpfs` now appears in /proc/mounts and obeys
            // MS_MOVE/MS_REC/umount uniformly. The caller's mount-ns is
            // stamped automatically by the register_bind ns provider.
            let root: InodeRef = Arc::new(::fs::tmpfs::TmpfsRootInode::new(target.clone()));
            let bind: Arc<dyn FileSystem> = Arc::new(::fs::tmpfs::TmpfsFs);
            let _ = vfs::mount::register_bind(&target, bind, root);
            // Propagation: replicate to the parent's peers if shared.
            let _ = vfs::mount::propagate_mount(&target);
            0
        }
        // cgroup v2 unified hierarchy per `26§4`: mount the real tree
        // at /sys/fs/cgroup (fixed mount point, invariant 4 — single
        // hierarchy, no v1). Idempotent.
        "cgroup2" => { cgroup::mount_root(); 0 }
        // proc and sysfs are already registered at boot; admit-and-noop
        // for these fstypes so userspace remount probes (systemd, /etc/
        // mtab tooling) don't choke. cgroup v1 is never mounted (26§2
        // invariant 4) — admit-noop so legacy probes don't error.
        "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" => 0,
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}
