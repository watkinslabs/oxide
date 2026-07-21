// 165 mount — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.
//
// Real `sys_mount(source, target, fstype, flags, data)` — slot 165.
// V1 honours fstype="tmpfs" by spawning a fresh TmpfsRootInode at
// `target` in devfs. Other fstypes return EOPNOTSUPP. Requires
// CAP_SYS_ADMIN. Per-NS mount-table virtualisation is a follow-up (per-NS mount table)
// once a real backend (ext4 + block) lands; until then mount(2)
// affects the global registry shared by all mount_ns ids.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::{read_optional_user_path, read_user_cstr_owned, read_user_path_required};
use crate::fsmount_common::mount_fstype_at;

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

/// `sys_mount(source, target, fstype, flags, data)` — slot 165.
/// # C: O(N_path)
pub fn sys_mount(args: &SyscallArgs) -> i64 {
    // TEMP (D24, debug-mnt): mount-creating syscall ENTRY trace — pair with the
    // vfs [MNTCREATE] mount-create lines to reconstruct how 10/11 are built.
    #[cfg(feature = "debug-mount")]
    {
        if let (Ok(src), Ok(tgt)) = (
            crate::mount_common::read_optional_user_path(args.a0).map(|s| match s { Some(v) => v, None => String::from("(null)") }),
            crate::mount_common::read_user_path_required(args.a1),
        ) {
            klog::write_raw(b"[MNTCREATE] syscall=mount flags=0x");
            klog::write_hex_u64(args.a3);
            klog::write_raw(b" recursive=");
            klog::write_raw(if args.a3 & MS_REC != 0 { b"true" } else { b"false" });
            klog::write_raw(b" source="); klog::write_raw(src.as_bytes());
            klog::write_raw(b" target="); klog::write_raw(tgt.as_bytes());
            klog::write_raw(b"\n");
        }
    }
    let rv = sys_mount_impl(args);
    // [X5 xdg] Ground-truth probe: is a tmpfs mounted at /run/user/<uid>?
    // logind/pam_systemd create the per-user runtime dir here; if it is never
    // mounted, systemd --user aborts with "$XDG_RUNTIME_DIR is not set".
    // Gated behind debug-syscall; logs the target + fstype + rv for ANY mount
    // whose target lands under /run/user (success and failure).
    #[cfg(feature = "debug-syscall")]
    {
        let tgt = crate::mount_common::read_user_cstr_owned(args.a1, 256).unwrap_or_default();
        if tgt.contains("/run/user") {
            let src = crate::mount_common::read_user_cstr_owned(args.a0, 128).unwrap_or_default();
            let fst = crate::mount_common::read_user_cstr_owned(args.a2, 32).unwrap_or_default();
            klog::write_raw(b"[X5 xdg] mount target=");
            klog::write_raw(tgt.as_bytes());
            klog::write_raw(b" src=");
            klog::write_raw(src.as_bytes());
            klog::write_raw(b" fstype=");
            klog::write_raw(fst.as_bytes());
            klog::write_raw(b" flags=0x");
            klog::write_hex_u64(args.a3);
            if rv < 0 {
                klog::write_raw(b" rv=-");
                klog::write_dec_u64((-rv) as u64);
            } else {
                klog::write_raw(b" rv=");
                klog::write_dec_u64(rv as u64);
            }
            klog::write_raw(b"\n");
        }
    }
    // Failure-only trace: logging every successful mount floods the UART and
    // shifts boot timing into the intermittent wedge before logind runs. Only
    // failures matter for 226/NAMESPACE diagnosis.
    #[cfg(feature = "debug-mount")]
    {
        let Ok(tgt0) = crate::mount_common::read_user_path_required(args.a1) else { return rv; };
        // Log failures AND any mount that touches /proc or /sys (success too) —
        // the 226 is a shadowing /proc mount in the sandbox hiding the static
        // /proc/sys/kernel/domainname leaf. Need to see what gets mounted there.
        if rv < 0 || tgt0.contains("/proc") || tgt0.contains("/sys") {
        let tgt = tgt0;
        let Ok(src) = crate::mount_common::read_optional_user_path(args.a0).map(|s| match s { Some(v) => v, None => String::from("(null)") }) else { return rv; };
        let Ok(fst) = crate::mount_common::read_user_cstr_owned(args.a2, 32) else { return rv; };
        // src/fstype/flags inline so a failing /proc/self/fd/N mount shows what
        // it actually is (bind vs fstype vs the unknown-fstype EOPNOTSUPP path).
        let mut tag = alloc::string::String::from(tgt.as_str());
        tag.push_str(" src="); tag.push_str(&src);
        tag.push_str(" fst="); tag.push_str(&fst);
        tag.push_str(" fl=");
        crate::mount_common::mnt_log_hex("mount", &tag, args.a3, rv);
        // 1.1 mount-EPERM: log the caller's cred/cap state so an EPERM at the
        // CAP_SYS_ADMIN gate reveals whether the caller is root-without-the-cap
        // (cap-tracking bug) or an already-dropped uid (expected).
        if let Some(c) = sched::live::current() {
            use core::sync::atomic::Ordering::Acquire;
            klog::write_raw(b"[mnt-cap] euid=");
            klog::write_dec_u64(c.creds.euid.load(Acquire) as u64);
            klog::write_raw(b" ruid=");
            klog::write_dec_u64(c.creds.ruid.load(Acquire) as u64);
            klog::write_raw(b" sysadmin=");
            klog::write_dec_u64(if c.has_cap(sched::cap::SYS_ADMIN) { 1 } else { 0 });
            klog::write_raw(b" vpid=");
            klog::write_dec_u64(c.visible_pid() as u64);
            klog::write_raw(b"\n");
        }
        }
    }
    rv
}

fn sys_mount_impl(args: &SyscallArgs) -> i64 {
    let source_p = args.a0;
    let target_p = args.a1;
    let fstype_p = args.a2;
    let flags    = args.a3;
    let data_p   = args.a4;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let target_raw = match read_user_path_required(target_p) { Ok(s) => s, Err(rv) => return rv };
    let (target_mt, target) = match crate::pathresolve::resolve_mount_target_raw(&target_raw) {
        Ok(t) => t,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let namespace = match cur.mount_namespace_snapshot() {
        Some(namespace) => namespace,
        None => return -(Errno::Esrch.as_i32() as i64),
    };
    let ns = namespace.id();

    // MS_REMOUNT changes options on an EXISTING mount — it carries no
    // source, so it MUST be handled before MS_BIND (systemd remounts the
    // machine-id bind read-only with MS_RDONLY|MS_REMOUNT|MS_BIND; the
    // bind branch would read a NULL source and EFAULT).
    if flags & MS_REMOUNT != 0 {
        // Identify the mount by the `mnt_id` the walk CROSSED INTO (Linux
        // `path->mnt`), not a re-derived dentry: the walk follows the mount at
        // the final component and lands on the mounted-fs ROOT, which is not a
        // mountpoint (and a pseudo-fs `s_root` is shared) — re-derivation
        // EINVAL'd and broke systemd's RO bind-remount of the sandbox /proc/sys.
        let vp = match crate::pathresolve::resolve_path_raw(&target_raw, false) {
            Ok(p) => p, Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        let r = if flags & MS_BIND != 0 {
            vfs::mount::remount_flags_by_id(vp.mnt_id, flags & MS_REMOUNTABLE)
        } else {
            vfs::mount::remount_super_flags_by_id(vp.mnt_id, flags & MS_REMOUNTABLE)
        };
        return match r {
            Ok(()) => 0,
            Err(e) => crate::namei_common::errno_from_vfs(e),
        };
    }

    // MS_BIND: redirect `target` into the `source` subtree. fstype is
    // ignored (may be NULL). Source is required.
    if flags & MS_BIND != 0 {
        let source_raw = match read_user_path_required(source_p) { Ok(s) => s, Err(rv) => return rv };
        let source_vp = match crate::pathresolve::resolve_path_raw(&source_raw, false) {
            Ok(p) => p, Err(_) => return -(Errno::Enoent.as_i32() as i64),
        };
        // Bind-as-clone (docs/16§6): source is a normal resolved `struct path`
        // (crossing the final mount), target is a mount-target `struct path`
        // (not crossing the final mountpoint) with the walked parent mount id.
        let source_d = source_vp.dentry.clone();
        let source_mnt = source_vp.mnt_id;
        let source_ok = vfs::mount::mount_by_id(source_mnt).map(|m| vfs::mount::check_mnt(&m)).unwrap_or(false);
        #[cfg(feature = "debug-mount")]
        if target_raw.starts_with("/proc/self/fd/") || source_raw == "/" {
            klog::write_raw(b"[MNTBIND] ns=");
            klog::write_dec_u64(ns);
            klog::write_raw(b" source=");
            klog::write_raw(source_raw.as_bytes());
            klog::write_raw(b" source_mnt=");
            klog::write_dec_u64(source_mnt);
            klog::write_raw(b" source_ok=");
            klog::write_dec_u64(if source_ok { 1 } else { 0 });
            klog::write_raw(b" target=");
            klog::write_raw(target_raw.as_bytes());
            klog::write_raw(b" target_parent=");
            klog::write_dec_u64(target_mt.parent.mnt_id);
            klog::write_raw(b"\n");
        }
        if !source_ok {
            return -(Errno::Einval.as_i32() as i64);
        }
        let target_d = target_mt.mountpoint.clone();
        let target_parent_mnt = target_mt.parent.mnt_id;
        let target_ok = vfs::mount::mount_by_id(target_parent_mnt).map(|m| vfs::mount::check_mnt(&m)).unwrap_or(false);
        #[cfg(feature = "debug-mount")]
        if target_raw.starts_with("/proc/self/fd/") || source_raw == "/" {
            klog::write_raw(b"[MNTBIND2] ns=");
            klog::write_dec_u64(ns);
            klog::write_raw(b" target_parent=");
            klog::write_dec_u64(target_parent_mnt);
            klog::write_raw(b" target_ok=");
            klog::write_dec_u64(if target_ok { 1 } else { 0 });
            klog::write_raw(b" target_render=");
            klog::write_raw(target.as_bytes());
            klog::write_raw(b"\n");
        }
        if !target_ok {
            return -(Errno::Einval.as_i32() as i64);
        }
        // Linux `do_add_mount` keys the target on `(parent vfsmount, dentry)`.
        // The resolver already supplied that pair, so never re-derive placement
        // from the dentry's global parent chain.
        let bind_res = {
            let r = vfs::mount::register_bind_clone_under(target_parent_mnt, target_d.clone(), source_mnt, source_d.clone());
            let _ = vfs::mount::propagate_mount(&target_d);
            r
        };
        if let Err(e) = bind_res {
            return crate::namei_common::errno_from_vfs(e);
        }
        // Linux `do_loopback` creates the bind via `clone_mnt(old, dentry, 0)`
        // (flag 0, NOT CL_MAKE_SHARED): a bind is NEVER a peer of its source.
        // Shared-ness propagates ONLY from the destination, handled above by
        // `attach_recursive_mnt`/`propagate_mount`. Do NOT join the source's
        // peer group — that made the service rootfs SHARED and EINVAL'd
        // pivot_root (systemd `make-rslave /` + open_tree bind must stay private).
        // MS_REC: also clone every mount nested under `source` to the
        // matching path under `target` (recursive bind, docs/16§6).
        if flags & MS_REC != 0 {
            let _ = vfs::mount::bind_submounts_rec_at(Some(source_mnt), &source_d, &target_d, Some(target_parent_mnt));
        }
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
        // Resolve to the MOUNTPOINT dentry (not crossing into a mount attached
        // there) so `set_propagation`'s `mount_exact_at` finds the mount grafted
        // AT target. A plain resolve crosses in and yields the mount's ROOT
        // dentry, which mount_exact_at can't match → the retune silently no-ops
        // and e.g. systemd's `make-rslave /run/systemd/mount-rootfs` leaves the
        // service rootfs SHARED, so its later pivot_root -EINVAL'd.
        {
            let td = target_mt.mountpoint.clone();
            if flags & MS_REC != 0 {
                // Recursive retune (systemd `make-rslave /` before pivot_root):
                // apply to the target mount AND its whole subtree, else the
                // bind-cloned service rootfs stays SHARED and pivot_root EINVALs.
                let _ = vfs::mount::set_propagation_recursive(&td, kind);
            } else {
                let _ = vfs::mount::set_propagation(&td, kind);
            }
        }
        return 0;
    }
    // MS_MOVE: relocate the mount currently at `source` to `target`.
    // The mount tree is implicit (parent = longest-prefix mount_point),
    // so the move is a mount_point rewrite preserving mnt_id +
    // propagation; the new parent_id falls out of the recompute. Source
    // is the existing mount point (required, absolute).
    if flags & MS_MOVE != 0 {
        let source_raw = match read_user_path_required(source_p) { Ok(s) => s, Err(rv) => return rv };
        // Identify the SOURCE mount by the `mnt_id` the walk crossed into (Linux
        // `path->mnt`), not a re-derived dentry: the source resolves THROUGH the
        // moved mount onto its (shared) root, which can't map back to a mount.
        let src_vp = match crate::pathresolve::resolve_path_raw(&source_raw, false) {
            Ok(p) => p,
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        // Thread the walked destination parent mount id: `to` may sit in a bind
        // mount whose shared dentries make `parent_by_dentry` ambiguous, but the
        // final component must remain the mountpoint dentry rather than crossing
        // into an existing mount there (systemd PrivateDevices MS_MOVE to /dev).
        let mr = vfs::mount::move_mount_by_id_to_rendered(src_vp.mnt_id, Some(target_mt.parent.mnt_id), &target_mt.mountpoint, target.clone());
        return match mr {
            Ok(())                    => 0,
            Err(vfs::VfsError::Ebusy) => -(Errno::Ebusy.as_i32() as i64),
            Err(_)                    => -(Errno::Einval.as_i32() as i64),
        };
    }

    // New mount by fstype.
    let source = match read_optional_user_path(source_p) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let fstype = match read_user_cstr_owned(fstype_p, 32)  { Ok(s) => s, Err(rv) => return rv };
    #[cfg(feature = "debug-boot")]
    if target.contains("credentials") {
        let ns = sched::live::current().and_then(sched::Task::mount_namespace_id).unwrap_or(0);
        klog::write_raw(b"[cred mount] fstype="); klog::write_raw(fstype.as_bytes());
        klog::write_raw(b" ns="); klog::write_dec_u64(ns);
        klog::write_raw(b" path="); klog::write_raw(target.as_bytes());
        klog::write_raw(b"\n");
    }
    let data = if data_p != 0 {
        match read_user_cstr_owned(data_p, 4096) {
            Ok(s) => s, Err(rv) => return rv,
        }
    } else {
        String::new()
    };
    mount_fstype_at(source.as_deref(), &fstype, &target, &target_mt.mountpoint, Some(target_mt.parent.mnt_id), &data)
}
