// 166 umount2 — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::mount_common::read_user_cstr_owned;

/// `sys_umount2(target, flags)` — slot 166.
///
/// Linux umount2(2) detaches a mount point. v1 implementation:
/// resolve the target path to a mount-NS-scoped registry entry,
/// remove every entry under the subtree (inclusive), and fire
/// IN_DELETE on each. Returns EINVAL if the target isn't a known
/// path, EPERM without CAP_SYS_ADMIN, EBUSY if `flags == 0` and
/// the target is a kernel-internal mount that shouldn't unmount
/// (proc/sys/dev/devpts), 0 on success.
///
/// `flags` honours MNT_FORCE (1) + MNT_DETACH (2) + UMOUNT_NOFOLLOW
/// (8) syntactically; v1 detaches in all cases since we don't track
/// open-fd refcounts on registry entries (see `26§3.1` follow-up).
/// # C: O(N) over devfs registry.
pub fn sys_umount2(args: &SyscallArgs) -> i64 {
    let rv = sys_umount2_impl(args);
    #[cfg(feature = "debug-mount")]
    {
        let tgt = read_user_cstr_owned(args.a0, 256).unwrap_or_default();
        crate::mount_common::mnt_log("umount2", &tgt, rv);
    }
    rv
}

fn sys_umount2_impl(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    // Linux ksys_umount flag gate (D53): reject unknown bits, and MNT_EXPIRE is
    // mutually exclusive with MNT_FORCE/MNT_DETACH — both before the path walk.
    const MNT_FORCE:        u64 = 1;
    const MNT_DETACH_BIT:   u64 = 2;
    const MNT_EXPIRE:       u64 = 4;
    const UMOUNT_NOFOLLOW:  u64 = 8;
    let flags = args.a1;
    if flags & !(MNT_FORCE | MNT_DETACH_BIT | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if (flags & MNT_EXPIRE) != 0 && (flags & (MNT_FORCE | MNT_DETACH_BIT)) != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let target_ptr = args.a0;
    let path_raw = match read_user_cstr_owned(target_ptr, 256) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let path = crate::pathresolve::resolve_cwd(&path_raw);
    let trimmed: &str = match path.as_str() {
        s if s.len() > 1 && s.ends_with('/') => &s[..s.len() - 1],
        s => s,
    };
    let ns = cur.mount_ns.load(Ordering::Acquire);
    const MNT_DETACH: u64 = 2;
    let lazy = (args.a1 & MNT_DETACH) != 0;

    // Linux `do_umount` semantics (fs/namespace.c), NO path blacklist:
    //
    //  * The namespace root `/` can never be unmounted → EINVAL.
    //  * A mount that has CHILD MOUNTS stacked under it is busy → EBUSY,
    //    unless MNT_DETACH (lazy) was requested. This is what protects the
    //    init ns's /dev (its real /dev/shm tmpfs submount makes it busy),
    //    /sys (cgroup2), etc. — exactly as Linux does, via the mount tree,
    //    not a hardcoded list. Plain device-node *files* under /dev are fs
    //    content, not mounts, so they correctly don't block the unmount.
    //  * Otherwise detach. The unmount is namespace-LOCAL: it only touches
    //    THIS task's mount_ns (its copy-on-unshare snapshot), never another
    //    namespace — so a private-ns service unmounting /dev/proc/sys for
    //    PrivateDevices=/ProtectKernelTunables= no longer fails the sandbox
    //    (was status=226/NAMESPACE).
    if trimmed == "/" && !lazy {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Linux umount(2) detaches a mount; it NEVER destroys the filesystem's
    // backing data. For the synthetic pseudo-filesystems (procfs/sysfs/
    // devtmpfs) the "data" is generated from kernel state — sysctl ctl_tables
    // (/proc/sys/*), the device list (/dev/*), kobjects (/sys/*) — which lives
    // independent of any mount and persists across umount/remount. Our
    // INITIAL-namespace (ns 0) devfs tree IS that kernel-side backing store.
    // So umounting one of these in ns 0 must detach the mount WITHOUT deleting
    // the tree; deleting it (the old devfs::unregister_subtree path) permanently
    // wiped /proc/sys/* after systemd's early `umount /proc`, breaking every
    // later sandbox that binds /proc/sys/kernel/domainname (status 226). Treat
    // it as a successful no-op: a (re)mount re-exposes the same synthetic
    // content, exactly as procfs regenerates it on Linux. Per-namespace (ns>0)
    // sandbox copies remain real mount content and tear down normally below.
    // The single namei walk umount2(2) does to validate the target crosses
    // into a mounted fs, so `/proc` resolves to procfs's root dentry. The
    // mount engine, however, detaches by the covered mountpoint dentry. If the
    // resolved final dentry is exactly the mounted fs root, translate the
    // VfsPath's mnt_id back to that mountpoint; otherwise it is not an exact
    // mount root and unregister_top() must fail with EINVAL.
    let resolved = crate::pathresolve::resolve_path(trimmed, false);
    let exact_mountpoint = resolved.as_ref().and_then(|p| {
        let root = vfs::mount::root_dentry_for_mount_id(p.mnt_id)?;
        if !Arc::ptr_eq(&p.dentry, &root) {
            return None;
        }
        vfs::mount::mountpoint_of(p.mnt_id).map(|(mp, _)| mp)
    });
    // Exact-root umount of a synthetic pseudo-filesystem (procfs/sysfs/
    // devtmpfs/devfs) is a successful no-op in ANY mount namespace, not only
    // ns 0. The content is kernel-generated and a (re)mount re-exposes it, so
    // tearing it down would strand later accessors — e.g. systemd/udevd in a
    // PRIVATE mount namespace umounts /proc during sandbox setup and must keep
    // seeing procfs afterward. The `exact_mountpoint` identity check fires
    // ONLY for the mounted fs ROOT: a descendant like /proc/sys/fs/binfmt_misc
    // keeps the same mnt_id but fails the root-dentry check, so it falls
    // through to normal teardown below.
    // Is the umount target a synthetic pseudo-fs (procfs/sysfs/devfs) mount?
    // Previously these returned 0 as a NO-OP (mount left in the table) to avoid
    // wiping their kernel-generated backing — but leaving the mount visible in
    // /proc/self/mountinfo made a userspace "umount until gone" loop spin
    // FOREVER: systemd's RootDirectory/MountAPIVFS teardown of
    // /run/systemd/mount-rootfs/{dev,proc,sys} called umount2 tens of thousands
    // of times (each returned 0, the mount never left mountinfo), a CPU-burning
    // livelock that starved dbus-broker/udevd/logind into their start timeouts.
    // Now: DETACH the instance (unregister_top below removes it from the table →
    // gone from mountinfo → the loop terminates) but NEVER wipe the synthetic
    // backing (it regenerates on re-mount, exactly as Linux umount detaches a
    // mount without destroying fs data).
    let is_pseudo = exact_mountpoint.is_some() && resolved.as_ref()
        .and_then(|p| vfs::mount::mount_by_id(p.mnt_id))
        .map(|m| matches!(m.fs().name(), "procfs" | "sysfs" | "devtmpfs" | "devfs"))
        .unwrap_or(false);
    // `None` (target gone or not a mount root) ⇒ no TABLE mount, but the
    // devfs-registry detach below may still match legacy devfs-owned paths.
    let target_d = exact_mountpoint.or_else(|| crate::pathresolve::mount_dentry(trimmed));
    // A pseudo-fs mount (procfs/sysfs/devfs) detaches its WHOLE subtree, even
    // non-lazy. systemd tears down its per-service sandbox staging tree
    // (/run/systemd/mount-rootfs/{proc,sys,dev}) with non-lazy umount2 — in
    // Linux that mount is already childless (its submounts were moved out via
    // pivot_root/MS_MOVE), so it succeeds; our tree keeps them nested, so the
    // Linux EBUSY-on-children busy-test spuriously fired and aborted the
    // sandbox setup (EXIT_NAMESPACE 226, intermittently, for dbus-broker/
    // udevd/logind → no graphical target). Recursive detach makes the staging
    // subtree vanish cleanly; a REAL (non-pseudo) mount keeps the Linux
    // EBUSY-on-children guard.
    let recursive = lazy || is_pseudo;
    if !recursive && target_d.as_ref().map(|d| vfs::mount::has_child_mounts(d, ns)).unwrap_or(false) {
        return -(Errno::Ebusy.as_i32() as i64);
    }
    // Detach from BOTH the unified mount table (bind mounts + any
    // TABLE-resident mount) and the legacy devfs registry for the paths devfs
    // actually owns. Do not apply the devfs fallback to `/proc` or `/sys`:
    // those are separate pseudo-filesystems now, and a non-mounted descendant
    // such as `/proc/sys/fs/binfmt_misc` must report EINVAL. Returning success
    // there makes systemd's automount cleanup spin on umount2 forever.
    let removed_tab = target_d.as_ref().map(|d| vfs::mount::unregister_top(d, recursive)).unwrap_or(0);
    // Registry wipe is ONLY for a real device-node fs at a devfs-owned path —
    // NEVER for a pseudo-fs (deleting the synthetic /proc/sys/dev tree once
    // permanently broke every later sandbox). The instance detach above already
    // removed it from mountinfo.
    let is_devfs_path = !is_pseudo && (trimmed == "/dev" || trimmed.starts_with("/dev/")
        || trimmed == "/etc" || trimmed.starts_with("/etc/"));
    let removed_reg = if is_devfs_path { devfs::unregister_subtree(ns, trimmed) } else { 0 };
    // A pseudo-fs umount that matched no removable mount instance is a
    // successful no-op (Linux detaches the initial /proc; a synthetic root with
    // no separate instance has nothing to remove) — never surface EINVAL there.
    if removed_tab == 0 && removed_reg == 0 && !is_pseudo {
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[umount EINVAL] ns="); klog::write_dec_u64(ns);
            klog::write_raw(b" lazy="); klog::write_dec_u64(lazy as u64);
            klog::write_raw(b" path="); klog::write_raw(trimmed.as_bytes());
            klog::write_raw(b"\n");
        }
        return -(Errno::Einval.as_i32() as i64);
    }
    0
}
