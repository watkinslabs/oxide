// 166 umount2 — one syscall, one file (docs/53 §0). Moved verbatim from mount.rs.

#![cfg(target_os = "oxide-kernel")]

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
    if ns == 0 {
        // Confirm `trimmed` is EXACTLY a synthetic mount (not a path under
        // one) by mount-object identity: `mount_at_path_exact` resolves the
        // target dentry and reads its covering-mount link, so this is the
        // mount whose mountpoint dentry IS `trimmed` — not the longest-prefix
        // owner `resolve_mount` would return.
        if let Some(m) = vfs::mount::mount_at_path_exact(trimmed) {
            if matches!(m.fs.name(), "procfs" | "sysfs" | "devtmpfs" | "devfs") {
                return 0;
            }
        }
    }
    if !lazy && vfs::mount::has_child_mounts(trimmed, ns) {
        return -(Errno::Ebusy.as_i32() as i64);
    }
    // Detach from BOTH the unified mount table (bind mounts + any
    // TABLE-resident mount) and the devfs registry (procfs/sysfs/devtmpfs
    // content + tmpfs). Both are namespace-scoped.
    let removed_tab = vfs::mount::unregister_top(trimmed, lazy);
    let removed_reg = devfs::unregister_subtree(ns, trimmed);
    if removed_tab == 0 && removed_reg == 0 {
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
