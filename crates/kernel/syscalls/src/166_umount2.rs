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
    use core::sync::atomic::Ordering;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let target_ptr = args.a0;
    let path = match read_user_cstr_owned(target_ptr, 256) {
        Ok(p) => p, Err(rv) => return rv,
    };
    let trimmed: &str = match path.as_str() {
        s if s.len() > 1 && s.ends_with('/') => &s[..s.len() - 1],
        s => s,
    };
    // Reject kernel-managed roots: detaching /proc /sys /dev would
    // brick procfs/sysfs/devfs lookups for every task. Linux
    // typically returns EINVAL or EBUSY for these.
    match trimmed {
        "/" | "/proc" | "/sys" | "/dev" | "/dev/pts" | "/dev/shm"
        | "/sys/kernel/tracing" | "/sys/fs/cgroup" => {
            return -(Errno::Ebusy.as_i32() as i64);
        }
        _ => {}
    }
    let ns = cur.mount_ns.load(Ordering::Acquire);
    // Detach from BOTH the unified mount table (bind mounts + any
    // TABLE-resident mount) and the devfs registry (tmpfs etc). Before
    // U3, only the registry was touched, so unmounting a bind mount was a
    // silent no-op that left it resolving forever.
    let removed_tab = vfs::mount::unregister(trimmed);
    let removed_reg = devfs::unregister_subtree(ns, trimmed);
    if removed_tab == 0 && removed_reg == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    0
}
