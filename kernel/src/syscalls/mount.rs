// Real `sys_mount(source, target, fstype, flags, data)` — slot 165.
// V1 honours fstype="tmpfs" by spawning a fresh TmpfsRootInode at
// `target` in devfs. Other fstypes return EOPNOTSUPP. Requires
// CAP_SYS_ADMIN. Per-NS mount-table virtualisation is a follow-up (per-NS mount table)
// once a real backend (ext4 + block) lands; until then mount(2)
// affects the global registry shared by all mount_ns ids.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

fn read_user_cstr_owned(p: u64, max: usize) -> Result<String, i64> {
    if p == 0 || p >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p validated < USER_VA_END; bounded read via existing helper.
    let bytes = unsafe { crate::devfs::read_user_cstr(p, max) };
    let s = bytes.and_then(|b| core::str::from_utf8(b).ok())
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    Ok(String::from(s))
}

/// `sys_mount(source, target, fstype, flags, data)` — slot 165.
/// # C: O(N_path)
pub fn sys_mount(args: &SyscallArgs) -> i64 {
    let _source = args.a0;
    let target_p = args.a1;
    let fstype_p = args.a2;
    let _flags   = args.a3;
    let _data    = args.a4;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    let target = match read_user_cstr_owned(target_p, 256) { Ok(s) => s, Err(rv) => return rv };
    let fstype = match read_user_cstr_owned(fstype_p, 32)  { Ok(s) => s, Err(rv) => return rv };
    if !target.starts_with('/') {
        return -(Errno::Einval.as_i32() as i64);
    }
    match fstype.as_str() {
        "tmpfs" => {
            let inode: InodeRef = Arc::new(::fs::tmpfs::TmpfsRootInode::new(target.clone()));
            // F119: register in caller's mount_ns so unshared tasks
            // see only their own mounts.
            let ns = cur.mount_ns.load(core::sync::atomic::Ordering::Acquire);
            crate::devfs::register_in_ns(ns, target, inode);
            0
        }
        // proc and sysfs are already registered at boot; admit-and-noop
        // for these fstypes so userspace remount probes (systemd, /etc/
        // mtab tooling) don't choke.
        "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" => 0,
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}

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
    let removed = crate::devfs::unregister_subtree(ns, trimmed);
    if removed == 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    0
}
