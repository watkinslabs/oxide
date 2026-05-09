// Real `sys_mount(source, target, fstype, flags, data)` — slot 165.
// V1 honours fstype="tmpfs" by spawning a fresh TmpfsRootInode at
// `target` in devfs. Other fstypes return EOPNOTSUPP. Requires
// CAP_SYS_ADMIN. Per-NS mount-table virtualisation rides v2 phase 29
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
pub fn kernel_sys_mount(args: &SyscallArgs) -> i64 {
    let _source = args.a0;
    let target_p = args.a1;
    let fstype_p = args.a2;
    let _flags   = args.a3;
    let _data    = args.a4;
    let cur = match crate::sched::current() {
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
            let inode: InodeRef = Arc::new(crate::tmpfs::TmpfsRootInode::new(target.clone()));
            crate::devfs::register_owned(target, inode);
            0
        }
        // proc and sysfs are already registered at boot; admit-and-noop
        // for these fstypes so userspace remount probes (systemd, /etc/
        // mtab tooling) don't choke.
        "proc" | "sysfs" | "devtmpfs" | "devpts" | "cgroup" | "cgroup2" => 0,
        _ => -(Errno::Eopnotsupp.as_i32() as i64),
    }
}

/// `sys_umount2(target, flags)` — slot 166. v1 cannot un-register a
/// devfs inode atomically with all open fds (no real refcount on the
/// path entry); accept silently for now so umount probes succeed.
/// Real umount with force/lazy semantics rides v2 phase 29.
/// # C: O(1)
pub fn kernel_sys_umount2(_args: &SyscallArgs) -> i64 {
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    if !cur.has_cap(sched::cap::SYS_ADMIN) {
        return -(Errno::Eperm.as_i32() as i64);
    }
    0
}
