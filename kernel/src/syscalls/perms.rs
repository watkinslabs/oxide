// Real `chmod` / `fchmod` / `fchmodat` / `chown` / `fchown` /
// `lchown` / `fchownat` (slots 90/91/268/92/93/94/260). v1 stores
// the mode + owner overlay in `inode_times` so statx surfaces them
// back to userspace. Real per-inode metadata (Inode trait extension
// or per-FS storage) rides a follow-up that touches every Inode impl.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

fn resolve_path_inode(path_ptr: u64) -> Result<InodeRef, i64> {
    if path_ptr == 0 || path_ptr >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: path_ptr in user range; bounded read via existing helper.
    let bytes = unsafe { crate::devfs::read_user_cstr(path_ptr, 256) };
    let s = bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() })
        .ok_or(-(Errno::Einval.as_i32() as i64))?;
    crate::devfs::lookup(s).ok_or(-(Errno::Enoent.as_i32() as i64))
}

fn resolve_fd_inode(fd: i32) -> Result<InodeRef, i64> {
    let cur = match crate::sched::current() {
        Some(c) => c, None => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    let f = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return Err(-(Errno::Ebadf.as_i32() as i64)),
    };
    Ok(f.inode().clone())
}

/// `sys_chmod(path, mode)` — slot 90.
/// # C: O(N_path)
pub fn kernel_sys_chmod(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a0) { Ok(i) => i, Err(rv) => return rv };
    let m = args.a1 as u16;
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(&inode, m, now_ns()); }
    0
}

/// `sys_fchmod(fd, mode)` — slot 91.
/// # C: O(1)
pub fn kernel_sys_fchmod(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let m = args.a1 as u16;
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(&inode, m, now_ns()); }
    0
}

/// `sys_fchmodat(dirfd, path, mode, flags)` — slot 268. v1 ignores
/// dirfd and resolves `path` against the global devfs.
/// # C: O(N_path)
pub fn kernel_sys_fchmodat(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a1) { Ok(i) => i, Err(rv) => return rv };
    let m = args.a2 as u16;
    if inode.set_perm(m).is_err() { vfs::inode_times::set_mode(&inode, m, now_ns()); }
    0
}

/// `sys_chown(path, uid, gid)` / `sys_lchown(path, uid, gid)` — slots 92/94.
/// # C: O(N_path)
pub fn kernel_sys_chown(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a0) { Ok(i) => i, Err(rv) => return rv };
    let u = args.a1 as u32; let g = args.a2 as u32;
    if inode.set_owner(u, g).is_err() { vfs::inode_times::set_owner(&inode, u, g, now_ns()); }
    0
}

/// `sys_fchown(fd, uid, gid)` — slot 93.
/// # C: O(1)
pub fn kernel_sys_fchown(args: &SyscallArgs) -> i64 {
    let inode = match resolve_fd_inode(args.a0 as i32) { Ok(i) => i, Err(rv) => return rv };
    let u = args.a1 as u32; let g = args.a2 as u32;
    if inode.set_owner(u, g).is_err() { vfs::inode_times::set_owner(&inode, u, g, now_ns()); }
    0
}

/// `sys_fchownat(dirfd, path, uid, gid, flags)` — slot 260.
/// # C: O(N_path)
pub fn kernel_sys_fchownat(args: &SyscallArgs) -> i64 {
    let inode = match resolve_path_inode(args.a1) { Ok(i) => i, Err(rv) => return rv };
    let u = args.a2 as u32; let g = args.a3 as u32;
    if inode.set_owner(u, g).is_err() { vfs::inode_times::set_owner(&inode, u, g, now_ns()); }
    0
}

/// Single-arm dispatch helper for syscall_glue.rs.
/// # C: O(1)
pub fn perms_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    let rv = match nr {
        NR_CHMOD     => kernel_sys_chmod(args),
        NR_FCHMOD    => kernel_sys_fchmod(args),
        NR_FCHMODAT  => kernel_sys_fchmodat(args),
        NR_CHOWN | NR_LCHOWN => kernel_sys_chown(args),
        NR_FCHOWN    => kernel_sys_fchown(args),
        NR_FCHOWNAT  => kernel_sys_fchownat(args),
        _ => return None,
    };
    Some(rv)
}
