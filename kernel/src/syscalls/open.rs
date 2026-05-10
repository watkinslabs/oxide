// `sys_open` / `sys_openat` per `15§5` / `16§3`. Split from
// syscall_glue.rs / syscall_glue_fs.rs to keep both under cap.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::ToString;
use alloc::sync::Arc;

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use vfs::{Dentry, File, OpenFlags};


const O_CREAT:     u32 = 0o100;
const O_TRUNC:     u32 = 0o1000;
const O_DIRECTORY: u32 = 0o200000;

/// Resolve a relative path against the calling task's cwd. Returns
/// `None` for absolute paths (caller uses path_raw verbatim).
/// Critically, the bare `.` and `..` cases must NOT be short-
/// circuited — `ls` (no arg) sends `.` and the openat lookup
/// otherwise tries to find a literal `.` entry in the registry,
/// which doesn't exist.
/// # C: O(N)
fn resolve_path_for_open(path_raw: &str) -> Option<alloc::string::String> {
    if path_raw.starts_with('/') { return None; }
    let cur = crate::sched::current()?;
    // SAFETY: cwd slot single-mutator per `13§5`.
    let cwd = unsafe { (*cur.cwd.get()).clone() };
    vfs::path::resolve_against_cwd(&cwd, path_raw)
}

/// `sys_open(path, flags, mode)` — slot 2.
/// # C: O(N_path)
pub fn kernel_sys_open(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let flags    = args.a1 as u32;
    let _mode    = args.a2;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller already ran code from this AS); 256 B bound.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let path_raw = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(path_raw);
    let path_str: &str = resolved.as_deref().unwrap_or(path_raw);
    // Lookup chain. Real-fs paths (/bin /etc /usr /sbin /lib /opt
    // /home /root) prefer ext4; pseudo paths (/dev /proc /sys /tmp)
    // stay on the synthetic providers. Per the Linux mount-table
    // shape: pseudo-fs mounts shadow real-fs paths.
    let prefer_ext4 = path_str.starts_with("/bin/")
                   || path_str.starts_with("/etc/")
                   || path_str.starts_with("/usr/")
                   || path_str.starts_with("/sbin/")
                   || path_str.starts_with("/lib/")
                   || path_str.starts_with("/opt/")
                   || path_str.starts_with("/home/")
                   || path_str.starts_with("/root/")
                   || path_str == "/init"
                   || path_str == "/hello.txt";
    let inode = if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev::pty::allocate_pair();
        master
    } else if prefer_ext4 {
        if let Some(i) = ext4::rootfs::lookup_inode(path_str.as_bytes()) { i }
        else if let Some(i) = crate::devfs::lookup(path_str) { i }
        else if let Some(i) = crate::procfs::lookup_dynamic(path_str) { i }
        else if let Some(i) = ::fs::tmpfs::lookup(path_str) { i }
        else if (flags & O_CREAT) != 0 {
            match ext4::rootfs::create_at(path_str.as_bytes(), 0o644) {
                Some(i) => i,
                None    => return -(Errno::Enoent.as_i32() as i64),
            }
        }
        else { return -(Errno::Enoent.as_i32() as i64); }
    } else if let Some(i) = crate::devfs::lookup(path_str) { i }
        else if let Some(i) = crate::procfs::lookup_dynamic(path_str) { i }
        else if let Some(i) = ::fs::tmpfs::lookup(path_str) { i }
        else if let Some(i) = ext4::rootfs::lookup_inode(path_str.as_bytes()) { i }
        else if (flags & O_CREAT) != 0 && path_str.starts_with("/tmp/") {
            ::fs::tmpfs::lookup_or_create(path_str)
        } else { return -(Errno::Enoent.as_i32() as i64); };
    if (flags & O_DIRECTORY) != 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, path_str.to_string(), Arc::clone(&inode));
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new(inode, dentry, oflags);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}

/// `sys_openat(dirfd, path, flags, mode)` — slot 257.
/// # C: O(N_path)
pub fn kernel_sys_openat(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a1;
    let flags    = args.a2 as u32;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = resolve_path_for_open(s);
    let path_str: &str = resolved.as_deref().unwrap_or(s);
    // Lookup chain. Real-fs paths (/bin /etc /usr /sbin /lib /opt
    // /home /root) prefer ext4; pseudo paths (/dev /proc /sys /tmp)
    // stay on the synthetic providers. Per the Linux mount-table
    // shape: pseudo-fs mounts shadow real-fs paths.
    let prefer_ext4 = path_str.starts_with("/bin/")
                   || path_str.starts_with("/etc/")
                   || path_str.starts_with("/usr/")
                   || path_str.starts_with("/sbin/")
                   || path_str.starts_with("/lib/")
                   || path_str.starts_with("/opt/")
                   || path_str.starts_with("/home/")
                   || path_str.starts_with("/root/")
                   || path_str == "/init"
                   || path_str == "/hello.txt";
    let inode = if path_str == "/dev/ptmx" {
        let (master, _n) = crate::dev::pty::allocate_pair();
        master
    } else if prefer_ext4 {
        if let Some(i) = ext4::rootfs::lookup_inode(path_str.as_bytes()) { i }
        else if let Some(i) = crate::devfs::lookup(path_str) { i }
        else if let Some(i) = crate::procfs::lookup_dynamic(path_str) { i }
        else if let Some(i) = ::fs::tmpfs::lookup(path_str) { i }
        else if (flags & O_CREAT) != 0 {
            match ext4::rootfs::create_at(path_str.as_bytes(), 0o644) {
                Some(i) => i,
                None    => return -(Errno::Enoent.as_i32() as i64),
            }
        }
        else { return -(Errno::Enoent.as_i32() as i64); }
    } else if let Some(i) = crate::devfs::lookup(path_str) { i }
        else if let Some(i) = crate::procfs::lookup_dynamic(path_str) { i }
        else if let Some(i) = ::fs::tmpfs::lookup(path_str) { i }
        else if let Some(i) = ext4::rootfs::lookup_inode(path_str.as_bytes()) { i }
        else if (flags & O_CREAT) != 0 && path_str.starts_with("/tmp/") {
            ::fs::tmpfs::lookup_or_create(path_str)
        } else { return -(Errno::Enoent.as_i32() as i64); };
    if (flags & O_DIRECTORY) != 0
        && !matches!(inode.file_type(), vfs::FileType::Directory)
    {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    if (flags & O_TRUNC) != 0 { let _ = inode.truncate(0); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, path_str.to_string(), Arc::clone(&inode));
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new(inode, dentry, oflags);
    match fdt.alloc(file) {
        Ok(fd)  => fd as i64,
        Err(e)  => -(e as i64),
    }
}
