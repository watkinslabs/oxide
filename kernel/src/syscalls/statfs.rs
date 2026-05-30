// statfs(2)/fstatfs(2) — slots 137/138. Reports the backing
// filesystem's `s_magic` as `f_type`, classified from the live mount
// table + the fixed synthetic-mount prefix set. systemd & util-linux
// detect fs type by this magic; a constant/wrong value broke
// cgroup2 / tmpfs / proc detection. Split from fs.rs for the 1000-line
// cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::syscalls::validate_user_buf;

// struct statfs `f_type` magics (linux/magic.h).
const M_PROC:    u64 = 0x9fa0;
const M_SYSFS:   u64 = 0x6265_6572;
const M_TMPFS:   u64 = 0x0102_1994;
const M_CGROUP2: u64 = 0x6367_7270;
const M_DEVPTS:  u64 = 0x1cd1;
const M_EXT4:    u64 = 0xEF53;

/// True when `m` equals `path` or is a path-prefix of it (`m` + `/…`).
fn under(path: &str, m: &str) -> bool {
    path == m || (path.starts_with(m) && path.as_bytes().get(m.len()) == Some(&b'/'))
}

/// Resolve an absolute path to its backing filesystem's `s_magic`.
/// Consults the live mount table first (so user `mount -t tmpfs|cgroup2`
/// and bind mounts report correctly — the Linux way), then a prefix
/// table for the fixed synthetic trees not registered as mounts
/// (sysfs `/sys`, devpts `/dev/pts`, tmpfs `/run` + `/dev/shm`), then
/// falls back to the ext4 rootfs.
/// # C: O(N_mounts)
pub fn magic_for_path(path: &str) -> u64 {
    // A registered mount that isn't the root wins (longest-prefix).
    if let Some((mnt, _)) = vfs::mount::resolve_mount(path) {
        if mnt.mount_point != "/" {
            let m = mnt.fs.magic();
            if m != 0 { return m; }
        }
    }
    // Fixed synthetic mounts not in the table. cgroup before sysfs.
    if under(path, "/sys/fs/cgroup")             { return M_CGROUP2; }
    if under(path, "/proc")                      { return M_PROC; }
    if under(path, "/sys")                       { return M_SYSFS; }
    if under(path, "/dev/pts")                   { return M_DEVPTS; }
    if under(path, "/dev/shm") || under(path, "/run") || under(path, "/tmp") { return M_TMPFS; }
    if under(path, "/dev")                       { return M_TMPFS; }
    M_EXT4
}

/// Fill a 120-byte `struct statfs` (identical LP64 layout on x86_64
/// and aarch64) with `magic` as `f_type`. Block/inode counts stay 0 —
/// our synthetic fses are unsized and ext4 usage tracking is a
/// follow-up; the f_type is what fs-type detection keys on.
/// # C: O(1)
fn write_statfs(buf: u64, magic: u64) {
    // SAFETY: caller validated 120-byte user buf < USER_VA_END, 8-aligned; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..120u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile( buf        as *mut u64, magic); // f_type   @0
        core::ptr::write_volatile((buf +  8)  as *mut u64, 4096);  // f_bsize  @8
        core::ptr::write_volatile((buf + 64)  as *mut u64, 255);   // f_namelen@64 (NAME_MAX)
        core::ptr::write_volatile((buf + 72)  as *mut u64, 4096);  // f_frsize @72
    }
}

/// `sys_statfs(path, buf)` — slot 137. Reports the `f_type` magic of
/// the filesystem backing `path`.
/// # C: O(N_mounts)
pub fn sys_statfs(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;
    if let Err(rv) = validate_user_buf(buf, 120, 8) { return rv; }
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's user code ran from this AS); read bounded at 256 B.
    let magic = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) => match core::str::from_utf8(p) {
            Ok(s) => magic_for_path(s),
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        },
        None => return -(Errno::Efault.as_i32() as i64),
    };
    write_statfs(buf, magic);
    0
}

/// `sys_fstatfs(fd, buf)` — slot 138. Reports the backing fs magic for
/// an open fd, classified by the path the fd was opened with.
/// # C: O(N_mounts)
pub fn sys_fstatfs(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    if let Err(rv) = validate_user_buf(buf, 120, 8) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // open(2) stores the full open path as the (flat) dentry name.
    let name = file.dentry().name();
    let magic = if name.starts_with('/') { magic_for_path(name) } else { M_TMPFS };
    write_statfs(buf, magic);
    0
}
