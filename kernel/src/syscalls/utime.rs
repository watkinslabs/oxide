// Real `utimensat` / `utimes` / `utime` (slots 280/235/132).
// Stores timestamps in the inode_times overlay so statx reads them back.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::InodeRef;

const UTIME_NOW:  i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;
const AT_FDCWD:   i32 = -100;

fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

fn read_user_ns_pair(p: u64, idx: usize, now: u64) -> Result<Option<u64>, i64> {
    // Linux: each timespec is 16 bytes (sec + nsec, i64 each).
    let off = (idx * 16) as u64;
    if p.checked_add(off + 16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: p+off+16 validated < USER_VA_END; CPL=0 reads the timespec pair (i64 sec, i64 nsec) through caller's AS.
    unsafe {
        let sec  = core::ptr::read_volatile((p + off)     as *const i64);
        let nsec = core::ptr::read_volatile((p + off + 8) as *const i64);
        if nsec == UTIME_OMIT { return Ok(None); }
        if nsec == UTIME_NOW  { return Ok(Some(now)); }
        if sec < 0 || nsec < 0 || nsec >= 1_000_000_000 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
        Ok(Some((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64)))
    }
}

fn resolve_inode(dirfd: i32, path_ptr: u64) -> Result<InodeRef, i64> {
    if path_ptr == 0 {
        // utimensat with NULL path = update by fd.
        let cur = match sched::live::current() {
            Some(c) => c, None => return Err(-(Errno::Ebadf.as_i32() as i64)),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)),
        };
        let f = match fdt.get(dirfd) {
            Ok(f) => f, Err(_) => return Err(-(Errno::Ebadf.as_i32() as i64)),
        };
        return Ok(f.inode().clone());
    }
    if path_ptr >= hal::USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    // SAFETY: path_ptr in user range; bounded read via devfs::read_user_cstr.
    let bytes = unsafe { crate::devfs::read_user_cstr(path_ptr, 256) };
    let raw = match bytes.and_then(|b| if b.is_empty() { None } else { core::str::from_utf8(b).ok() }) {
        Some(s) => s, None => return Err(-(Errno::Einval.as_i32() as i64)),
    };
    let _ = dirfd; //  AT_FDCWD assumed; full dirfd-relative resolution rides namei rewrite.
    let resolved = crate::syscalls::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
    if let Ok(i) = vfs::mount::lookup(s) { return Ok(i); }
    if let Some(i) = ext4::rootfs::lookup_inode_any(s.as_bytes()) { return Ok(i); }
    Err(-(Errno::Enoent.as_i32() as i64))
}

/// `sys_utimensat(dirfd, path, times[2], flags)` — slot 280.
/// `times == NULL` ⇒ both atime and mtime = now.
/// Each slot may be UTIME_NOW (use now_ns), UTIME_OMIT (don't change),
/// or a real timespec.
/// # C: O(N_path)
pub fn sys_utimensat(args: &SyscallArgs) -> i64 {
    let dirfd    = args.a0 as i32;
    let path_ptr = args.a1;
    let times_ptr = args.a2;
    let _flags   = args.a3;
    let _ = AT_FDCWD;
    let inode = match resolve_inode(dirfd, path_ptr) {
        Ok(i) => i, Err(rv) => return rv,
    };
    let now = now_ns();
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now))
    } else {
        let a = match read_user_ns_pair(times_ptr, 0, now) { Ok(v) => v, Err(rv) => return rv };
        let m = match read_user_ns_pair(times_ptr, 1, now) { Ok(v) => v, Err(rv) => return rv };
        (a, m)
    };
    if inode.set_times(atime, mtime, now).is_err() {
        vfs::inode_times::set(&inode, atime, mtime, now);
    }
    0
}

/// Dispatch helper for utimes/utime so syscall_glue.rs only carries
/// one match arm.
/// # C: O(1)
pub fn sys_utime_dispatch(nr: u64, args: &SyscallArgs) -> i64 {
    if nr == syscall::nrs::NR_UTIMES { sys_utimes(args) }
    else                                   { sys_utime(args) }
}

/// `sys_utimes(path, times[2])` — slot 235. Same as utimensat but
/// the times are 16-byte timeval (sec, usec) pairs and there is no
/// dirfd / flags. NULL ⇒ both = now.
/// # C: O(N_path)
pub fn sys_utimes(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let times_ptr = args.a1;
    let inode = match resolve_inode(AT_FDCWD, path_ptr) {
        Ok(i) => i, Err(rv) => return rv,
    };
    let now = now_ns();
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now))
    } else {
        if times_ptr.checked_add(32).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: times_ptr+32 validated < USER_VA_END; CPL=0 reads two timeval (i64+i64) pairs through caller's AS.
        let (asec, ausec, msec, musec) = unsafe {
            (core::ptr::read_volatile( times_ptr        as *const i64),
             core::ptr::read_volatile((times_ptr +  8)  as *const i64),
             core::ptr::read_volatile((times_ptr + 16)  as *const i64),
             core::ptr::read_volatile((times_ptr + 24)  as *const i64))
        };
        if asec < 0 || msec < 0 || ausec < 0 || musec < 0
            || ausec >= 1_000_000 || musec >= 1_000_000 {
            return -(Errno::Einval.as_i32() as i64);
        }
        let atime_ns = (asec as u64) * 1_000_000_000 + (ausec as u64) * 1_000;
        let mtime_ns = (msec as u64) * 1_000_000_000 + (musec as u64) * 1_000;
        (Some(atime_ns), Some(mtime_ns))
    };
    if inode.set_times(atime, mtime, now).is_err() {
        vfs::inode_times::set(&inode, atime, mtime, now);
    }
    0
}

/// `sys_utime(path, times)` — slot 132 (older API). `times` is a
/// `struct utimbuf { time_t actime; time_t modtime; }` (16 bytes).
/// NULL ⇒ both = now.
/// # C: O(N_path)
pub fn sys_utime(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let times_ptr = args.a1;
    let inode = match resolve_inode(AT_FDCWD, path_ptr) {
        Ok(i) => i, Err(rv) => return rv,
    };
    let now = now_ns();
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now))
    } else {
        if times_ptr.checked_add(16).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: times_ptr+16 validated < USER_VA_END; CPL=0 reads two i64 fields (utimbuf) through caller's AS.
        let (asec, msec) = unsafe {
            (core::ptr::read_volatile( times_ptr       as *const i64),
             core::ptr::read_volatile((times_ptr + 8)  as *const i64))
        };
        if asec < 0 || msec < 0 {
            return -(Errno::Einval.as_i32() as i64);
        }
        (Some((asec as u64) * 1_000_000_000), Some((msec as u64) * 1_000_000_000))
    };
    if inode.set_times(atime, mtime, now).is_err() {
        vfs::inode_times::set(&inode, atime, mtime, now);
    }
    0
}
