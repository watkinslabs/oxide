// 005 fstat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// `sys_fstat(fd, statbuf)` — slot 5. 144-byte Linux x86_64 struct stat.
/// # C: O(1)
pub fn sys_fstat(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    // x86_64 struct stat = 144 B; aarch64 asm-generic struct stat = 128 B.
    // Per-arch layout differs (mode@24/+rdev@40 vs mode@16/+rdev@32) — using
    // the x86 layout on aarch64 returned mismatched st_ino vs newfstatat
    // because the field offsets don't line up; broke musl's ttyname.
    #[cfg(target_arch = "x86_64")]
    const STAT_BYTES: u64 = 144;
    #[cfg(target_arch = "aarch64")]
    const STAT_BYTES: u64 = 128;
    if let Err(rv) = validate_user_buf(buf, STAT_BYTES, 8) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per single-mutator-per-active-CPU invariant in `13§5`.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let (mode_type, rdev): (u32, u64) = match inode.file_type() {
        vfs::FileType::CharDev   => (0o020000, 0x0103),
        vfs::FileType::BlockDev  => (0o060000, 0),
        vfs::FileType::Directory => (0o040000, 0),
        vfs::FileType::Regular   => (0o100000, 0),
        vfs::FileType::Symlink   => (0o120000, 0),
        vfs::FileType::Fifo      => (0o010000, 0),
        vfs::FileType::Socket    => (0o140000, 0),
    };
    // Real perms via the inode (overlay-aware), matching sys_statx/sys_stat.
    // Hardcoding 0o600 here made systemd see every unit file as
    // world-inaccessible (it opens then fstat()s the fd), and broke any
    // group/other-read check on fstat'd files.
    let overlay = vfs::inode_times::get(&inode).unwrap_or_default();
    let mode_perm = inode.perm()
        .or_else(|| if overlay.owner_set && overlay.mode_bits != 0 { Some(overlay.mode_bits) } else { None })
        .unwrap_or(0o755);
    let mode: u32 = mode_type | mode_perm as u32;
    let uid = inode.uid().unwrap_or(if overlay.owner_set { overlay.uid } else { 0 });
    let gid = inode.gid().unwrap_or(if overlay.owner_set { overlay.gid } else { 0 });
    let ino  = inode.ino();
    let size = inode.size() as i64;
    // SAFETY: buf validated STAT_BYTES below USER_VA_END + 8-byte aligned; CPL=0 writes through user mapping per the active CR3/TTBR0 = caller's AS.
    unsafe {
        for off in (0..STAT_BYTES).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        #[cfg(target_arch = "x86_64")] {
            // x86_64: dev@0 ino@8 nlink@16 mode@24 uid@28 gid@32 rdev@40 size@48 blksize@56 blocks@64.
            core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
            core::ptr::write_volatile((buf +  16)     as *mut u64, 1);
            core::ptr::write_volatile((buf +  24)     as *mut u32, mode);
            core::ptr::write_volatile((buf +  28)     as *mut u32, uid);
            core::ptr::write_volatile((buf +  32)     as *mut u32, gid);
            core::ptr::write_volatile((buf +  40)     as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48)     as *mut i64, size);
            core::ptr::write_volatile((buf +  56)     as *mut i64, 4096);
        }
        #[cfg(target_arch = "aarch64")] {
            // asm-generic: dev@0 ino@8 mode@16 nlink@20 uid@24 gid@28 rdev@32 size@48 blksize@56 blocks@64.
            core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
            core::ptr::write_volatile((buf +  16)     as *mut u32, mode);
            core::ptr::write_volatile((buf +  20)     as *mut u32, 1);
            core::ptr::write_volatile((buf +  24)     as *mut u32, uid);
            core::ptr::write_volatile((buf +  28)     as *mut u32, gid);
            core::ptr::write_volatile((buf +  32)     as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48)     as *mut i64, size);
            core::ptr::write_volatile((buf +  56)     as *mut i32, 4096);
        }
    }
    0
}
