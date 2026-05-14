// sys_newfstatat — split out of `fs.rs` for the 1000-line cap.
//
// Per-arch struct stat: x86_64 = 144 B, aarch64 asm-generic = 128 B.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::syscalls::validate_user_buf;

/// `sys_newfstatat(dirfd, path, statbuf, flags)` — x86_64 slot 262.
/// Previously this was routed to sys_statx, which mis-reads args
/// (statx's a2=flags is newfstatat's a2=statbuf) and corrupted
/// userspace memory; ARM busybox's PATH search printed
/// "Permission denied" for every probe.
/// # C: O(1)
pub fn sys_newfstatat(args: &SyscallArgs) -> i64 {
    use vfs::FileType;
    const AT_EMPTY_PATH: u32 = 0x1000;
    let dirfd    = args.a0 as i32;
    let path_ptr = args.a1;
    let buf      = args.a2;
    let flags    = args.a3 as u32;

    #[cfg(target_arch = "x86_64")]
    const STAT_BYTES: u64 = 144;
    #[cfg(target_arch = "aarch64")]
    const STAT_BYTES: u64 = 128;

    if let Err(rv) = validate_user_buf(buf, STAT_BYTES, 8) { return rv; }
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path_opt = unsafe { crate::devfs::read_user_cstr(path_ptr, 256) };
    let inode = match path_opt {
        Some(p) if !p.is_empty() => {
            let s = match core::str::from_utf8(p) {
                Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
            };
            match vfs::mount::lookup(s) {
                Ok(i) => i,
                Err(_) => match ext4::rootfs::lookup_inode_any(s.as_bytes()) {
                    Some(i) => i,
                    None    => return -(Errno::Enoent.as_i32() as i64),
                }
            }
        }
        _ if (flags & AT_EMPTY_PATH) != 0 => {
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
            };
            // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per 13§5.
            let fdt = match unsafe { cur.fd_table_ref() } {
                Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
            };
            let f = match fdt.get(dirfd) {
                Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
            };
            f.inode().clone()
        }
        _ => return -(Errno::Enoent.as_i32() as i64),
    };

    let (mode_type, rdev): (u32, u64) = match inode.file_type() {
        FileType::CharDev   => (0o020000, 0x0103),
        FileType::BlockDev  => (0o060000, 0),
        FileType::Directory => (0o040000, 0),
        FileType::Regular   => (0o100000, 0),
        FileType::Symlink   => (0o120000, 0),
        FileType::Fifo      => (0o010000, 0),
        FileType::Socket    => (0o140000, 0),
    };
    let overlay   = vfs::inode_times::get(&inode).unwrap_or_default();
    let mode_perm = inode.perm()
        .or_else(|| if overlay.owner_set && overlay.mode_bits != 0 { Some(overlay.mode_bits) } else { None })
        .unwrap_or(0o755);
    let mode = mode_type | (mode_perm as u32);
    let uid  = inode.uid().unwrap_or(if overlay.owner_set { overlay.uid } else { 0 });
    let gid  = inode.gid().unwrap_or(if overlay.owner_set { overlay.gid } else { 0 });
    let ino  = inode.ino();
    let size = inode.size() as i64;
    let blocks = (inode.size() + 511) / 512;

    // SAFETY: buf validated STAT_BYTES writeable below USER_VA_END + 8-aligned; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..STAT_BYTES).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        #[cfg(target_arch = "x86_64")] {
            // x86_64 struct stat (144 B): dev@0 ino@8 nlink@16 mode@24
            // uid@28 gid@32 rdev@40 size@48 blksize@56 blocks@64.
            core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
            core::ptr::write_volatile((buf +  16)     as *mut u64, 1);
            core::ptr::write_volatile((buf +  24)     as *mut u32, mode);
            core::ptr::write_volatile((buf +  28)     as *mut u32, uid);
            core::ptr::write_volatile((buf +  32)     as *mut u32, gid);
            core::ptr::write_volatile((buf +  40)     as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48)     as *mut i64, size);
            core::ptr::write_volatile((buf +  56)     as *mut i64, 4096);
            core::ptr::write_volatile((buf +  64)     as *mut i64, blocks as i64);
        }
        #[cfg(target_arch = "aarch64")] {
            // asm-generic struct stat (128 B): ino@8 mode@16 nlink@20
            // uid@24 gid@28 rdev@32 size@48 blksize@56 blocks@64.
            core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
            core::ptr::write_volatile((buf +  16)     as *mut u32, mode);
            core::ptr::write_volatile((buf +  20)     as *mut u32, 1);
            core::ptr::write_volatile((buf +  24)     as *mut u32, uid);
            core::ptr::write_volatile((buf +  28)     as *mut u32, gid);
            core::ptr::write_volatile((buf +  32)     as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48)     as *mut i64, size);
            core::ptr::write_volatile((buf +  56)     as *mut i32, 4096);
            core::ptr::write_volatile((buf +  64)     as *mut i64, blocks as i64);
        }
    }
    0
}
