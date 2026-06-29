// 005 fstat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

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
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 1) { return rv; }
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
    // vfs_getattr → i_op->getattr (default generic_fillattr): S_IF* mapping +
    // inode_times overlay merge + idmap-out owner ids, identical to the other
    // stat-family handlers. The fd carries the owning mount for the idmap.
    let idmap = vfs::mount::idmap_for(file.mnt_id());
    let st = vfs::vfs_getattr(inode, &idmap, vfs::inode_times::get(inode));
    let mode: u32 = st.mode;
    let rdev = st.rdev as u64;
    let uid = st.uid;
    let gid = st.gid;
    let ino  = st.ino;
    let size = st.size as i64;
    let blocks = st.blocks;
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    let nlink = st.nlink;
    let blksize = st.blksize;
    let at = st.atime_ns;
    let mt = st.mtime_ns;
    let ct = st.ctime_ns;
    // SAFETY: buf validated STAT_BYTES below USER_VA_END; unaligned stores
    // match Linux copy_to_user semantics for user-provided buffers.
    unsafe {
        for off in (0..STAT_BYTES).step_by(8) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
        // st_dev@0 — distinct per filesystem (both arch layouts have dev@0).
        core::ptr::write_unaligned(buf as *mut u64, dev);
        let write_ts = |sec_off: u64, ns: u64| {
            core::ptr::write_unaligned((buf + sec_off)     as *mut i64, (ns / 1_000_000_000) as i64);
            core::ptr::write_unaligned((buf + sec_off + 8) as *mut i64, (ns % 1_000_000_000) as i64);
        };
        #[cfg(target_arch = "x86_64")] {
            // x86_64: dev@0 ino@8 nlink@16 mode@24 uid@28 gid@32 rdev@40
            // size@48 blksize@56 blocks@64 atime@72 mtime@88 ctime@104.
            core::ptr::write_unaligned((buf +   8)     as *mut u64, ino);
            core::ptr::write_unaligned((buf +  16)     as *mut u64, nlink as u64);
            core::ptr::write_unaligned((buf +  24)     as *mut u32, mode);
            core::ptr::write_unaligned((buf +  28)     as *mut u32, uid);
            core::ptr::write_unaligned((buf +  32)     as *mut u32, gid);
            core::ptr::write_unaligned((buf +  40)     as *mut u64, rdev);
            core::ptr::write_unaligned((buf +  48)     as *mut i64, size);
            core::ptr::write_unaligned((buf +  56)     as *mut i64, blksize as i64);
            core::ptr::write_unaligned((buf +  64)     as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
        #[cfg(target_arch = "aarch64")] {
            // asm-generic: dev@0 ino@8 mode@16 nlink@20 uid@24 gid@28 rdev@32
            // size@48 blksize@56 blocks@64 atime@72 mtime@88 ctime@104.
            core::ptr::write_unaligned((buf +   8)     as *mut u64, ino);
            core::ptr::write_unaligned((buf +  16)     as *mut u32, mode);
            core::ptr::write_unaligned((buf +  20)     as *mut u32, nlink);
            core::ptr::write_unaligned((buf +  24)     as *mut u32, uid);
            core::ptr::write_unaligned((buf +  28)     as *mut u32, gid);
            core::ptr::write_unaligned((buf +  32)     as *mut u64, rdev);
            core::ptr::write_unaligned((buf +  48)     as *mut i64, size);
            core::ptr::write_unaligned((buf +  56)     as *mut i32, blksize as i32);
            core::ptr::write_unaligned((buf +  64)     as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
    }
    0
}
