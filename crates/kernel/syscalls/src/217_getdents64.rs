// 217 getdents64 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// `sys_getdents64(fd, dirp, count)` — slot 217. Walks the inode's
/// `readdir`, packs `linux_dirent64` records into the user buffer.
/// Returns bytes written, or 0 at end-of-dir. ENOTDIR for non-dirs.
/// File offset is the readdir cookie — incremented across calls.
/// # C: O(N_dirents)
pub fn sys_getdents64(args: &SyscallArgs) -> i64 {
    use vfs::FileType;
    let fd = args.a0 as i32;
    let dirp = args.a1;
    let count = args.a2 as usize;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if count == 0 { return 0; }
    if let Err(rv) = validate_user_buf(dirp, args.a2, 1) { return rv; }
    let inode = file.inode().clone();
    if !matches!(inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let off = file.pos();
    let mut written: usize = 0;
    let mut new_off = off;
    let r = inode.readdir(off, &mut |cookie, name, ft| {
        let reclen = vfs::dirent64_reclen(name.len());
        if written + reclen > count { return false; }
        let dt: u8 = match ft {
            FileType::Regular   => 8,
            FileType::Directory => 4,
            FileType::CharDev   => 2,
            FileType::BlockDev  => 6,
            FileType::Symlink   => 10,
            FileType::Fifo      => 1,
            FileType::Socket    => 12,
        };
        let mut tmp = [0u8; 320];
        let n = vfs::dirent64_pack(&mut tmp[..reclen], 0, cookie, dt, name.as_bytes())
            .expect("dirent64_pack: tmp buf sized to reclen");
        // SAFETY: validate_user_buf above bounded [dirp, dirp+count) < USER_VA_END; CPL=0; caller's AS active.
        unsafe {
            for i in 0..n {
                core::ptr::write_volatile((dirp + (written + i) as u64) as *mut u8, tmp[i]);
            }
        }
        written += n;
        new_off = cookie;
        true
    });
    match r {
        Ok(_) => { file.set_pos(new_off); written as i64 }
        Err(e) => -(e as i64),
    }
}
