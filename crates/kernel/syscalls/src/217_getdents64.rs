// 217 getdents64 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

/// `sys_getdents64(fd, dirp, count)` — slot 217. Packs `linux_dirent64`
/// records (fixed `d_type` field at offset 18).
/// # C: O(N_dirents)
pub fn sys_getdents64(args: &SyscallArgs) -> i64 {
    getdents_common(args, false)
}

/// `sys_getdents(fd, dirp, count)` — legacy slot 78. Packs the older
/// `linux_dirent` layout (`d_type` smuggled into the record's LAST byte).
/// Routing this through the dirent64 packer corrupts records, so it has
/// its own packer.
/// # C: O(N_dirents)
pub fn sys_getdents(args: &SyscallArgs) -> i64 {
    getdents_common(args, true)
}

/// Shared getdents core. `legacy` selects the `linux_dirent` (true) vs
/// `linux_dirent64` (false) record layout. Walks the inode `readdir`,
/// packs records into the user buffer. Returns bytes written; **EINVAL**
/// if the buffer cannot hold even the first entry (Linux `filldir`
/// contract — returning 0 there would be read as end-of-dir, silently
/// truncating the directory listing). ENOTDIR for non-dirs.
/// # C: O(N_dirents)
fn getdents_common(args: &SyscallArgs, legacy: bool) -> i64 {
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
    if let Err(rv) = validate_user_buf_writable(dirp, args.a2, 1) { return rv; }
    let inode = file.inode().clone();
    if !matches!(inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let off = file.pos();
    let mut written: usize = 0;
    let mut new_off = off;
    // Set when the first record overflows the buffer: distinguishes a
    // genuinely empty result (return 0) from a too-small buffer (EINVAL).
    let mut overflow_first = false;
    let r = inode.readdir(off, &mut |d_ino, cookie, name, ft| {
        let reclen = if legacy { vfs::dirent_reclen(name.len()) }
                     else      { vfs::dirent64_reclen(name.len()) };
        if written + reclen > count {
            if written == 0 { overflow_first = true; }
            return false;
        }
        let dt: u8 = vfs::dirent::dtype_from_file_type(ft);
        let mut tmp = [0u8; 320];
        let n = if legacy {
            vfs::dirent_pack(&mut tmp[..reclen], d_ino, cookie, dt, name.as_bytes())
        } else {
            vfs::dirent64_pack(&mut tmp[..reclen], d_ino, cookie, dt, name.as_bytes())
        }.expect("dirent pack: tmp buf sized to reclen");
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
        Ok(_) => {
            if written == 0 && overflow_first {
                return -(Errno::Einval.as_i32() as i64);
            }
            file.set_pos(new_off);
            written as i64
        }
        Err(e) => -(e as i64),
    }
}
