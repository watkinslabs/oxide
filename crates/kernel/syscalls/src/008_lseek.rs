// 008 lseek — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_lseek(fd, offset, whence)` — slot 8. Real `vfs::File::seek`
/// for seekable file types (Regular + BlockDev); ESPIPE for the
/// non-seekable kinds (Fifo / Socket / CharDev) per Linux.
/// # C: O(1)
pub fn sys_lseek(args: &SyscallArgs) -> i64 {
    let fd     = args.a0 as i32;
    let off    = args.a1 as i64;
    let whence = args.a2 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    match file.inode().file_type() {
        vfs::FileType::Regular | vfs::FileType::BlockDev => {}
        _ => return -(Errno::Espipe.as_i32() as i64),
    }
    let from = match whence {
        0 => vfs::SeekFrom::Start,   // SEEK_SET
        1 => vfs::SeekFrom::Current, // SEEK_CUR
        2 => vfs::SeekFrom::End,     // SEEK_END
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    match file.seek(from, off) {
        Ok(pos) => pos as i64,
        Err(e)  => -(e as i64),
    }
}
