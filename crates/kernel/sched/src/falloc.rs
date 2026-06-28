// `sys_fallocate` (slot 285) real impl. Split out of
// `syscall_glue_fs.rs` to keep that file under the 1000-line cap.


use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_fallocate(fd, mode, offset, len)` — slot 285.
///
/// Modes (`linux/falloc.h`):
///   0                       — ensure space allocated for [off, off+len);
///                              extends file size if needed (truncate up).
///   FALLOC_FL_KEEP_SIZE (1) — allocate without extending size.
///   FALLOC_FL_ZERO_RANGE (16) [+KEEP_SIZE] — write zeros across range.
///   Anything else (PUNCH_HOLE / COLLAPSE_RANGE / INSERT_RANGE) — EOPNOTSUPP.
/// # C: depends on backing fs.
pub fn sys_fallocate(args: &SyscallArgs) -> i64 {
    const FALLOC_FL_KEEP_SIZE:    u32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE:   u32 = 0x02;
    const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
    const FALLOC_FL_ZERO_RANGE:   u32 = 0x10;
    const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
    let fd     = args.a0 as i32;
    let mode   = args.a1 as u32;
    if (args.a2 as i64) < 0 || (args.a3 as i64) <= 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let offset = args.a2;
    let len    = args.a3;
    if offset.checked_add(len).is_none() {
        return -(Errno::Einval.as_i32() as i64);
    }
    let supported = FALLOC_FL_KEEP_SIZE | FALLOC_FL_ZERO_RANGE;
    if mode & !supported != 0
        || mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE) != 0
    {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    let cur = match crate::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if !file.f_mode().contains(vfs::Fmode::WRITE) {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    let keep_size = mode & FALLOC_FL_KEEP_SIZE != 0;
    let zero_range = mode & FALLOC_FL_ZERO_RANGE != 0;
    match file.inode().fallocate(offset, len, keep_size, zero_range) {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}
