#![cfg(target_os = "oxide-kernel")]
// `sys_fallocate` (slot 285) real impl. Split out of
// `syscall_glue_fs.rs` to keep that file under the 1000-line cap.


use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_fallocate(fd, mode, offset, len)` — slot 285.
///
/// Modes (`linux/falloc.h`):
///   0                       — ensure space allocated for [off, off+len);
///                              extends file size if needed (truncate up).
///   FALLOC_FL_KEEP_SIZE (1) — allocate without extending size; v1 no-op
///                              since tmpfs/anon files are dense.
///   FALLOC_FL_ZERO_RANGE (16) [+KEEP_SIZE] — write zeros across range.
///   Anything else (PUNCH_HOLE / COLLAPSE_RANGE / INSERT_RANGE) — ENOSYS.
/// # C: O(len) for ZERO_RANGE; O(1) otherwise.
pub fn kernel_sys_fallocate(args: &SyscallArgs) -> i64 {
    const FALLOC_FL_KEEP_SIZE:    u32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE:   u32 = 0x02;
    const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x08;
    const FALLOC_FL_ZERO_RANGE:   u32 = 0x10;
    const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
    let fd     = args.a0 as i32;
    let mode   = args.a1 as u32;
    let offset = args.a2;
    let len    = args.a3;
    if len == 0 || offset.checked_add(len).is_none() {
        return -(Errno::Einval.as_i32() as i64);
    }
    if mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE) != 0 {
        return -(Errno::Enosys.as_i32() as i64);
    }
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
    let end = offset + len;
    let cur_size = file.inode().size();
    if mode & FALLOC_FL_ZERO_RANGE != 0 {
        let mut buf = [0u8; 4096];
        let mut off = offset;
        while off < end {
            let chunk = core::cmp::min((end - off) as usize, buf.len());
            let n = match file.inode().write(off, &buf[..chunk]) {
                Ok(n) => n, Err(e) => return -(e as i64),
            };
            if n == 0 { return -(Errno::Eio.as_i32() as i64); }
            off += n as u64;
            for b in &mut buf[..chunk] { *b = 0; }
        }
        return 0;
    }
    if mode & FALLOC_FL_KEEP_SIZE != 0 { return 0; }
    if end > cur_size {
        match file.inode().truncate(end) { Ok(_) => 0, Err(e) => -(e as i64) }
    } else {
        0
    }
}
