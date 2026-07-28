// 326 copy_file_range — one syscall, one file (docs/53 §0). ABI shim only:
// fd resolution, the `loff_t __user *` copy-in/copy-out, and the RLIMIT_FSIZE
// lookup. The check ladder and the copy are `fs::splice::copy_file_range`
// (Linux `fs/read_write.c`).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)` — slot 326.
///
/// Order is Linux's (`fs/read_write.c:1649-1703`): both fd lookups (EBADF),
/// then the offset copy-in (EFAULT), then `flags != 0` (EINVAL) — so a bad
/// offset pointer AND a bad flag word reports EFAULT. Offsets are written back
/// only when bytes were actually copied, and a NULL pointer means the
/// description's own `f_pos` is used and advanced instead.
/// # C: O(len)
pub fn sys_copy_file_range(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: fd_table slot single-mutator per `13§5`; running task on this CPU; Arc clone.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    let in_file  = match fdt.get(args.a0 as i32) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };
    let out_file = match fdt.get(args.a2 as i32) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };
    let (in_ptr, out_ptr) = (args.a1, args.a3);
    let mut pos_in = match load_pos(in_ptr, &in_file) { Ok(v) => v, Err(e) => return e };
    let mut pos_out = match load_pos(out_ptr, &out_file) { Ok(v) => v, Err(e) => return e };
    let limit = cur.rlimit(sched::rlimit::rlim::FSIZE).0;
    let limit = if limit == sched::rlimit::INFINITY { u64::MAX } else { limit };
    let ret = ::fs::splice::copy_file_range(&in_file, &mut pos_in, &out_file, &mut pos_out,
                                            args.a4, args.a5, limit);
    if ret <= 0 { return ret; }
    // `fs/read_write.c:1684-1701`: advance and store, user pointer or f_pos.
    if in_ptr != 0 {
        if let Err(e) = store_pos(in_ptr, pos_in) { return e; }
    } else { in_file.set_pos(pos_in); }
    if out_ptr != 0 {
        if let Err(e) = store_pos(out_ptr, pos_out) { return e; }
    } else { out_file.set_pos(pos_out); }
    ret
}

/// A NULL `loff_t __user *` means "use the description's cursor"
/// (`fs/read_write.c:1665-1677`). # C: O(1)
fn load_pos(ptr: u64, file: &vfs::File) -> Result<u64, i64> {
    if ptr == 0 { return Ok(file.pos()); }
    validate_user_buf(ptr, 8, 8)?;
    // SAFETY: `validate_user_buf` proved 8 readable, 8-aligned bytes at `ptr`
    // below USER_VA_END in the caller's active address space.
    Ok(unsafe { core::ptr::read_volatile(ptr as *const u64) })
}

/// # C: O(1)
fn store_pos(ptr: u64, v: u64) -> Result<(), i64> {
    validate_user_buf_writable(ptr, 8, 8)?;
    // SAFETY: `validate_user_buf_writable` proved 8 writable, 8-aligned bytes
    // at `ptr` below USER_VA_END in the caller's active address space.
    unsafe { core::ptr::write_volatile(ptr as *mut u64, v); }
    Ok(())
}
