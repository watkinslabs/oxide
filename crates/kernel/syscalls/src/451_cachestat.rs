// 451 cachestat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::Fmode;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

const CSTAT_RANGE_SIZE: u64 = 16;
const CSTAT_SIZE:       u64 = 40;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_cachestat(fd, range, cstat, flags)` — slot 451. Oxide has no
/// hugetlbfs and no page-cache residency counters yet, so a valid request
/// returns a zeroed `struct cachestat` after Linux-order validation.
/// # C: O(1)
pub fn sys_cachestat(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let range = args.a1;
    let out = args.a2;
    let flags = args.a3 as u32;

    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Ebadf) };
    // SAFETY: running task on this CPU; fd_table slot read follows the syscall single-mutator invariant.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return errno(Errno::Ebadf) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return errno(Errno::Ebadf) };

    if let Err(rv) = validate_user_buf(range, CSTAT_RANGE_SIZE, 1) { return rv; }
    // SAFETY: range was validated as a 16-byte user buffer below USER_VA_END; unaligned loads match copy_from_user semantics.
    let (_off, _len) = unsafe {
        (
            core::ptr::read_unaligned(range as *const u64),
            core::ptr::read_unaligned((range + 8) as *const u64),
        )
    };

    if !file.f_mode().contains(Fmode::WRITE) {
        let cred = crate::pathresolve::current_cred();
        if file.inode().permission(vfs::MAY_WRITE, &cred).is_err() {
            return errno(Errno::Eperm);
        }
    }
    if flags != 0 { return errno(Errno::Einval); }
    if let Err(rv) = validate_user_buf_writable(out, CSTAT_SIZE, 1) { return rv; }

    // SAFETY: out was validated as a 40-byte writable user buffer below USER_VA_END; unaligned stores match copy_to_user semantics.
    unsafe {
        for off in (0..CSTAT_SIZE).step_by(8) {
            core::ptr::write_unaligned((out + off) as *mut u64, 0);
        }
    }
    0
}
