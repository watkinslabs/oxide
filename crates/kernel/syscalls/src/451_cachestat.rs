// 451 cachestat — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vfs::{CachestatRange, Fmode, MAY_WRITE};
use vfs::idmap::IDENTITY;
use vfs::inode::inode_owner_or_capable;

use crate::cachestat::can_do_cachestat;
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `struct cachestat_range { __u64 off; __u64 len; }`.
const CSTAT_RANGE_SIZE: u64 = 16;
/// `struct cachestat` — five `__u64` counters.
const CSTAT_SIZE: u64 = vfs::CACHESTAT_FIELDS as u64 * 8;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_cachestat(fd, range, cstat, flags)` — slot 451.
///
/// Admission order is Linux's: fd, the range copy-in, the hugetlbfs refusal,
/// the write-authority ladder, `flags`, then the walk and the copy-out.
/// # C: O(entries in range)
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
    let (off, len) = unsafe {
        (
            core::ptr::read_unaligned(range as *const u64),
            core::ptr::read_unaligned((range + 8) as *const u64),
        )
    };

    let inode = file.inode();
    // A hugepage file's cache is not counted in base pages, and every counter
    // this call reports is a base-page count — so the reference refuses rather
    // than answering in a unit the caller cannot interpret.
    if inode.huge_page_size() != 0 { return errno(Errno::Eopnotsupp); }
    let cred = crate::pathresolve::current_cred();
    let admitted = can_do_cachestat(
        file.f_mode().contains(Fmode::WRITE),
        inode_owner_or_capable(&IDENTITY, inode.as_ref(), &cred),
        inode.permission(MAY_WRITE, &cred).is_ok(),
    );
    if !admitted { return errno(Errno::Eperm); }
    if flags != 0 { return errno(Errno::Einval); }

    let counts = match inode.i_mapping() {
        Some(m) => m.cachestat(CachestatRange::from_bytes(off, len, hal::PAGE_SHIFT)),
        // An inode with no address_space holds no page cache: every counter is
        // genuinely zero, the same answer the walk would produce for an empty
        // index space.
        None => vfs::CachestatCounts::default(),
    };

    if let Err(rv) = validate_user_buf_writable(out, CSTAT_SIZE, 1) { return rv; }
    // SAFETY: out was validated as a 40-byte writable user buffer below USER_VA_END; unaligned stores match copy_to_user semantics.
    unsafe {
        for (i, v) in counts.as_uapi().iter().enumerate() {
            core::ptr::write_unaligned((out + i as u64 * 8) as *mut u64, *v);
        }
    }
    0
}
