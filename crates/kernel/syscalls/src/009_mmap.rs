// 009 mmap — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// # C: O(log N_vmas)
pub fn kernel_mmap(args: &SyscallArgs) -> i64 {
    let fd     = args.a4 as i64;
    let offset = args.a5;
    let flags  = args.a3;
    const MAP_ANON: u64 = 0x20;
    // File-backed mmap: resolve fd, wrap as FileBacking, pass to
    // glue_mmap. Anonymous goes through the None path.
    let backing: Option<alloc::sync::Arc<dyn vmm::FileBacking>> =
        if (flags & MAP_ANON) == 0 && fd >= 0 {
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
            };
            // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
            let fdt = match unsafe { cur.fd_table_ref() } {
                Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
            };
            let file = match fdt.get(fd as i32) {
                Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
            };
            Some(crate::mmap_file::InodeFileBacking::new(file.inode().clone()))
        } else { None };
    match pmm::user_as::glue_mmap(args.a0, args.a1, args.a2, args.a3, fd, offset, backing) {
        Ok(va)  => va as i64,
        Err(rv) => rv,
    }
}
