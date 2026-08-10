// `prctl(PR_SET_MM, opt, addr, arg4, 0)` — Linux
// `prctl_set_mm`. Split out of `prctl.rs` so the pointer-setter /
// AUXV / EXE_FILE / whole-MAP dispatch stays under the file cap.
//
// Requires CAP_SYS_RESOURCE (else EPERM). The layout bounds it writes
// (mm->arg_start..env_end, start_code..end_data, start_brk, brk,
// start_stack) are the source `/proc/<pid>/{cmdline,environ,stat}`
// read from — systemd relabels its argv block then PR_SET_MM_ARG_START/
// ARG_END so `/proc/self/cmdline` reflects the new title.
//
// The validation / apply core lives in `vmm` (`AddressSpace::
// prctl_set_field` / `apply_prctl_mm_map`) so it is hosted-testable;
// this file only reads user memory + resolves the exe fd, which need
// the live kernel context.

#![cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use vmm::{
    PrctlMmMap, PR_SET_MM_AUXV, PR_SET_MM_EXE_FILE, PR_SET_MM_MAP, PR_SET_MM_MAP_SIZE,
};

use crate::task::Task;

// Auxv blob is bounded to one page (Linux caps `saved_auxv` at
// `AT_VECTOR_SIZE` entries; one page is the pragmatic equivalent).
const AUXV_MAX: usize = 4096;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

/// Copy `dst.len()` bytes out of the calling task's active address space at
/// `addr`. Goes through `uaccess`, whose copy carries the exception-table
/// fixups: a range check alone leaves an unmapped user page faulting the
/// kernel instead of answering EFAULT. False on any address the copy refused.
/// # C: O(len)
fn read_user_bytes(addr: u64, dst: &mut [u8]) -> bool {
    uaccess::copy_from_user(dst, addr).is_ok()
}

/// `prctl(PR_SET_MM, ...)` dispatch. `args.a1` = subcommand `opt`,
/// `args.a2` = `addr` (or fd for EXE_FILE / out-ptr for MAP_SIZE),
/// `args.a3` = `arg4` (blob/struct length).
/// # C: O(1) for setters; O(struct)/O(auxv) for MAP/AUXV
pub fn sys_set_mm(cur: &Task, args: &SyscallArgs) -> i64 {
    // Linux `prctl_set_mm`: CAP_SYS_RESOURCE or EPERM.
    if !cur.has_cap(crate::cap::SYS_RESOURCE) { return -(Errno::Eperm.as_i32() as i64); }
    // SAFETY: running task on this CPU; preempt-off in dispatch; no concurrent execve writer against this mm.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return einval() };
    let opt  = args.a1;
    let addr = args.a2;
    let arg4 = args.a3;

    match opt {
        // Single-field pointer setters (start_code..env_end + brk).
        1..=11 => match mm.prctl_set_field(opt, addr) { Ok(()) => 0, Err(()) => einval() },

        // PR_SET_MM_AUXV: copy an auxv blob of length `arg4` (bounded).
        PR_SET_MM_AUXV => {
            let len = (arg4 as usize).min(AUXV_MAX);
            if len == 0 { mm.set_auxv(alloc::vec::Vec::new()); return 0; }
            let mut buf = alloc::vec![0u8; len];
            if !read_user_bytes(addr, &mut buf) { return efault(); }
            mm.set_auxv(buf);
            0
        }

        // PR_SET_MM_EXE_FILE: set mm->exe_file from an open fd (arg3=addr slot).
        PR_SET_MM_EXE_FILE => set_exe_from_fd(cur, &mm, addr as i32),

        // PR_SET_MM_MAP: apply the whole prctl_mm_map atomically.
        PR_SET_MM_MAP => {
            if arg4 as usize != PrctlMmMap::SIZE { return einval(); }
            let mut raw = [0u8; PrctlMmMap::SIZE];
            if !read_user_bytes(addr, &mut raw) { return efault(); }
            let map = match PrctlMmMap::from_bytes(&raw) { Some(m) => m, None => return einval() };
            if mm.apply_prctl_mm_map(&map).is_err() { return einval(); }
            // auxv blob + exe fd travel with the map (best-effort, post-commit).
            if map.auxv != 0 && map.auxv_size != 0 {
                let len = (map.auxv_size as usize).min(AUXV_MAX);
                let mut buf = alloc::vec![0u8; len];
                if read_user_bytes(map.auxv, &mut buf) { mm.set_auxv(buf); }
            }
            if map.exe_fd >= 0 { let _ = set_exe_from_fd(cur, &mm, map.exe_fd); }
            0
        }

        // PR_SET_MM_MAP_SIZE: write sizeof(struct prctl_mm_map) to *addr (u32).
        PR_SET_MM_MAP_SIZE => {
            let size = (PrctlMmMap::SIZE as u32).to_ne_bytes();
            if uaccess::copy_to_user(addr, &size).is_err() { return efault(); }
            0
        }

        _ => einval(),
    }
}

/// Resolve an open fd to its dentry path and install it as the mm's
/// exe_file (Linux `prctl_set_mm_exe_file`). Mirrors execve: sets both
/// the per-mm `exe_path` (`/proc/<pid>/exe`) and the task snapshot.
fn set_exe_from_fd(cur: &Task, mm: &vmm::AddressSpace, fd: i32) -> i64 {
    // SAFETY: running task on this CPU; sole reader of the fd_table slot per `13§5`.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let path = file.dentry().absolute_path();
    let s = match core::str::from_utf8(&path) { Ok(s) => alloc::string::String::from(s), Err(_) => return einval() };
    if s.is_empty() { return einval(); }
    mm.set_exe_path(s.clone());
    cur.set_exe_path(Some(s));
    0
}

#[cfg(test)]
mod tests {
    use super::read_user_bytes;

    /// The blob copy answers a refusal rather than dereferencing an address
    /// the range check only happened to admit.
    #[test]
    fn the_blob_copy_refuses_a_pointer_outside_the_user_half() {
        let mut buf = [0u8; 8];
        assert!(!read_user_bytes(0, &mut buf));
        assert!(!read_user_bytes(hal::USER_VA_END, &mut buf));
        assert!(!read_user_bytes(hal::USER_VA_END - 4, &mut buf), "the tail leaves the user half");
    }

    #[test]
    fn the_blob_copy_takes_exactly_the_requested_length() {
        let src = *b"auxvblob!!";
        let mut buf = [0u8; 4];
        assert!(read_user_bytes(src.as_ptr() as u64, &mut buf));
        assert_eq!(&buf, b"auxv");
    }
}
